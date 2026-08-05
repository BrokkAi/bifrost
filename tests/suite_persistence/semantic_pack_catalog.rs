use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use brokk_bifrost::analyzer::semantic_model::{
    AuthoredSemanticModelPack, CatalogCoordinate, CatalogError, CatalogGcOptions, CatalogMiss,
    CatalogOpenMode, CatalogOptions, CatalogPackSourceKind, DurablePackSource,
    DurablePackSourceKind, GeneratedProductionKey, SemanticPackCatalog, SemanticPackSelectorQuery,
    SessionPackSource, SessionPackSourceKind, SourceFormat, compile_pack, compile_source,
};
use brokk_bifrost::analyzer::semantic_model::{CompiledSemanticModelPack, CompilerOptions};
use brokk_bifrost::analyzer::store::{
    AnalyzerStore, SemanticPackActivationSourceKind, SemanticPackActiveReference,
};
use filetime::{FileTime, set_file_mtime};
use rusqlite::{Connection, params};
use semver::Version;
use tempfile::TempDir;

const DECLARATIONS_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/declarations-v1.json");
const PROCEDURE_SUMMARIES_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/procedure-summaries-v1.json");

fn compiled_pack() -> CompiledSemanticModelPack {
    compile_source(
        SourceFormat::Json,
        DECLARATIONS_JSON,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("fixture compilation failed: {diagnostics:#?}"))
}

fn compiled_procedure_pack() -> CompiledSemanticModelPack {
    compile_source(
        SourceFormat::Json,
        PROCEDURE_SUMMARIES_JSON,
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("fixture compilation failed: {diagnostics:#?}"))
}

fn compiled_pack_version(version: &str) -> CompiledSemanticModelPack {
    let mut authored: AuthoredSemanticModelPack =
        serde_json::from_slice(DECLARATIONS_JSON).unwrap();
    authored.version = version.to_owned();
    compile_pack(&authored, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| panic!("fixture compilation failed: {diagnostics:#?}"))
}

fn source(kind: DurablePackSourceKind, id: &str) -> DurablePackSource {
    DurablePackSource {
        kind,
        source_id: id.to_owned(),
    }
}

fn generated_key(pack: &CompiledSemanticModelPack, input: char) -> GeneratedProductionKey {
    GeneratedProductionKey::new(
        input.to_string().repeat(64),
        pack.manifest.producer.name.clone(),
        pack.manifest.producer.version.clone(),
        pack.manifest.schema_version,
    )
    .unwrap()
}

fn matching_query() -> SemanticPackSelectorQuery {
    SemanticPackSelectorQuery {
        language: "java".to_owned(),
        ecosystem: "maven".to_owned(),
        package: Some(CatalogCoordinate {
            name: "com.acme:widget".to_owned(),
            version: Some(Version::parse("1.5.0").unwrap()),
        }),
        module: None,
        toolchain: None,
        target: Some("jvm".to_owned()),
        configuration: Some("release".to_owned()),
        artifact_sha256: None,
        bifrost_version: Version::parse("0.8.17").unwrap(),
    }
}

fn procedure_matching_query() -> SemanticPackSelectorQuery {
    SemanticPackSelectorQuery {
        language: "java".to_owned(),
        ecosystem: "maven".to_owned(),
        package: Some(CatalogCoordinate {
            name: "com.acme:flows".to_owned(),
            version: Some(Version::parse("1.5.0").unwrap()),
        }),
        module: None,
        toolchain: None,
        target: Some("jvm".to_owned()),
        configuration: Some("release".to_owned()),
        artifact_sha256: None,
        bifrost_version: Version::parse("0.8.17").unwrap(),
    }
}

#[test]
fn procedure_summary_shards_install_select_load_and_account_without_activation() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let pack = compiled_procedure_pack();
    let descriptor = &pack.shards[0].descriptor;

    catalog
        .install(
            &pack,
            &source(DurablePackSourceKind::Installed, "procedure-fixture"),
        )
        .unwrap();
    let object_path = root
        .path()
        .join("objects/sha256")
        .join(&descriptor.stored_sha256[..2])
        .join(&descriptor.stored_sha256[2..]);
    assert_eq!(fs::read(object_path).unwrap(), pack.shards[0].bytes);

    let candidates = catalog.candidates(&procedure_matching_query()).unwrap();
    assert_eq!(candidates.len(), 1);
    let loaded = catalog.load(&candidates[0]).unwrap();
    assert_eq!(loaded.shard.payload_kind(), descriptor.payload_kind);
    assert_eq!(loaded.shard.record_count(), 2);
    assert_eq!(
        loaded.shard.payload().procedure_summaries().unwrap().len(),
        2
    );

    let accounting = catalog.accounting().unwrap();
    assert_eq!(accounting.object_count, 1);
    assert_eq!(accounting.logical_shard_count, 1);
    assert_eq!(accounting.active_shard_count, 0);
    assert_eq!(accounting.installed_stored_bytes, descriptor.stored_size);
    assert_eq!(accounting.active_stored_bytes, 0);
}

#[test]
fn indexed_lookup_and_verified_load_do_not_read_payload_during_discovery() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let pack = compiled_pack();
    catalog
        .install(&pack, &source(DurablePackSourceKind::Installed, "fixture"))
        .unwrap();

    let candidates = catalog.candidates(&matching_query()).unwrap();
    assert_eq!(candidates.len(), 1);
    let mut toolchain_query = matching_query();
    toolchain_query.toolchain = Some(CatalogCoordinate {
        name: "jdk".to_owned(),
        version: Some(Version::parse("17.0.1").unwrap()),
    });
    assert_eq!(catalog.candidates(&toolchain_query).unwrap().len(), 1);
    toolchain_query.toolchain.as_mut().unwrap().version = Some(Version::parse("11.0.1").unwrap());
    assert!(catalog.candidates(&toolchain_query).unwrap().is_empty());
    catalog.load(&candidates[0]).unwrap();

    let descriptor = &pack.shards[0].descriptor;
    let object_path = root
        .path()
        .join("objects/sha256")
        .join(&descriptor.stored_sha256[..2])
        .join(&descriptor.stored_sha256[2..]);
    fs::remove_file(object_path).unwrap();

    assert_eq!(catalog.candidates(&matching_query()).unwrap().len(), 1);
    let miss = catalog.load(&candidates[0]).unwrap_err();
    assert!(matches!(miss, CatalogMiss::Quarantined { .. }));
    assert!(catalog.candidates(&matching_query()).unwrap().is_empty());
    let repair = catalog
        .install(&pack, &source(DurablePackSourceKind::Installed, "fixture"))
        .unwrap();
    assert!(!repair.inserted_manifest);
    assert_eq!(repair.inserted_objects, 1);
    let repaired = catalog.candidates(&matching_query()).unwrap();
    assert_eq!(repaired.len(), 1);
    catalog.load(&repaired[0]).unwrap();
}

#[test]
fn populated_selector_dimensions_use_bounded_index_searches() {
    let root = TempDir::new().unwrap();
    drop(
        SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap(),
    );
    let connection = Connection::open(root.path().join("catalog.db")).unwrap();
    for (column, index) in [
        ("package_name", "catalog_selectors_package"),
        ("module_name", "catalog_selectors_module"),
        ("toolchain_name", "catalog_selectors_toolchain"),
        ("artifact_sha256", "catalog_selectors_artifact"),
    ] {
        let sql = format!(
            "EXPLAIN QUERY PLAN
             SELECT * FROM (
               SELECT * FROM catalog_selectors INDEXED BY {index}
               WHERE {column} IS NULL
               UNION ALL
               SELECT * FROM catalog_selectors INDEXED BY {index}
               WHERE {column} = ?1
             )"
        );
        let mut statement = connection.prepare(&sql).unwrap();
        let details = statement
            .query_map(params!["selector"], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            details
                .iter()
                .filter(|detail| detail
                    .contains(&format!("SEARCH catalog_selectors USING INDEX {index}")))
                .count()
                >= 2,
            "{column} plan did not use two bounded index searches: {details:?}"
        );
        assert!(
            details
                .iter()
                .all(|detail| !detail.contains("SCAN catalog_selectors")),
            "{column} plan performed a selector scan: {details:?}"
        );
    }
}

#[test]
fn opening_catalog_removes_unreserved_cas_orphans() {
    let root = TempDir::new().unwrap();
    let pack = compiled_pack();
    let descriptor = &pack.shards[0].descriptor;
    let object_path = root
        .path()
        .join("objects/sha256")
        .join(&descriptor.stored_sha256[..2])
        .join(&descriptor.stored_sha256[2..]);
    fs::create_dir_all(object_path.parent().unwrap()).unwrap();
    fs::write(&object_path, &pack.shards[0].bytes).unwrap();
    let staging = root.path().join("staging");
    fs::create_dir_all(&staging).unwrap();
    let abandoned_stage = staging.join("abandoned");
    fs::write(&abandoned_stage, b"partial").unwrap();
    set_file_mtime(&abandoned_stage, FileTime::from_unix_time(1, 0)).unwrap();

    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();

    assert!(!object_path.exists());
    assert!(!abandoned_stage.exists());
    assert_eq!(catalog.accounting().unwrap().object_count, 0);
}

#[test]
fn reinstall_repairs_corrupt_object_and_manifest_metadata() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let pack = compiled_pack();
    let installed_source = source(DurablePackSourceKind::Installed, "repair");
    catalog.install(&pack, &installed_source).unwrap();
    let descriptor = &pack.shards[0].descriptor;
    let object_path = root
        .path()
        .join("objects/sha256")
        .join(&descriptor.stored_sha256[..2])
        .join(&descriptor.stored_sha256[2..]);
    let mut corrupted = fs::read(&object_path).unwrap();
    corrupted[0] ^= 1;
    fs::write(&object_path, corrupted).unwrap();
    let connection = Connection::open(root.path().join("catalog.db")).unwrap();
    connection
        .execute(
            "UPDATE catalog_packs
             SET manifest_bytes = X'00', state = 'quarantined'
             WHERE manifest_digest = ?1",
            [&pack.manifest.content_sha256],
        )
        .unwrap();
    drop(connection);

    let outcome = catalog.install(&pack, &installed_source).unwrap();

    assert!(!outcome.inserted_manifest);
    assert_eq!(outcome.inserted_objects, 1);
    let candidates = catalog.candidates(&matching_query()).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        catalog.load(&candidates[0]).unwrap().manifest,
        pack.manifest
    );
}

#[test]
fn identical_pack_and_object_deduplicate_across_sources() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let pack = compiled_pack();

    let first = catalog
        .install(&pack, &source(DurablePackSourceKind::Installed, "registry"))
        .unwrap();
    let second = catalog
        .install(
            &pack,
            &source(DurablePackSourceKind::WorkspaceProduced, "workspace-a"),
        )
        .unwrap();

    assert!(first.inserted_manifest);
    assert_eq!(first.inserted_objects, 1);
    assert!(!second.inserted_manifest);
    assert_eq!(second.inserted_objects, 0);
    let accounting = catalog.accounting().unwrap();
    assert_eq!(accounting.object_count, 1);
    assert_eq!(accounting.logical_shard_count, 1);
    assert_eq!(accounting.source_count, 2);
    assert_eq!(
        accounting.installed_stored_bytes,
        pack.shards[0].descriptor.stored_size
    );
}

#[test]
fn oversized_pack_is_rejected_before_durable_publication() {
    let root = TempDir::new().unwrap();
    let mut options = CatalogOptions::default();
    options.decode_limits.max_stored_shard_bytes = 1;
    let catalog =
        SemanticPackCatalog::open(root.path(), CatalogOpenMode::ReadWrite, options).unwrap();
    assert!(matches!(
        catalog.install(
            &compiled_pack(),
            &source(DurablePackSourceKind::Installed, "oversized")
        ),
        Err(CatalogError::Artifact(_))
    ));
    let accounting = catalog.accounting().unwrap();
    assert_eq!(accounting.object_count, 0);
    assert_eq!(accounting.logical_shard_count, 0);
    assert!(
        fs::read_dir(root.path().join("staging"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn corrupt_catalog_metadata_is_quarantined_as_a_safe_miss() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let pack = compiled_pack();
    catalog
        .install(&pack, &source(DurablePackSourceKind::Installed, "metadata"))
        .unwrap();
    let connection = Connection::open(root.path().join("catalog.db")).unwrap();
    connection
        .execute(
            "UPDATE catalog_pack_shards
             SET descriptor_json = X'00'
             WHERE manifest_digest = ?1",
            [&pack.manifest.content_sha256],
        )
        .unwrap();
    drop(connection);

    assert!(catalog.candidates(&matching_query()).unwrap().is_empty());
    assert_eq!(catalog.accounting().unwrap().quarantined_pack_count, 1);
}

#[cfg(unix)]
#[test]
fn install_rejects_symlinked_object_tree() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let sha_root = root.path().join("objects/sha256");
    fs::remove_dir(&sha_root).unwrap();
    std::os::unix::fs::symlink(outside.path(), &sha_root).unwrap();

    assert!(matches!(
        catalog.install(
            &compiled_pack(),
            &source(DurablePackSourceKind::Installed, "symlink")
        ),
        Err(CatalogError::Integrity(_))
    ));
    assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
}

#[test]
fn concurrent_installers_publish_one_complete_pack() {
    let root = TempDir::new().unwrap();
    let pack = Arc::new(compiled_pack());
    let barrier = Arc::new(Barrier::new(4));
    let mut workers = Vec::new();
    for worker in 0..4 {
        let root = root.path().to_owned();
        let pack = Arc::clone(&pack);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            let catalog = SemanticPackCatalog::open(
                &root,
                CatalogOpenMode::ReadWrite,
                CatalogOptions::default(),
            )
            .unwrap();
            catalog
                .install(
                    &pack,
                    &source(
                        DurablePackSourceKind::Generated,
                        &format!("worker-{worker}"),
                    ),
                )
                .unwrap()
        }));
    }

    let outcomes: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.inserted_manifest)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .map(|outcome| outcome.inserted_objects)
            .sum::<usize>(),
        1
    );

    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let candidates = catalog.candidates(&matching_query()).unwrap();
    assert_eq!(candidates.len(), 4);
    assert_eq!(
        catalog.load(&candidates[0]).unwrap().manifest,
        pack.manifest
    );
}

#[test]
fn generated_production_reuses_exact_input_and_rejects_changed_semantics() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = compiled_pack();
    let key = generated_key(&pack, 'a');

    assert!(catalog.generated_production(&key).unwrap().is_none());
    let first = catalog.install_generated(&key, &pack).unwrap();
    assert!(first.install.inserted_manifest);
    assert_eq!(first.install.inserted_objects, 1);
    assert_eq!(
        catalog.generated_production(&key).unwrap(),
        Some(first.production.clone())
    );

    let second = catalog.install_generated(&key, &pack).unwrap();
    assert!(!second.install.inserted_manifest);
    assert_eq!(second.install.inserted_objects, 0);
    assert_eq!(second.production, first.production);

    let changed_input = generated_key(&pack, 'b');
    assert!(
        catalog
            .generated_production(&changed_input)
            .unwrap()
            .is_none()
    );
    let changed_producer = GeneratedProductionKey::new(
        key.input_digest(),
        key.producer_name(),
        "different-producer-version",
        key.schema_version(),
    )
    .unwrap();
    assert!(
        catalog
            .generated_production(&changed_producer)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        catalog.install_generated(&changed_producer, &pack),
        Err(CatalogError::Integrity(_))
    ));
}

#[test]
fn generated_production_key_cannot_rebind_to_different_manifest() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let first_pack = compiled_pack();
    let second_pack = compiled_pack_version("1.0.1");
    let key = generated_key(&first_pack, 'c');
    catalog.install_generated(&key, &first_pack).unwrap();

    let error = catalog
        .install_generated(&key, &second_pack)
        .expect_err("one production key cannot identify two manifests");
    assert!(matches!(error, CatalogError::Integrity(_)));
    assert_eq!(
        catalog
            .generated_production(&key)
            .unwrap()
            .unwrap()
            .manifest_digest,
        first_pack.manifest.content_sha256
    );
}

#[test]
fn concurrent_generated_installers_publish_one_production() {
    let root = TempDir::new().unwrap();
    let pack = Arc::new(compiled_pack());
    let key = Arc::new(generated_key(&pack, 'd'));
    let barrier = Arc::new(Barrier::new(4));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let root = root.path().to_owned();
        let pack = Arc::clone(&pack);
        let key = Arc::clone(&key);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            SemanticPackCatalog::open(&root, CatalogOpenMode::ReadWrite, CatalogOptions::default())
                .unwrap()
                .install_generated(&key, &pack)
                .unwrap()
        }));
    }

    let outcomes: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.install.inserted_manifest)
            .count(),
        1
    );
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.production == outcomes[0].production)
    );

    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadOnly,
        CatalogOptions::default(),
    )
    .unwrap();
    assert_eq!(
        catalog.generated_production(&key).unwrap(),
        Some(outcomes[0].production.clone())
    );
}

#[test]
fn corrupt_generated_production_is_quarantined_as_a_safe_miss() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let pack = compiled_pack();
    let key = generated_key(&pack, 'e');
    catalog.install_generated(&key, &pack).unwrap();
    let connection = Connection::open(root.path().join("catalog.db")).unwrap();
    connection
        .execute(
            "UPDATE catalog_packs SET manifest_bytes = X'00'
             WHERE manifest_digest = ?1",
            [&pack.manifest.content_sha256],
        )
        .unwrap();
    drop(connection);

    assert!(catalog.generated_production(&key).unwrap().is_none());
    assert_eq!(catalog.accounting().unwrap().quarantined_pack_count, 1);
}

#[test]
fn generated_production_is_removed_with_garbage_collected_pack() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let pack = compiled_pack();
    let key = generated_key(&pack, 'f');
    catalog.install_generated(&key, &pack).unwrap();
    assert_eq!(
        catalog
            .garbage_collect(&CatalogGcOptions {
                minimum_age: Duration::ZERO,
                max_packs: 100,
                max_objects: 100,
            })
            .unwrap()
            .pruned_packs,
        1
    );

    assert!(catalog.generated_production(&key).unwrap().is_none());
    let connection = Connection::open(root.path().join("catalog.db")).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM catalog_generated_productions",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn generated_lookup_rejects_corrupt_shard_objects() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let pack = compiled_pack();
    let key = generated_key(&pack, '9');
    catalog.install_generated(&key, &pack).unwrap();
    let connection = Connection::open(root.path().join("catalog.db")).unwrap();
    let relative_path: String = connection
        .query_row(
            "SELECT relative_path FROM catalog_objects LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    fs::write(root.path().join(relative_path), b"corrupt").unwrap();

    assert!(catalog.generated_production(&key).unwrap().is_none());
    assert_eq!(catalog.accounting().unwrap().quarantined_pack_count, 1);
}

#[test]
fn generated_lookup_requires_its_source_binding() {
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let pack = compiled_pack();
    let key = generated_key(&pack, '8');
    catalog.install_generated(&key, &pack).unwrap();
    catalog
        .pin(&pack.manifest.content_sha256, "test-pin")
        .unwrap();
    assert!(
        catalog
            .remove_source(&source(DurablePackSourceKind::Generated, &key.source_id()))
            .unwrap()
    );

    assert!(catalog.generated_production(&key).unwrap().is_none());
    assert!(
        catalog
            .unpin(&pack.manifest.content_sha256, "test-pin")
            .unwrap()
    );
}

#[test]
fn read_only_catalog_supports_lookup_but_rejects_install() {
    let root = TempDir::new().unwrap();
    let pack = compiled_pack();
    {
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        catalog
            .install(&pack, &source(DurablePackSourceKind::PreShipped, "release"))
            .unwrap();
    }

    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadOnly,
        CatalogOptions::default(),
    )
    .unwrap();
    let candidates = catalog.candidates(&matching_query()).unwrap();
    assert_eq!(candidates.len(), 1);
    catalog.load(&candidates[0]).unwrap();
    let descriptor = &pack.shards[0].descriptor;
    let object_path = root
        .path()
        .join("objects/sha256")
        .join(&descriptor.stored_sha256[..2])
        .join(&descriptor.stored_sha256[2..]);
    fs::remove_file(object_path).unwrap();
    assert!(matches!(
        catalog.load(&candidates[0]),
        Err(CatalogMiss::Quarantined { .. })
    ));
    assert!(catalog.candidates(&matching_query()).unwrap().is_empty());
    assert!(matches!(
        catalog.install(
            &pack,
            &source(DurablePackSourceKind::Installed, "forbidden")
        ),
        Err(CatalogError::ReadOnly)
    ));
}

#[test]
fn newer_catalog_schema_is_rejected_without_mutation() {
    let root = TempDir::new().unwrap();
    drop(
        SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap(),
    );
    let database = root.path().join("catalog.db");
    let connection = Connection::open(&database).unwrap();
    connection.pragma_update(None, "user_version", 5).unwrap();
    drop(connection);
    let before = fs::read(&database).unwrap();

    let error = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .err()
    .expect("newer catalog must be rejected");
    assert!(matches!(
        error,
        CatalogError::CatalogTooNew {
            found: 5,
            supported: 4
        }
    ));
    assert_eq!(fs::read(database).unwrap(), before);
}

#[test]
fn catalog_migrations_preserve_existing_catalog_rows() {
    let root = TempDir::new().unwrap();
    let database = root.path().join("catalog.db");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(include_str!(
            "../../crates/bifrost-analysis/migrations/semantic-pack-catalog/0001-current-baseline.sql"
        ))
        .unwrap();
    connection
        .execute(
            "INSERT INTO catalog_quarantine(
               manifest_digest, reason, detail, detected_at
             ) VALUES(?1, 'test', 'preserve me', 1)",
            ["a".repeat(64)],
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    drop(connection);

    drop(
        SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap(),
    );

    let connection = Connection::open(database).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        connection
            .query_row("SELECT detail FROM catalog_quarantine", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
        "preserve me"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'catalog_leases'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}

#[test]
fn procedure_summary_migration_preserves_version_two_pack_rows() {
    let root = TempDir::new().unwrap();
    let pack = compiled_pack();
    {
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        catalog
            .install(
                &pack,
                &source(DurablePackSourceKind::Installed, "pre-migration"),
            )
            .unwrap();
    }

    let database = root.path().join("catalog.db");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch("DROP TABLE catalog_generated_productions;")
        .unwrap();
    connection.pragma_update(None, "user_version", 2).unwrap();
    drop(connection);

    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let candidates = catalog.candidates(&matching_query()).unwrap();
    assert_eq!(candidates.len(), 1);
    let loaded = catalog.load(&candidates[0]).unwrap();
    assert_eq!(
        loaded.shard.payload_kind(),
        pack.shards[0].descriptor.payload_kind
    );
    assert_eq!(
        loaded.shard.record_count() as u64,
        pack.shards[0].descriptor.record_count
    );

    let connection = Connection::open(database).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        4
    );
}

#[test]
fn generated_production_migration_preserves_version_three_pack_rows() {
    let root = TempDir::new().unwrap();
    let pack = compiled_pack();
    {
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        catalog
            .install(
                &pack,
                &source(DurablePackSourceKind::Installed, "pre-production-migration"),
            )
            .unwrap();
    }

    let database = root.path().join("catalog.db");
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch("DROP TABLE catalog_generated_productions;")
        .unwrap();
    connection.pragma_update(None, "user_version", 3).unwrap();
    drop(connection);

    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    assert_eq!(catalog.candidates(&matching_query()).unwrap().len(), 1);

    let connection = Connection::open(database).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE name = 'catalog_generated_productions'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
}

#[test]
fn active_set_digest_is_order_independent_and_persists() {
    let root = TempDir::new().unwrap();
    let database = root.path().join("workspace.db");
    let first = SemanticPackActiveReference {
        manifest_digest: "1".repeat(64),
        source_kind: SemanticPackActivationSourceKind::Installed,
        source_id: "registry".to_owned(),
        workspace_produced: false,
    };
    let second = SemanticPackActiveReference {
        manifest_digest: "2".repeat(64),
        source_kind: SemanticPackActivationSourceKind::WorkspaceProduced,
        source_id: "workspace".to_owned(),
        workspace_produced: true,
    };
    let expected = {
        let store = AnalyzerStore::open_persistent(&database).unwrap();
        let forward = store
            .replace_semantic_pack_active_set(&[first.clone(), second.clone()])
            .unwrap();
        let reverse = store
            .replace_semantic_pack_active_set(&[second.clone(), first.clone()])
            .unwrap();
        assert_eq!(forward, reverse);
        forward
    };

    let reopened = AnalyzerStore::open_persistent(&database).unwrap();
    assert_eq!(reopened.semantic_pack_active_set().unwrap(), Some(expected));
    let connection = Connection::open(database).unwrap();
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        15
    );
}

#[test]
fn session_pack_is_selected_and_loaded_without_durable_accounting() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let pack = compiled_pack();
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "release-resource".to_owned(),
            },
        )
        .unwrap();

    let candidates = catalog.candidates(&matching_query()).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].source_kind(), CatalogPackSourceKind::Embedded);
    assert_eq!(
        catalog.load(&candidates[0]).unwrap().manifest,
        pack.manifest
    );
    let accounting = catalog.accounting().unwrap();
    assert_eq!(accounting.installed_stored_bytes, 0);
    assert_eq!(accounting.object_count, 0);
    assert_eq!(accounting.logical_shard_count, 0);
}

#[test]
fn ephemeral_catalog_and_workspace_state_disappear_on_drop() {
    let pack = compiled_pack();
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let root = catalog.root().to_owned();
    let store = AnalyzerStore::open_in_memory().unwrap();
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::EphemeralWorkspace,
                source_id: "scratch".to_owned(),
            },
        )
        .unwrap();
    let reference = SemanticPackActiveReference {
        manifest_digest: pack.manifest.content_sha256.clone(),
        source_kind: SemanticPackActivationSourceKind::EphemeralWorkspace,
        source_id: "scratch".to_owned(),
        workspace_produced: true,
    };
    store
        .replace_semantic_pack_active_set(&[reference])
        .unwrap();
    catalog
        .reconcile_workspace_active_set("ephemeral", &store)
        .unwrap();
    assert_eq!(catalog.candidates(&matching_query()).unwrap().len(), 1);
    assert_eq!(
        catalog.accounting().unwrap().activations,
        [
            brokk_bifrost::analyzer::semantic_model::ActivationSourceCount {
                source_kind: CatalogPackSourceKind::EphemeralWorkspace,
                source_id: "scratch".to_owned(),
                pack_count: 1,
            }
        ]
    );
    drop(store);
    assert!(catalog.accounting().unwrap().activations.is_empty());
    drop(catalog);
    assert!(!root.exists());
}

#[test]
fn activation_requires_exact_registered_source_and_compatible_store_lifetime() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let pack = compiled_pack();
    catalog
        .install(&pack, &source(DurablePackSourceKind::Installed, "registry"))
        .unwrap();
    let persistent = AnalyzerStore::open_persistent(&root.path().join("workspace.db")).unwrap();
    let fabricated = SemanticPackActiveReference {
        manifest_digest: pack.manifest.content_sha256.clone(),
        source_kind: SemanticPackActivationSourceKind::Generated,
        source_id: "fabricated".to_owned(),
        workspace_produced: false,
    };

    assert!(matches!(
        catalog.replace_workspace_active_set("persistent", &persistent, &[fabricated]),
        Err(CatalogError::Unavailable)
    ));
    assert!(persistent.semantic_pack_active_set().unwrap().is_none());
    assert!(catalog.accounting().unwrap().activations.is_empty());

    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "embedded".to_owned(),
            },
        )
        .unwrap();
    let embedded = SemanticPackActiveReference {
        manifest_digest: pack.manifest.content_sha256.clone(),
        source_kind: SemanticPackActivationSourceKind::Embedded,
        source_id: "embedded".to_owned(),
        workspace_produced: false,
    };
    assert!(matches!(
        catalog.replace_workspace_active_set("persistent", &persistent, &[embedded]),
        Err(CatalogError::Integrity(_))
    ));
    assert!(persistent.semantic_pack_active_set().unwrap().is_none());
}

#[test]
fn ephemeral_workspace_rejects_durable_pack_activation() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let store = AnalyzerStore::open_in_memory().unwrap();
    let pack = compiled_pack();
    let installed_source = source(DurablePackSourceKind::Installed, "registry");
    catalog.install(&pack, &installed_source).unwrap();
    let reference = SemanticPackActiveReference {
        manifest_digest: pack.manifest.content_sha256.clone(),
        source_kind: SemanticPackActivationSourceKind::Installed,
        source_id: "registry".to_owned(),
        workspace_produced: false,
    };
    assert!(matches!(
        catalog.replace_workspace_active_set("scratch", &store, &[reference]),
        Err(CatalogError::Integrity(_))
    ));
    assert!(store.semantic_pack_active_set().unwrap().is_none());
}

#[test]
fn read_only_catalog_activates_session_pack_without_durable_writes() {
    let root = TempDir::new().unwrap();
    drop(
        SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap(),
    );
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadOnly,
        CatalogOptions::default(),
    )
    .unwrap();
    let store = AnalyzerStore::open_in_memory().unwrap();
    let pack = compiled_pack();
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "release".to_owned(),
            },
        )
        .unwrap();
    let reference = SemanticPackActiveReference {
        manifest_digest: pack.manifest.content_sha256.clone(),
        source_kind: SemanticPackActivationSourceKind::Embedded,
        source_id: "release".to_owned(),
        workspace_produced: false,
    };

    catalog
        .replace_workspace_active_set("read-only-session", &store, &[reference])
        .unwrap();

    assert_eq!(
        catalog.accounting().unwrap().activations[0].source_kind,
        CatalogPackSourceKind::Embedded
    );
}

#[test]
fn source_removal_preserves_authoritative_workspace_reconciliation() {
    let root = TempDir::new().unwrap();
    let workspace_db = root.path().join("workspace.db");
    let pack = compiled_pack();
    let installed_source = source(DurablePackSourceKind::Installed, "registry");
    {
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let store = AnalyzerStore::open_persistent(&workspace_db).unwrap();
        catalog.install(&pack, &installed_source).unwrap();
        let reference = SemanticPackActiveReference {
            manifest_digest: pack.manifest.content_sha256.clone(),
            source_kind: SemanticPackActivationSourceKind::Installed,
            source_id: "registry".to_owned(),
            workspace_produced: false,
        };
        catalog
            .replace_workspace_active_set("workspace", &store, &[reference])
            .unwrap();
        assert!(catalog.remove_source(&installed_source).unwrap());
    }
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let store = AnalyzerStore::open_persistent(&workspace_db).unwrap();

    assert!(
        catalog
            .reconcile_workspace_active_set("workspace", &store)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        catalog
            .garbage_collect(&CatalogGcOptions {
                minimum_age: Duration::ZERO,
                max_packs: 100,
                max_objects: 100,
            })
            .unwrap()
            .pruned_packs,
        0
    );
}

#[test]
fn active_accounting_deduplicates_durable_and_session_bytes() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let pack = compiled_pack();
    catalog
        .install(&pack, &source(DurablePackSourceKind::Installed, "registry"))
        .unwrap();
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: "release".to_owned(),
            },
        )
        .unwrap();
    let persistent = AnalyzerStore::open_persistent(&root.path().join("workspace.db")).unwrap();
    catalog
        .replace_workspace_active_set(
            "durable",
            &persistent,
            &[SemanticPackActiveReference {
                manifest_digest: pack.manifest.content_sha256.clone(),
                source_kind: SemanticPackActivationSourceKind::Installed,
                source_id: "registry".to_owned(),
                workspace_produced: false,
            }],
        )
        .unwrap();
    let ephemeral = AnalyzerStore::open_in_memory().unwrap();
    catalog
        .replace_workspace_active_set(
            "session",
            &ephemeral,
            &[SemanticPackActiveReference {
                manifest_digest: pack.manifest.content_sha256.clone(),
                source_kind: SemanticPackActivationSourceKind::Embedded,
                source_id: "release".to_owned(),
                workspace_produced: false,
            }],
        )
        .unwrap();

    let accounting = catalog.accounting().unwrap();

    assert_eq!(
        accounting.active_stored_bytes,
        pack.shards[0].descriptor.stored_size
    );
    assert_eq!(accounting.active_shard_count, 1);
}

#[test]
fn activation_pin_and_lease_independently_protect_garbage_collection() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let store = AnalyzerStore::open_persistent(&root.path().join("workspace.db")).unwrap();
    let pack = compiled_pack();
    let installed_source = source(DurablePackSourceKind::Installed, "registry");
    catalog.install(&pack, &installed_source).unwrap();
    let reference = SemanticPackActiveReference {
        manifest_digest: pack.manifest.content_sha256.clone(),
        source_kind: SemanticPackActivationSourceKind::Installed,
        source_id: "registry".to_owned(),
        workspace_produced: false,
    };
    catalog
        .replace_workspace_active_set("workspace-a", &store, &[reference])
        .unwrap();
    assert!(catalog.remove_source(&installed_source).unwrap());

    let collect_now = CatalogGcOptions {
        minimum_age: Duration::ZERO,
        max_packs: 100,
        max_objects: 100,
    };
    assert_eq!(
        catalog.garbage_collect(&collect_now).unwrap().pruned_packs,
        0
    );
    let accounting = catalog.accounting().unwrap();
    assert_eq!(
        accounting.active_stored_bytes,
        pack.shards[0].descriptor.stored_size
    );
    assert_eq!(accounting.active_shard_count, 1);
    assert_eq!(accounting.activations[0].source_id, "registry");

    catalog
        .replace_workspace_active_set("workspace-a", &store, &[])
        .unwrap();
    let collected = catalog.garbage_collect(&collect_now).unwrap();
    assert_eq!(collected.pruned_packs, 1);
    assert_eq!(collected.pruned_objects, 1);

    let pinned_pack = compiled_pack_version("1.0.1");
    let pinned_source = source(DurablePackSourceKind::Generated, "generator");
    catalog.install(&pinned_pack, &pinned_source).unwrap();
    catalog
        .pin(&pinned_pack.manifest.content_sha256, "keep")
        .unwrap();
    assert!(catalog.remove_source(&pinned_source).unwrap());
    assert_eq!(
        catalog.garbage_collect(&collect_now).unwrap().pruned_packs,
        0
    );
    assert!(
        catalog
            .unpin(&pinned_pack.manifest.content_sha256, "keep")
            .unwrap()
    );

    let lease = catalog
        .lease(
            &pinned_pack.manifest.content_sha256,
            "test-reader",
            Duration::from_secs(60),
        )
        .unwrap();
    assert_eq!(
        catalog.garbage_collect(&collect_now).unwrap().pruned_packs,
        0
    );
    lease.release().unwrap();
    let collected = catalog.garbage_collect(&collect_now).unwrap();
    assert_eq!(collected.pruned_packs, 1);
    assert_eq!(collected.pruned_objects, 1);
}

#[test]
fn subsecond_lease_protects_pack_and_missing_object_reclaims_no_bytes() {
    let root = TempDir::new().unwrap();
    let catalog = SemanticPackCatalog::open(
        root.path(),
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .unwrap();
    let pack = compiled_pack();
    let installed_source = source(DurablePackSourceKind::Installed, "registry");
    catalog.install(&pack, &installed_source).unwrap();
    let lease = catalog
        .lease(
            &pack.manifest.content_sha256,
            "subsecond-reader",
            Duration::from_millis(500),
        )
        .unwrap();
    assert!(catalog.remove_source(&installed_source).unwrap());
    let collect_now = CatalogGcOptions {
        minimum_age: Duration::ZERO,
        max_packs: 100,
        max_objects: 100,
    };
    assert_eq!(
        catalog.garbage_collect(&collect_now).unwrap().pruned_packs,
        0
    );
    lease.release().unwrap();
    let descriptor = &pack.shards[0].descriptor;
    let object_path = root
        .path()
        .join("objects/sha256")
        .join(&descriptor.stored_sha256[..2])
        .join(&descriptor.stored_sha256[2..]);
    fs::remove_file(object_path).unwrap();

    let outcome = catalog.garbage_collect(&collect_now).unwrap();

    assert_eq!(outcome.pruned_packs, 1);
    assert_eq!(outcome.pruned_objects, 1);
    assert_eq!(outcome.reclaimed_bytes, 0);
}
