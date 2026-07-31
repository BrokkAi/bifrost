use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use brokk_bifrost::analyzer::semantic_model::{
    AuthoredSemanticModelPack, CatalogCoordinate, CatalogError, CatalogGcOptions, CatalogMiss,
    CatalogOpenMode, CatalogOptions, CatalogPackSourceKind, DurablePackSource,
    DurablePackSourceKind, SemanticPackCatalog, SemanticPackSelectorQuery, SessionPackSource,
    SessionPackSourceKind, SourceFormat, compile_pack, compile_source,
};
use brokk_bifrost::analyzer::semantic_model::{CompiledSemanticModelPack, CompilerOptions};
use brokk_bifrost::analyzer::store::{
    AnalyzerStore, SemanticPackActivationSourceKind, SemanticPackActiveReference,
};
use rusqlite::Connection;
use semver::Version;
use tempfile::TempDir;

const DECLARATIONS_JSON: &[u8] =
    include_bytes!("../fixtures/semantic-model-packs/declarations-v1.json");

fn compiled_pack() -> CompiledSemanticModelPack {
    compile_source(
        SourceFormat::Json,
        DECLARATIONS_JSON,
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
    let mut stale = candidates[0].clone();
    stale.shard_id.push_str("-stale");
    assert_eq!(catalog.load(&stale).unwrap_err(), CatalogMiss::NotFound);
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
            let catalog = SemanticPackCatalog::open(
                &root,
                CatalogOpenMode::ReadWrite,
                CatalogOptions::default(),
            )
            .unwrap();
            barrier.wait();
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
    connection.pragma_update(None, "user_version", 3).unwrap();
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
            found: 3,
            supported: 2
        }
    ));
    assert_eq!(fs::read(database).unwrap(), before);
}

#[test]
fn lifecycle_migration_preserves_existing_catalog_rows() {
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
        2
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
        13
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
    assert_eq!(candidates[0].source_kind, CatalogPackSourceKind::Embedded);
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
    let root;
    {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        root = catalog.root().to_owned();
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
        catalog
            .replace_workspace_active_set("ephemeral", &store, &[reference])
            .unwrap();
        assert!(store.semantic_pack_active_set().unwrap().is_some());
        assert_eq!(catalog.candidates(&matching_query()).unwrap().len(), 1);
    }
    assert!(!root.exists());
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
