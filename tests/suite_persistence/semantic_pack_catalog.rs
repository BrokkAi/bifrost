use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

use brokk_bifrost::analyzer::semantic_model::{
    CatalogCoordinate, CatalogError, CatalogMiss, CatalogOpenMode, CatalogOptions,
    DurablePackSource, DurablePackSourceKind, SemanticPackCatalog, SemanticPackSelectorQuery,
    SourceFormat, compile_source,
};
use brokk_bifrost::analyzer::semantic_model::{CompiledSemanticModelPack, CompilerOptions};
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
    connection.pragma_update(None, "user_version", 2).unwrap();
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
            found: 2,
            supported: 1
        }
    ));
    assert_eq!(fs::read(database).unwrap(), before);
}
