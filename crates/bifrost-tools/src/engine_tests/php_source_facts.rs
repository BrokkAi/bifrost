#[cfg(test)]
mod php_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_php_analysis::analyzer::php::adapter::PhpAdapter;

    use brokk_bifrost_php_analysis::analyzer::php::source_storage::PhpSourceStorage;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::StoreError;

    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    const SOURCE: &str = r#"<?php
namespace Example;

use Vendor\Package as PackageAlias;
use Vendor\{A as AliasA, B as AliasB};

class Base {}
class Child extends Base {
    /** @var list<int> */
    public array $items;

    public function __construct() {
        $this->items = [];
    }
}

function make(?PackageAlias $value): Child { return new Child(); }
"#;

    #[test]
    fn php_declaration_source_facts_reopen_without_source_and_mount_exact_bridges() {
        let fixture = InlineTestProject::with_language(Language::Php)
            .file("first/types.php", SOURCE)
            .file("second/types.php", SOURCE)
            .build();
        let file = fixture.file("first/types.php");
        let second = fixture.file("second/types.php");
        let state = parse_state(&PhpAdapter, &file);
        let expected = state.source_facts.as_ref().unwrap().php.as_ref().unwrap();
        assert!(!expected.contexts.is_empty());
        assert!(!expected.declarations.is_empty());
        let oid = oid_for(SOURCE.as_bytes());
        let path = fixture.root().join("php-source.db");
        {
            let store = AnalyzerStore::open_persistent(&path).unwrap();
            store
                .write_parsed_blob(
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "php"),
                    &PhpAdapter,
                    &state,
                )
                .unwrap();
            store
            .conn
            .execute(move |conn| {
                let mut statement = conn.prepare(
                    "SELECT imports.alias, imports.identifier
                       FROM source_php_aliases AS aliases
                       JOIN source_imports AS imports
                         ON imports.blob_id = aliases.blob_id
                        AND imports.import_id = aliases.source_import_id
                      WHERE aliases.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'php')
                      ORDER BY aliases.alias_id",
                )?;
                let rows = statement
                    .query_map([oid.to_string()], |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<String>>(1)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                assert!(rows
                    .iter()
                    .any(|(alias, _)| alias.as_deref() == Some("AliasA")));
                assert!(rows
                    .iter()
                    .any(|(alias, _)| alias.as_deref() == Some("AliasB")));
                assert!(rows.iter().all(|(alias, identifier)| {
                    alias.as_deref().is_some_and(|alias| !alias.is_empty())
                        && identifier
                            .as_deref()
                            .is_some_and(|identifier| !identifier.is_empty())
                }));
                Ok::<_, StoreError>(())
            })
            .unwrap();
        }
        std::fs::remove_file(file.abs_path()).unwrap();
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let generation = store.current_generation("php").unwrap();
        let (first, mounted) = brokk_bifrost_analysis::analyzer::store::source_facts::assert_source_facts_match_across_mounts(
        &store,
        generation,
        &file,
        &second,
        |store, generation, file, cancellation| {
            store.php_source_facts(oid, generation, &PhpAdapter, file, cancellation)
        },
        |read| &read.facts,
    );
        assert_eq!(&first.facts, expected);
        assert_eq!(first.imports, state.source_facts.as_ref().unwrap().imports);
        assert_eq!(first.imports, mounted.imports);
        assert_eq!(
            first.source,
            state.source_facts.as_ref().unwrap().occurrences
        );
        assert!(
            first
                .declaration_units
                .values()
                .flatten()
                .all(|unit| unit.source() == &file)
        );
        assert!(
            mounted
                .declaration_units
                .values()
                .flatten()
                .all(|unit| unit.source() == &second)
        );
        brokk_bifrost_analysis::analyzer::store::source_facts::assert_source_read_cancellation_retries(|cancellation| {
        store.php_source_facts(oid, generation, &PhpAdapter, &file, cancellation)
    });
    }

    #[test]
    fn php_source_publication_rejects_invalid_context_and_sealed_mutation() {
        let fixture = InlineTestProject::with_language(Language::Php)
            .file("types.php", SOURCE)
            .build();
        let file = fixture.file("types.php");
        let state = parse_state(&PhpAdapter, &file);
        let oid = oid_for(SOURCE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("php").unwrap();
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "php"),
                &PhpAdapter,
                &state,
            )
            .unwrap();
        store
        .conn
        .execute(|conn| {
            assert!(
                conn.execute("UPDATE source_php_contexts SET namespace = namespace", [])
                    .is_err()
            );
            assert!(
                conn.execute(
                    "UPDATE source_php_manifests SET payload_bytes = payload_bytes",
                    []
                )
                .is_err()
            );
            conn.execute_batch(
                "DROP TRIGGER source_php_declarations_no_update_after_seal;",
            )?;
            assert!(conn.execute(
                "UPDATE source_php_declarations SET context_id = (SELECT MAX(context_id) + 1 FROM source_php_contexts)",
                [],
            ).is_err());
            Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
        })
        .unwrap();
        assert!(
            store
                .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn php_source_requires_a_sealed_canonical_source_manifest() {
        let fixture = InlineTestProject::with_language(Language::Php)
            .file("types.php", SOURCE)
            .build();
        let file = fixture.file("types.php");
        let state = parse_state(&PhpAdapter, &file);
        let oid = oid_for(SOURCE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("php").unwrap();
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "php"),
                &PhpAdapter,
                &state,
            )
            .unwrap();
        store
        .conn
        .execute(|conn| {
            conn.execute_batch("DROP TRIGGER source_fact_manifests_no_reopen; UPDATE source_fact_manifests SET publication_state = 'building';")?;
            Ok::<_, StoreError>(())
        })
        .unwrap();
        assert!(
            store
                .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
                .is_err()
        );
    }

    #[test]
    fn php_source_publication_count_and_cascade_are_enforced() {
        let fixture = InlineTestProject::with_language(Language::Php)
            .file("empty.php", "<?php\n")
            .file("types.php", SOURCE)
            .build();
        let empty_file = fixture.file("empty.php");
        let populated_file = fixture.file("types.php");
        let empty_state = parse_state(&PhpAdapter, &empty_file);
        let populated_state = parse_state(&PhpAdapter, &populated_file);
        let empty_oid = oid_for(empty_state.source.as_bytes());
        let populated_oid = oid_for(SOURCE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("php").unwrap();
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(empty_oid, "php"),
                &PhpAdapter,
                &empty_state,
            )
            .unwrap();
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(populated_oid, "php"),
                &PhpAdapter,
                &populated_state,
            )
            .unwrap();
        assert!(
            store
                .php_source_facts(empty_oid, generation, &PhpAdapter, &empty_file, &|| true)
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .php_source_facts(
                    populated_oid,
                    generation,
                    &PhpAdapter,
                    &populated_file,
                    &|| true
                )
                .unwrap()
                .is_some()
        );
        store
            .conn
            .execute(|conn| {
                let writes: i64 =
                    conn.query_row("SELECT COUNT(*) FROM source_php_writes", [], |row| {
                        row.get(0)
                    })?;
                assert!(writes > 0);
                conn.execute("DELETE FROM blobs", [])?;
                for table in [
                    "source_php_writes",
                    "source_php_declarations",
                    "source_php_aliases",
                    "source_php_manifests",
                ] {
                    let count: i64 =
                        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                            row.get(0)
                        })?;
                    assert_eq!(count, 0, "blob deletion must cascade {table}");
                }
                Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
            })
            .unwrap();
    }

    #[test]
    fn php_source_lookup_seeks_populated_publications_before_and_after_statistics() {
        let fixture = InlineTestProject::with_language(Language::Php)
            .file("types.php", SOURCE)
            .build();
        let file = fixture.file("types.php");
        let state = parse_state(&PhpAdapter, &file);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("php").unwrap();
        let oid = oid_for(SOURCE.as_bytes());
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "php"),
                &PhpAdapter,
                &state,
            )
            .unwrap();
        for index in 0..32 {
            let other = oid_for(format!("planner PHP publication {index}").as_bytes());
            store
                .write_parsed_blob(
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(other, "php"),
                    &PhpAdapter,
                    &state,
                )
                .unwrap();
        }
        brokk_bifrost_analysis::analyzer::store::source_facts::assert_source_lookup_plan(
            &store,
            |conn| {
                conn.prepare(&format!(
                    "EXPLAIN QUERY PLAN {}",
                    brokk_bifrost_php_analysis::analyzer::php::source_storage::PHP_SOURCE_HEADER_SQL
                ))
                .unwrap()
                .query_map(
                    rusqlite::params![
                        oid.to_string(),
                        generation.get(),
                        1,
                        brokk_bifrost_analysis::analyzer::store::source_facts::SOURCE_FACTS_VERSION
                    ],
                    |row| row.get::<_, String>(3),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
            },
            || {
                store
                    .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
                    .unwrap()
                    .is_some()
            },
        );
    }

    #[test]
    fn php_source_missing_family_is_unavailable_and_repaired_by_publication() {
        let fixture = InlineTestProject::with_language(Language::Php)
            .file("empty.php", "<?php\n")
            .build();
        let file = fixture.file("empty.php");
        let mut state = parse_state(&PhpAdapter, &file);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("php").unwrap();
        let facts = state.source_facts.as_mut().unwrap().php.take().unwrap();
        assert!(
            store
                .write_parsed_blob(
                    &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "php"),
                    &PhpAdapter,
                    &state
                )
                .is_err()
        );
        state.source_facts.as_mut().unwrap().php = Some(facts);
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "php"),
                &PhpAdapter,
                &state,
            )
            .unwrap();
        assert!(
            store
                .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
                .unwrap()
                .unwrap()
                .facts
                .declarations
                .is_empty()
        );
        store.conn.execute(|conn| {
        conn.execute("UPDATE blob_meta SET is_complete = 0", [])?;
        assert!(conn.execute("UPDATE blob_meta SET php_source_version = NULL", []).is_err());
        conn.execute("UPDATE blob_meta SET is_complete = 1", [])?;
        conn.execute_batch("DROP TRIGGER source_php_manifests_no_delete_after_seal; DELETE FROM source_php_manifests;")?;
        let available: i64 = conn.query_row("SELECT available FROM source_fact_readiness", [], |row| row.get(0))?;
        assert_eq!(available, 0);
        Ok::<_, StoreError>(())
    }).unwrap();
        assert!(
            store
                .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
                .is_err()
        );
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "php"),
                &PhpAdapter,
                &state,
            )
            .unwrap();
        assert!(
            store
                .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn php_source_rejects_payload_accounting_corruption() {
        let fixture = InlineTestProject::with_language(Language::Php)
            .file("types.php", SOURCE)
            .build();
        let file = fixture.file("types.php");
        let state = parse_state(&PhpAdapter, &file);
        let oid = oid_for(SOURCE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("php").unwrap();
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "php"),
                &PhpAdapter,
                &state,
            )
            .unwrap();
        brokk_bifrost_analysis::analyzer::store::source_facts::assert_reader_rejects_tampering(
            || {
                store.conn.execute(|conn| {
                    conn.execute_batch(
                        "DROP TRIGGER source_php_manifests_no_update_after_seal;
                     UPDATE source_php_manifests SET payload_bytes = payload_bytes + 1;",
                    )?;
                    Ok::<_, StoreError>(())
                })
            },
            || store.php_source_facts(oid, generation, &PhpAdapter, &file, &|| true),
        );
    }

    #[test]
    fn php_source_properties_preserve_sparse_shared_declaration_ids() {
        let fixture = InlineTestProject::with_language(Language::Php)
            .file("types.php", SOURCE)
            .build();
        let file = fixture.file("types.php");
        let mut state = parse_state(&PhpAdapter, &file);
        let facts = state.source_facts.as_mut().unwrap().php.as_mut().unwrap();
        // A shared declaration can have no PHP extension row. Later PHP rows
        // retain their shared identities; their vector positions are not IDs.
        facts.declarations.remove(0);
        let expected = facts.clone();
        assert!(expected.declarations[0].declaration.get() > 0);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("php").unwrap();
        let oid = oid_for(SOURCE.as_bytes());
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "php"),
                &PhpAdapter,
                &state,
            )
            .unwrap();
        let read = store
            .php_source_facts(oid, generation, &PhpAdapter, &file, &|| true)
            .unwrap()
            .unwrap();
        assert_eq!(read.facts, expected);
    }

    /// #4288: a grouped `use` with a trailing comma is valid PHP 7.2+, but
    /// tree-sitter-php 0.24.2 has no rule for it, so recovery inserts a phantom
    /// clause with an empty name; a `use` inside a function body and a bare
    /// `use ;` are the other recovery shapes the grammar admits as statements.
    /// The producer must hold its generic import list equal to the canonical
    /// source imports, because `ImportRows::from_imports` zips them by ordinal
    /// and asserts equal length. The pin asserts the equality invariant, not the
    /// counts, so it survives a grammar fix that stops synthesizing the phantom.
    #[test]
    fn php_import_projections_agree_on_recovery_import_shapes() {
        let source = r#"<?php

namespace Abraham\TwitterOAuth;

use Abraham\TwitterOAuth\{
    Consumer,
    HmacSha1,
    Response,
    Token,
    Util\JsonDecoder,
};
use Composer\CaBundle\CaBundle;

class TwitterOAuth
{
    public function request(string $path): void
    {
        use function Vendor\helper;
    }
}

use ;
"#;
        let fixture = InlineTestProject::with_language(Language::Php)
            .file("src/TwitterOAuth.php", source)
            .build();
        let file = fixture.file("src/TwitterOAuth.php");
        let state = parse_state(&PhpAdapter, &file);
        let source_facts = state.source_facts.as_ref().unwrap();
        assert_eq!(state.imports.len(), source_facts.imports.len());
        assert_eq!(state.imports.len(), source_facts.generic_imports.len());
        let oid = oid_for(source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        // Pre-fix this panicked in `ImportRows::from_imports`: the producer
        // overwrote the generic list with a second interpretation that skipped
        // the phantom clause and the nested `use`.
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "php"),
                &PhpAdapter,
                &state,
            )
            .unwrap();
    }
}
