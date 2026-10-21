#[cfg(test)]
pub(crate) mod go_publication_tests {
    use brokk_bifrost_core::analyzer::model::StructuredImportPathKind;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    use crate::inline_project::InlineTestProject;

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub mod go_extraction_support_3 {
        use brokk_bifrost_go_analysis::analyzer::go::source_storage::GoSourceStorage;

        use brokk_bifrost_analysis::analyzer::store::source_facts::import_read::read_source_imports;

        use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

        use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

        use brokk_bifrost_analysis::analyzer::store::read_import_infos;

        use brokk_bifrost_analysis::analyzer::store::stored_unit_keys;

        use brokk_bifrost_analysis::analyzer::structural::facts::FileFacts;

        use brokk_bifrost_analysis::analyzer::structural::facts::STRUCTURAL_FACTS_VERSION;

        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;

        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

        use brokk_bifrost_core::analyzer::structural::facts::StructuralFactRows;

        #[doc(hidden)]
        pub fn assert_published_canonical_source<A: LanguageAdapter>(
            fixture: &crate::inline_project::BuiltInlineTestProject,
            relative_path: &str,
            lang: &str,
            adapter: &A,
            state: &FileState,
        ) {
            let facts = state.source_facts.as_ref().expect("canonical source facts");
            let expected_imports = facts.imports.clone();
            let expected_generic_imports = state.imports.clone();
            // A recovered region publishes its span; whether a callable contains it
            // is the store's answer when it reads the row back (#3777), so the parse
            // alone cannot state the expected region rows.
            let (nodes, roles, occurrence_roles, recovered_regions) =
                facts.structural.clone().into_parts();
            let mut expected_structural = FileFacts::from_source_and_rows(
                state.source.clone(),
                facts.occurrences.clone(),
                StructuralFactRows::new(nodes, roles, occurrence_roles, Vec::new()),
            )
            .persisted_rows()
            .expect("canonical structural rows");
            let expected_occurrences = facts.occurrences.occurrence_count() as i64;
            let expected_declarations = facts.occurrences.declaration_count() as i64;
            let expected_structural_nodes = facts.structural.nodes().len() as i64;
            let unit_keys = stored_unit_keys(adapter, state);
            let mut expected_bridge_pairs = state
                .source_declaration_units
                .iter()
                .filter_map(|(declaration, unit)| {
                    unit_keys.get(unit).map(|key| (*declaration, *key))
                })
                .collect::<Vec<_>>();
            expected_bridge_pairs
                .sort_unstable_by_key(|(declaration, key)| (declaration.get(), *key));
            expected_bridge_pairs.dedup();
            let expected_bridge_rows = expected_bridge_pairs.len() as i64;
            assert!(
                expected_bridge_rows > 0,
                "fixture must publish declaration bridges"
            );
            let oid = oid_for(state.source.as_bytes());
            let store_path = fixture
                .root()
                .join(format!("{lang}-canonical-publication.db"));

            let store =
                AnalyzerStore::open_persistent(&store_path).expect("open publication store");
            store
                .write_parsed_blob(oid, lang, adapter, state)
                .expect("canonical publication succeeds");
            drop(store);

            let reopened =
                AnalyzerStore::open_persistent(&store_path).expect("reopen publication store");
            let generation = reopened
                .current_generation(lang)
                .expect("current language generation");
            let published = reopened
                .load_structural_facts_rows(oid, lang, generation, STRUCTURAL_FACTS_VERSION)
                .expect("read canonical structural rows")
                .expect("published canonical structural rows");
            assert_eq!(
                published
                    .recovered_regions
                    .iter()
                    .map(|region| (region.span.start as usize, region.span.end as usize))
                    .collect::<Vec<_>>(),
                recovered_regions
                    .iter()
                    .map(|span| (span.start_byte, span.end_byte))
                    .collect::<Vec<_>>(),
                "the store must publish every recovered region the parse found"
            );
            expected_structural.recovered_regions = published.recovered_regions.clone();
            assert_eq!(
                published, expected_structural,
                "structural consumers must read the source-owned publication"
            );

            let conn = reopened.read_conn().expect("read publication store");
            let blob_id: i64 = conn
                .query_row(
                    "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
                    rusqlite::params![oid.to_string(), lang],
                    |row| row.get(0),
                )
                .expect("published blob id");

            let typed_imports = read_source_imports(&conn, blob_id, &|| true)
                .expect("typed source import read")
                .expect("typed source import publication");
            assert_eq!(typed_imports, expected_imports);
            assert_eq!(
                read_import_infos(&conn, &oid.to_string(), lang).expect("generic import read"),
                expected_generic_imports,
                "generic imports must remain a projection of canonical source imports"
            );

            let (generic_rows, linked_generic_rows, link_only_generic_rows): (i64, i64, i64) = conn
                .query_row(
                    "SELECT count(*),
                    count(*) FILTER (WHERE source_import_id IS NOT NULL),
                    count(*) FILTER (WHERE source_import_id IS NOT NULL
                        AND statement IS NULL AND is_wildcard IS NULL AND is_global IS NULL
                        AND identifier IS NULL AND alias IS NULL AND path_kind IS NULL
                        AND declaration_start_byte IS NULL AND binder_start IS NULL
                        AND binder_end IS NULL AND declaration_occurrence_id IS NULL
                        AND binder_occurrence_id IS NULL)
             FROM import_statements WHERE blob_id = ?1",
                    [blob_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("canonical generic projection rows");
            assert_eq!(generic_rows, expected_generic_imports.len() as i64);
            assert_eq!(linked_generic_rows, generic_rows);
            assert_eq!(link_only_generic_rows, generic_rows);
            let actual_bridge_pairs = conn
                .prepare(
                    "SELECT declaration_id, unit_key FROM source_declaration_units
             WHERE blob_id = ?1 ORDER BY declaration_id, unit_key",
                )
                .expect("prepare declaration bridge query")
                .query_map([blob_id], |row| Ok((row.get(0)?, row.get(1)?)))
                .expect("read declaration bridges")
                .collect::<rusqlite::Result<Vec<(i64, i64)>>>()
                .expect("collect declaration bridges");
            let expected_bridge_pairs = expected_bridge_pairs
                .iter()
                .map(|(declaration, key)| (i64::from(declaration.get()), *key))
                .collect::<Vec<_>>();
            assert_eq!(actual_bridge_pairs, expected_bridge_pairs);

            let counts = conn
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM source_fact_manifests WHERE blob_id = ?1),
                 (SELECT COUNT(*) FROM source_occurrences WHERE blob_id = ?1),
                 (SELECT COUNT(*) FROM source_declarations WHERE blob_id = ?1),
                 (SELECT COALESCE(json_array_length(nodes), 0) FROM source_structural_facts WHERE blob_id = ?1),
                 (SELECT COUNT(*) FROM resolution_semantic_sites WHERE blob_id = ?1),
                 (SELECT COUNT(*) FROM resolution_semantic_sites
                    WHERE blob_id = ?1 AND semantic_role = 'reference'),
                 (SELECT COUNT(*) FROM source_declaration_units WHERE blob_id = ?1),
                 (SELECT COUNT(*) FROM source_declaration_units AS bridge
                    LEFT JOIN source_declarations AS declaration
                      ON declaration.blob_id = bridge.blob_id
                     AND declaration.declaration_id = bridge.declaration_id
                   WHERE bridge.blob_id = ?1 AND declaration.declaration_id IS NULL)",
            [blob_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .expect("canonical publication counts");
            assert_eq!(counts.0, 1, "one complete source-facts manifest");
            assert_eq!(counts.1, expected_occurrences);
            assert_eq!(counts.2, expected_declarations);
            assert_eq!(counts.3, expected_structural_nodes);
            assert!(counts.5 > 0, "fixture must publish native references");
            assert!(
                counts.5 <= counts.4,
                "every native reference site is a semantic site"
            );
            assert_eq!(counts.6, expected_bridge_rows);
            assert_eq!(
                counts.7, 0,
                "declaration bridges must stay in the source domain"
            );

            // The reference-site relation is interior detail now. What publication
            // still owns is the definition half, which must name a declaration of this
            // blob and nothing outside it. A Go named or blank import spec is a
            // file-scope binder without a source declaration; its own row family,
            // resolution_go_package_imports, bridges it to the import occurrence.
            let orphan_definition_sites: i64 = conn
                .query_row(
                    "SELECT COUNT(*)
               FROM resolution_semantic_sites AS site
               LEFT JOIN source_native_declaration_bridges AS bridge
                 ON bridge.blob_id = site.blob_id AND bridge.source_site = site.source_site
              WHERE site.blob_id = ?1 AND site.semantic_role = 'definition'
                AND bridge.declaration_id IS NULL
                AND NOT EXISTS (
                    SELECT 1 FROM resolution_go_package_imports AS import
                     WHERE import.blob_id = site.blob_id
                       AND import.source_site = site.source_site
                )",
                    [blob_id],
                    |row| row.get(0),
                )
                .expect("validate native definition-site links");
            assert_eq!(orphan_definition_sites, 0);

            let hydrated = reopened
                .hydrate_file_state(oid, lang, adapter, &fixture.file(relative_path))
                .expect("hydrate published file")
                .expect("published file state");
            assert_eq!(hydrated.imports, expected_generic_imports);
            if let Some(expected) = facts.go.as_ref() {
                let source = reopened
                    .go_source_facts(
                        oid,
                        generation,
                        adapter,
                        &fixture.file(relative_path),
                        &|| true,
                    )
                    .expect("hydrate Go source properties")
                    .expect("published Go source properties");
                assert_eq!(
                    &source.facts, expected,
                    "Go source properties survive reopening"
                );
            }
        }
    }

    use self::go_extraction_support_3::assert_published_canonical_source;
    #[test]
    fn java_canonical_publication_reopens_imports_structural_rows_and_native_links() {
        let source = r#"import java.util.*;
import static java.lang.Math.max;
import java.lang.String;
import broken.;
class C {
    int field;
    void run() {
        int local = field;
        max(local);
    }
}
"#;
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("src/C.java", source)
            .build();
        let state = parse_state(&JavaAdapter, &fixture.file("src/C.java"));
        let facts = state.source_facts.as_ref().expect("Java source facts");
        assert_eq!(facts.imports.len(), 4);
        assert!(facts.imports[0].is_wildcard);
        assert_eq!(
            facts.imports[0].path.as_ref().and_then(|path| path.kind),
            Some(StructuredImportPathKind::Namespace)
        );
        assert!(
            facts.imports[3].path.is_none(),
            "malformed Java path is unavailable"
        );
        assert!(!facts.structural.nodes().is_empty());
        assert!(!facts.native_declaration_sources.is_empty());
        assert_published_canonical_source(&fixture, "src/C.java", "java", &JavaAdapter, &state);
    }
}
