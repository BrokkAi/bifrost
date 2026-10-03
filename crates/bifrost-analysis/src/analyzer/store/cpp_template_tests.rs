//! Persisted C++ class-template metadata through production publication.
//!
//! R5.2 replaced the opaque `unit_cpp_template_metadata` payload with five
//! relational families. What the parser produces must survive publication and
//! come back identical, including the four shapes the opaque payload used to
//! carry for free: parameter defaults, variadic parameters, specialization
//! arguments and alias targets with or without arguments.

use super::tests::{assert_direct_prepared_parity, oid_for, parse_state};
use super::*;
use crate::analyzer::cpp::CppAdapter;
use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::model::{CppTemplateMetadata, CppTemplateTerm};

/// Declares, in order: a primary class template with a defaulted parameter, a
/// non-type parameter and a variadic parameter; its partial specialization,
/// which carries specialization arguments; an alias template whose target is a
/// qualified name with arguments; and an alias template whose target has no
/// argument list at all.
const TEMPLATE_SOURCE: &str = concat!(
    "namespace demo {\n",
    "class Holder {};\n",
    "template <typename T, typename U = T*, unsigned N = 4, typename... Rest>\n",
    "class Bundle {};\n",
    "template <typename T, typename... Rest>\n",
    "class Bundle<T, T*, 0, Rest...> {};\n",
    "template <typename T> using Handle = ::demo::Bundle<T, T*>;\n",
    "template <typename T> using Plain = Holder;\n",
    "}\n",
);

fn template_fixture(root: &std::path::Path) -> ProjectFile {
    let file = ProjectFile::new(root.to_path_buf(), "include/bundle.h");
    file.write(TEMPLATE_SOURCE).unwrap();
    file
}

/// Fails with the whole parsed map when the fixture stops producing one of the
/// shapes this suite exists to cover, rather than passing vacuously.
fn assert_fixture_covers_every_shape(metadata: &HashMap<CodeUnit, CppTemplateMetadata>) {
    let values = || metadata.values();
    assert!(
        values().any(|value| value
            .parameters
            .iter()
            .any(|parameter| parameter.default.is_some())),
        "no parameter default in {metadata:#?}"
    );
    assert!(
        values().any(|value| value.parameters.iter().any(|parameter| parameter.variadic)),
        "no variadic parameter in {metadata:#?}"
    );
    assert!(
        values().any(|value| !value.specialization_arguments.is_empty()),
        "no specialization arguments in {metadata:#?}"
    );
    assert!(
        values().any(
            |value| value.alias_target.as_ref().is_some_and(|alias| alias
                .arguments
                .as_ref()
                .is_some_and(|args| !args.is_empty()))
        ),
        "no alias target with arguments in {metadata:#?}"
    );
    assert!(
        values().any(|value| value
            .alias_target
            .as_ref()
            .is_some_and(|alias| alias.arguments.is_none())),
        "no alias target without an argument list in {metadata:#?}"
    );
    assert!(
        values()
            .flat_map(|value| value
                .parameters
                .iter()
                .filter_map(|parameter| parameter.default.as_ref())
                .chain(value.specialization_arguments.iter())
                .chain(
                    value
                        .alias_target
                        .iter()
                        .flat_map(|alias| alias.arguments.iter().flatten())
                ))
            .any(|expression| matches!(
                &expression.term,
                CppTemplateTerm::Node { children, .. } if !children.is_empty()
            )),
        "no compound expression term in {metadata:#?}"
    );
}

#[test]
fn persisted_cpp_class_templates_preserve_every_metadata_shape() {
    let temp = tempfile::TempDir::new().unwrap();
    let file = template_fixture(temp.path());
    let source = file.read_to_string().unwrap();
    let oid = oid_for(source.as_bytes());
    let parsed = parse_state(&CppAdapter, &file);
    assert_fixture_covers_every_shape(&parsed.cpp_template_metadata);

    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "cpp", &CppAdapter, &parsed)
        .unwrap();
    let hydrated = store
        .hydrate_file_state(oid, "cpp", &CppAdapter, &file)
        .unwrap()
        .unwrap();

    assert_eq!(
        hydrated.cpp_template_metadata, parsed.cpp_template_metadata,
        "persisted class-template metadata must hydrate unchanged"
    );
    // The same fixture through the prepared batch path and bulk hydration,
    // over the whole FileState rather than this one map.
    assert_direct_prepared_parity(&CppAdapter, "cpp", &file);
}

/// The persisted schema of a store that has done production work is the
/// baseline and nothing else. The analyzer's own workspace projections are
/// TEMP objects on each connection; a projection that lost its `TEMP` would
/// land in `main` and survive the process, which is what this pins.
#[test]
fn a_worked_store_holds_exactly_the_baseline_schema() {
    let baseline_temp = tempfile::TempDir::new().unwrap();
    let baseline_path = baseline_temp
        .path()
        .join(crate::cache_db::cache_db_file_name());
    let baseline = crate::cache_db::open_unified_connection(&baseline_path).unwrap();
    let baseline_objects = persisted_schema_objects(&baseline);
    let baseline_tables = || {
        baseline_objects
            .iter()
            .filter(|(kind, _)| kind == "table")
            .map(|(_, name)| name.as_str())
            .collect::<Vec<_>>()
    };
    for family in [
        "unit_cpp_class_templates",
        "unit_cpp_class_template_parameters",
        "unit_cpp_class_template_alias_components",
        "unit_cpp_class_template_expressions",
        "unit_cpp_class_template_terms",
    ] {
        assert!(
            baseline_tables().contains(&family),
            "the baseline must still declare {family}: {:?}",
            baseline_tables()
        );
    }

    let temp = tempfile::TempDir::new().unwrap();
    let db_path = temp.path().join("worked.db");
    let file = template_fixture(temp.path());
    let source = file.read_to_string().unwrap();
    let oid = oid_for(source.as_bytes());
    let parsed = parse_state(&CppAdapter, &file);
    {
        let store = AnalyzerStore::open_persistent(&db_path).unwrap();
        store
            .write_parsed_blob(oid, "cpp", &CppAdapter, &parsed)
            .unwrap();
        assert!(
            store
                .hydrate_file_state(oid, "cpp", &CppAdapter, &file)
                .unwrap()
                .is_some()
        );
        let conn = store.read_conn().unwrap();
        ensure_revisioned_workspace_views(&conn).unwrap();
    }

    let worked = Connection::open(&db_path).unwrap();
    assert_eq!(
        persisted_schema_objects(&worked),
        baseline_objects,
        "a worked store must persist the baseline schema and nothing else"
    );
}

/// What `CppAnalyzer::template_metadata` answers after a build is what the
/// relational families hold. The comparison runs against the metadata read
/// back out of a store rather than against the parse alone, so this is the
/// warm-versus-persisted parity the opaque payload used to get from
/// `assert_file_state_equivalent`, unit by unit and in both directions.
#[test]
fn warm_analyzer_class_template_metadata_matches_the_persisted_metadata() {
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
        .file("include/bundle.h", TEMPLATE_SOURCE)
        .build();
    let file = fixture.file("include/bundle.h");
    let parsed = parse_state(&CppAdapter, &file);
    assert_fixture_covers_every_shape(&parsed.cpp_template_metadata);

    let store = AnalyzerStore::open_ephemeral().unwrap();
    let oid = oid_for(file.read_to_string().unwrap().as_bytes());
    store
        .write_parsed_blob(oid, "cpp", &CppAdapter, &parsed)
        .unwrap();
    let persisted = store
        .hydrate_file_state(oid, "cpp", &CppAdapter, &file)
        .unwrap()
        .unwrap()
        .cpp_template_metadata;
    assert_eq!(persisted, parsed.cpp_template_metadata);

    let analyzer = crate::analyzer::cpp::CppAnalyzer::from_project(fixture.project().clone());
    for (unit, metadata) in &persisted {
        assert_eq!(
            analyzer.template_metadata(unit).as_ref(),
            Some(metadata),
            "warm metadata differs for {unit:?}"
        );
    }
    // And no other declaration acquires metadata of its own.
    for unit in &analyzer.get_all_declarations() {
        assert_eq!(
            analyzer.template_metadata(unit),
            persisted.get(unit).cloned(),
            "warm metadata differs for {unit:?}"
        );
    }
}

/// Every object the store file itself holds: tables, views, triggers and
/// indexes, without SQLite's own bookkeeping objects.
fn persisted_schema_objects(conn: &Connection) -> Vec<(String, String)> {
    conn.prepare(
        "SELECT type, name FROM main.sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
         ORDER BY type, name",
    )
    .unwrap()
    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
    .unwrap()
    .collect::<rusqlite::Result<Vec<(String, String)>>>()
    .unwrap()
}
