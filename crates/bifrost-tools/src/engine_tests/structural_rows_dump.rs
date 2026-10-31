//! Stored structural facts receipt over a frozen source tree.
//!
//! Run `dump_stored_structural_rows --ignored` with BIFROST_STRUCTURAL_DUMP_ROOT
//! (absolute), BIFROST_STRUCTURAL_DUMP_LANGUAGE (any Language config label),
//! BIFROST_STRUCTURAL_DUMP_INPUTS (newline-separated relative subtrees), and
//! BIFROST_STRUCTURAL_DUMP_OUTPUT. The output contains JSON-decoded array
//! elements and recovered regions. Siblings `.raw` and `.headers` contain exact
//! JSONB hex and manifests/epochs respectively. All rows are keyed by relative
//! path and content OID; database-local blob IDs are replaced by that key.
//! Each file is parsed and published through the real store writer before SQL
//! reads its rows. Source-admission refusals have an explicit header and no
//! stored rows. No expected digest is checked in; compare receipts externally.

use brokk_bifrost_analysis::analyzer::store::test_support::file_state_from_source;
use brokk_bifrost_analysis::analyzer::store::{AnalyzerStore, test_blob_oid};
use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
use brokk_bifrost_analysis::analyzer::{Language, LanguageAdapter, ProjectFile};
use std::io::Write;
use std::path::PathBuf;

type DumpResult<T> = Result<T, Box<dyn std::error::Error>>;

fn publish<A: LanguageAdapter>(
    store: &AnalyzerStore,
    file: &ProjectFile,
    adapter: &A,
) -> DumpResult<Option<String>> {
    let generation = store.ensure_language_epoch(adapter.language(), &adapter.parser_language())?;
    let source = file.read_to_string()?;
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&adapter.parser_language_for_file(file))?;
    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{
        BoundedParse, COMPLETE_FILE_PARSE_BUDGET, parse_admitted_source_with_policy,
    };
    match parse_admitted_source_with_policy(
        &mut parser,
        adapter,
        &source,
        None,
        std::time::Instant::now() + COMPLETE_FILE_PARSE_BUDGET,
        brokk_bifrost_analysis::analyzer::source_admission::SourceAdmissionPolicy::current(),
    ) {
        BoundedParse::Complete(_) => {}
        BoundedParse::Refused(reason) => return Ok(Some(format!("{reason:?}"))),
        BoundedParse::TimedOut => {
            return Err(std::io::Error::other("source admission timed out").into());
        }
        BoundedParse::Rejected => {
            return Err(std::io::Error::other("parser rejected source").into());
        }
        BoundedParse::Cancelled => unreachable!("no cancellation token supplied"),
    }
    let state = file_state_from_source(adapter, file, &source);
    store.write_parsed_blob_at_generation(
        file,
        &brokk_bifrost_core::gitblob::BlobKey::unvaried(
            test_blob_oid(state.source.as_bytes()),
            adapter.language().config_label(),
        ),
        generation,
        adapter,
        &state,
    )?;
    Ok(None)
}

#[test]
#[ignore = "before/after developer tool; requires explicit source tree and output"]
fn dump_stored_structural_rows() -> DumpResult<()> {
    let root = PathBuf::from(std::env::var("BIFROST_STRUCTURAL_DUMP_ROOT")?);
    assert!(root.is_absolute(), "dump input root must be absolute");
    let label = std::env::var("BIFROST_STRUCTURAL_DUMP_LANGUAGE")?;
    let language = Language::from_config_label(&label).expect("analyzable dump language");
    let mut paths = std::collections::BTreeSet::new();
    for input in std::env::var("BIFROST_STRUCTURAL_DUMP_INPUTS")?.lines() {
        let input = std::path::Path::new(input);
        assert!(
            input.is_relative()
                && !input
                    .components()
                    .any(|part| part == std::path::Component::ParentDir)
        );
        for entry in walkdir::WalkDir::new(root.join(input)) {
            let entry = entry?;
            if entry.file_type().is_file() && Language::from_path(entry.path()) == language {
                paths.insert(entry.into_path());
            }
        }
    }
    assert!(!paths.is_empty(), "dump must exercise source files");
    let output_path = std::env::var("BIFROST_STRUCTURAL_DUMP_OUTPUT")?;
    let mut output = std::io::BufWriter::new(std::fs::File::create(&output_path)?);
    let mut raw = std::io::BufWriter::new(std::fs::File::create(format!("{output_path}.raw"))?);
    let mut headers =
        std::io::BufWriter::new(std::fs::File::create(format!("{output_path}.headers"))?);
    let store = AnalyzerStore::open_ephemeral()?;
    let mut rows = 0usize;
    let mut refused = 0usize;
    for path in &paths {
        let file = ProjectFile::new(&root, path.strip_prefix(&root)?);
        eprintln!("publishing {}", path.display());
        let refusal = match language {
            Language::Java => publish(&store, &file, &brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter)?,
            Language::Kotlin => publish(&store, &file, &brokk_bifrost_jvm_analysis::analyzer::kotlin::adapter::KotlinAdapter)?,
            Language::Scala => publish(&store, &file, &brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter)?,
            Language::Go => publish(&store, &file, &brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter)?,
            Language::Rust => publish(&store, &file, &brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter)?,
            Language::Cpp => publish(&store, &file, &brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter)?,
            Language::Php => publish(&store, &file, &brokk_bifrost_php_analysis::analyzer::php::adapter::PhpAdapter)?,
            Language::Ruby => publish(&store, &file, &brokk_bifrost_ruby_analysis::analyzer::ruby::adapter::RubyAdapter)?,
            Language::CSharp => publish(&store, &file, &brokk_bifrost_csharp_analysis::analyzer::csharp::adapter::CSharpAdapter)?,
            Language::Python => publish(&store, &file, &brokk_bifrost_python_analysis::analyzer::python::adapter::PythonAdapter::for_test_file(&file))?,
            Language::JavaScript => publish(&store, &file, &brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter)?,
            Language::TypeScript => publish(&store, &file, &brokk_bifrost_js_ts_analysis::analyzer::typescript::TypescriptAdapter)?,
            Language::None => unreachable!("analyzable language"),
        };
        let oid = test_blob_oid(&std::fs::read(path)?).to_string();
        let relative = path
            .strip_prefix(&root)?
            .to_string_lossy()
            .replace('\\', "/");
        let key = serde_json::to_string(&(relative, &oid))?;
        if let Some(reason) = refusal {
            writeln!(headers, "{key} refused {reason}")?;
            refused += 1;
            continue;
        }
        let conn = store.read_conn()?;
        let blob: i64 = conn.query_row(
            "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
            rusqlite::params![oid, language.config_label()],
            |row| row.get(0),
        )?;
        let epoch: String = conn.query_row(
            "SELECT epoch FROM analysis_epochs WHERE lang = ?1",
            [language.config_label()],
            |row| row.get(0),
        )?;
        writeln!(headers, "{key} epoch {epoch}")?;
        let mut manifest =
            conn.prepare("SELECT * FROM source_fact_manifests WHERE blob_id = ?1")?;
        let names: Vec<String> = manifest
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect();
        let values = manifest.query_row([blob], |row| {
            (1..names.len())
                .map(|index| {
                    Ok(match row.get_ref(index)? {
                        rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                        rusqlite::types::ValueRef::Integer(value) => value.into(),
                        rusqlite::types::ValueRef::Text(value) => {
                            String::from_utf8_lossy(value).into_owned().into()
                        }
                        value => panic!("unexpected manifest scalar {value:?}"),
                    })
                })
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
        for (name, value) in names.iter().skip(1).zip(values) {
            writeln!(headers, "{key} manifest {name} {value}")?;
        }
        for column in ["nodes", "roles", "occurrence_roles"] {
            let hex: String = conn.query_row(
                &format!("SELECT hex({column}) FROM source_structural_facts WHERE blob_id = ?1"),
                [blob],
                |row| row.get(0),
            )?;
            writeln!(raw, "{key} {column} {hex}")?;
            let mut elements = conn.prepare(&format!("SELECT key, json(value) FROM source_structural_facts, json_each({column}) WHERE blob_id = ?1 ORDER BY CAST(key AS INTEGER)"))?;
            for element in elements.query_map([blob], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })? {
                let (index, value) = element?;
                // Occurrence arrays already carry node IDs; insertion must not
                // make every following occurrence appear changed in a diff.
                if column == "occurrence_roles" {
                    writeln!(output, "{key} {column} {value}")?;
                } else {
                    writeln!(output, "{key} {column} {index} {value}")?;
                }
                rows += 1;
            }
        }
        let mut regions = conn.prepare("SELECT ordinal, start_byte, end_byte FROM source_structural_recovered_regions WHERE blob_id = ?1 ORDER BY ordinal")?;
        for region in regions.query_map([blob], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })? {
            writeln!(output, "{key} recovered {:?}", region?)?;
            rows += 1;
        }
    }
    output.flush()?;
    raw.flush()?;
    headers.flush()?;
    eprintln!(
        "dumped {} {} files ({refused} refused), {rows} element/region rows",
        paths.len(),
        language.config_label()
    );
    Ok(())
}
