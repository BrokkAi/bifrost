//! Reusable before/after dump of one source tree's prepared resolution rows.
//!
//! Run the ignored `dump_prepared_resolution_rows` entry point with
//! BIFROST_RESOLUTION_DUMP_ROOT (an absolute, identical input tree in both runs),
//! BIFROST_RESOLUTION_DUMP_LANGUAGE, BIFROST_RESOLUTION_DUMP_INPUTS (newline
//! separated relative subtrees), and BIFROST_RESOLUTION_DUMP_OUTPUT. No expected
//! digest is checked in. Compare dumps with cmp; they include every populated family,
//! the complete-content digest, and the path bodies' $[8] precedence arrays.
//! Files are lowered and written one at a time; no artifacts survive a file.

use brokk_bifrost_analysis::analyzer::resolution::{
    BindingFragmentId, lower_resolution_facts_with_identity_catalog,
};
use brokk_bifrost_analysis::analyzer::store::resolution_prepare::{
    ResolutionInteriorPreparation, prepare_resolution_bundle_with_source_facts,
};
use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::model::ProjectFile;
use std::io::Write;
use std::path::PathBuf;

#[test]
#[ignore = "before/after developer tool; requires explicit source tree and output"]
fn dump_prepared_resolution_rows() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::var("BIFROST_RESOLUTION_DUMP_ROOT")?);
    assert!(root.is_absolute(), "dump input root must be absolute");
    let label = std::env::var("BIFROST_RESOLUTION_DUMP_LANGUAGE")?;
    let (language, extension) = match label.as_str() {
        "rust" => (Language::Rust, "rs"),
        "go" => (Language::Go, "go"),
        "java" => (Language::Java, "java"),
        "kotlin" => (Language::Kotlin, "kt"),
        "scala" => (Language::Scala, "scala"),
        "python" => (Language::Python, "py"),
        "csharp" => (Language::CSharp, "cs"),
        _ => panic!("unsupported dump language: {label}"),
    };
    let grammar = brokk_bifrost_analysis::analyzer::parser_language_for(language)
        .expect("dump language has a grammar");
    let mut paths = std::collections::BTreeSet::new();
    for input in std::env::var("BIFROST_RESOLUTION_DUMP_INPUTS")?.lines() {
        for entry in walkdir::WalkDir::new(root.join(input)) {
            let entry = entry?;
            if entry.file_type().is_file()
                && entry.path().extension().is_some_and(|ext| ext == extension)
            {
                paths.insert(entry.into_path());
            }
        }
    }
    assert!(!paths.is_empty(), "dump must exercise source files");
    let count = paths.len();
    let mut output = std::io::BufWriter::new(std::fs::File::create(std::env::var(
        "BIFROST_RESOLUTION_DUMP_OUTPUT",
    )?)?);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&grammar)?;
    let cancellation = brokk_bifrost_analysis::CancellationToken::default();
    for path in paths {
        let relative = path.strip_prefix(&root)?;
        let file = ProjectFile::new(&root, relative);
        let source = std::fs::read_to_string(&path)?;
        let tree = parser.parse(&source, None).expect("uncancelled parse");
        let parsed = match language {
            Language::Rust => {
                brokk_bifrost_rust::declarations::parse_rust_file(&file, &source, &tree)
            }
            Language::Go => brokk_bifrost_go::declarations::parse_go_file(&file, &source, &tree),
            Language::Java => {
                brokk_bifrost_jvm::java::declarations::parse_java_file(&file, &source, &tree)
            }
            Language::Kotlin => {
                brokk_bifrost_jvm::kotlin::declarations::parse_kotlin_file(&file, &source, &tree)
            }
            Language::Scala => {
                brokk_bifrost_jvm::scala::declarations::parse_scala_file(&file, &source, &tree)
            }
            Language::CSharp => {
                brokk_bifrost_csharp::declarations::parse_csharp_file_with_native_facts(
                    &file, &source, &tree,
                )
            }
            Language::Python => {
                brokk_bifrost_python::declarations::parse_python_file_with_native_facts(
                    &brokk_bifrost_core::analyzer::project::TestProject::new(&root, language),
                    &file,
                    &source,
                    &tree,
                )
            }
            _ => unreachable!("language selected above"),
        };
        let relative = relative.to_string_lossy().replace('\\', "/");
        writeln!(output, "file {relative}")?;
        let lowered = lower_resolution_facts_with_identity_catalog(
            BindingFragmentId::for_test(relative.as_bytes()),
            language,
            &parsed.resolution_facts,
        );
        let unit_keys = parsed
            .declarations()
            .iter()
            .enumerate()
            .map(|(index, unit)| {
                (
                    unit.clone(),
                    i64::try_from(index).expect("file unit count fits i64"),
                )
            })
            .collect();
        let ResolutionInteriorPreparation::Prepared(bundle) =
            prepare_resolution_bundle_with_source_facts(
                &lowered,
                &unit_keys,
                parsed.source_facts.as_ref(),
                Some(&source),
                &cancellation,
            )?
        else {
            panic!("uncancelled preparation completes")
        };
        bundle.write_prepared_rows(&mut output)?;
    }
    output.flush()?;
    eprintln!("dumped {count} {label} files");
    Ok(())
}
