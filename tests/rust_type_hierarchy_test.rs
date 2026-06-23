mod common;

use brokk_bifrost::{CodeUnit, IAnalyzer, Language, RustAnalyzer, TypeHierarchyProvider};
use common::{BuiltInlineTestProject, InlineTestProject};
use std::collections::BTreeSet;

fn rust_analyzer_with_files(files: &[(&str, &str)]) -> (BuiltInlineTestProject, RustAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Rust);
    for (path, contents) in files {
        builder = builder.file(path, *contents);
    }
    let project = builder.build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn definition(analyzer: &RustAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn fq_names(units: impl IntoIterator<Item = CodeUnit>) -> BTreeSet<String> {
    units.into_iter().map(|unit| unit.fq_name()).collect()
}

#[test]
fn rust_type_hierarchy_resolves_same_file_trait_impl() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
trait Runnable {}
struct Worker;
impl Runnable for Worker {}
"#,
    )]);

    let runnable = definition(&analyzer, "Runnable");
    let worker = definition(&analyzer, "Worker");

    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&runnable)),
        BTreeSet::from(["Worker".to_string()])
    );
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        BTreeSet::from(["Runnable".to_string()])
    );
}

#[test]
fn rust_type_hierarchy_resolves_imported_trait_reference() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/contracts.rs", "pub trait Runnable {}"),
        (
            "src/worker.rs",
            r#"
use crate::contracts::Runnable;
pub struct Worker;
impl Runnable for Worker {}
"#,
        ),
    ]);

    let runnable = definition(&analyzer, "contracts.Runnable");
    let worker = definition(&analyzer, "worker.Worker");

    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        BTreeSet::from(["contracts.Runnable".to_string()])
    );
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&runnable)),
        BTreeSet::from(["worker.Worker".to_string()])
    );
}

#[test]
fn rust_type_hierarchy_resolves_aliased_imported_trait_reference() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/contracts.rs", "pub trait Runnable {}"),
        (
            "src/worker.rs",
            r#"
use crate::contracts::Runnable as Run;
pub struct Worker;
impl Run for Worker {}
"#,
        ),
    ]);

    let worker = definition(&analyzer, "worker.Worker");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        BTreeSet::from(["contracts.Runnable".to_string()])
    );
}

#[test]
fn rust_type_hierarchy_resolves_scoped_trait_reference() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/contracts.rs", "pub trait Runnable {}"),
        (
            "src/worker.rs",
            r#"
pub struct Worker;
impl crate::contracts::Runnable for Worker {}
"#,
        ),
    ]);

    let worker = definition(&analyzer, "worker.Worker");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&worker)),
        BTreeSet::from(["contracts.Runnable".to_string()])
    );
}

#[test]
fn rust_type_hierarchy_supports_enum_and_type_alias_implementers() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
trait Runnable {}
enum Job {}
struct Worker;
type WorkerAlias = Worker;
impl Runnable for Job {}
impl Runnable for WorkerAlias {}
"#,
    )]);

    let runnable = definition(&analyzer, "Runnable");
    assert_eq!(
        fq_names(analyzer.get_direct_descendants(&runnable)),
        BTreeSet::from(["Job".to_string(), "WorkerAlias".to_string()])
    );

    let alias = definition(&analyzer, "WorkerAlias");
    assert_eq!(
        fq_names(analyzer.get_direct_ancestors(&alias)),
        BTreeSet::from(["Runnable".to_string()])
    );
}

#[test]
fn rust_type_hierarchy_ignores_inherent_impls() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
trait Runnable {}
struct Worker;
impl Worker {}
"#,
    )]);

    let runnable = definition(&analyzer, "Runnable");
    let worker = definition(&analyzer, "Worker");

    assert!(analyzer.get_direct_descendants(&runnable).is_empty());
    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
}

#[test]
fn rust_type_hierarchy_ignores_unresolved_references() {
    let (_project, analyzer) = rust_analyzer_with_files(&[(
        "src/lib.rs",
        r#"
trait Runnable {}
struct Worker;
impl Missing for Worker {}
impl Runnable for MissingType {}
"#,
    )]);

    let runnable = definition(&analyzer, "Runnable");
    let worker = definition(&analyzer, "Worker");

    assert!(analyzer.get_direct_descendants(&runnable).is_empty());
    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
}

#[test]
fn rust_type_hierarchy_ignores_ambiguous_glob_trait_import() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/one.rs", "pub trait Runnable {}"),
        ("src/two.rs", "pub trait Runnable {}"),
        (
            "src/worker.rs",
            r#"
use crate::one::*;
use crate::two::*;
pub struct Worker;
impl Runnable for Worker {}
"#,
        ),
    ]);

    let worker = definition(&analyzer, "worker.Worker");
    assert!(analyzer.get_direct_ancestors(&worker).is_empty());
}

#[test]
fn rust_type_hierarchy_ignores_ambiguous_glob_implementer_import() {
    let (_project, analyzer) = rust_analyzer_with_files(&[
        ("src/contracts.rs", "pub trait Runnable {}"),
        ("src/one.rs", "pub struct Worker;"),
        ("src/two.rs", "pub struct Worker;"),
        (
            "src/impls.rs",
            r#"
use crate::contracts::Runnable;
use crate::one::*;
use crate::two::*;
impl Runnable for Worker {}
"#,
        ),
    ]);

    let runnable = definition(&analyzer, "contracts.Runnable");
    assert!(analyzer.get_direct_descendants(&runnable).is_empty());
}
