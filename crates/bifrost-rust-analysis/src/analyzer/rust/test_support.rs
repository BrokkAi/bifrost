use crate::analyzer::rust::RustAnalyzer;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use rustdoc_types::{Id, Item, ItemEnum, Visibility};

#[track_caller]
pub(crate) fn project<R: AsRef<str>, C: AsRef<str>>(
    files: &[(R, C)],
) -> (tempfile::TempDir, RustAnalyzer) {
    let (temp, analyzer) = lazy_project(files);
    let _ = analyzer.get_analyzed_files();
    (temp, analyzer)
}

#[track_caller]
pub(crate) fn lazy_project<R: AsRef<str>, C: AsRef<str>>(
    files: &[(R, C)],
) -> (tempfile::TempDir, RustAnalyzer) {
    let mut builder = crate::inline_project::InlineTestProject::with_language(Language::Rust);
    for (relative_path, body) in files {
        builder = builder.file(relative_path.as_ref(), body.as_ref());
    }
    let fixture = builder.build();
    let analyzer = RustAnalyzer::from_project(fixture.project().clone());
    let temp = fixture.into_temp_dir();
    (temp, analyzer)
}

#[track_caller]
pub(crate) fn inline_source_project(
    package_name: &str,
    source: &str,
) -> (crate::inline_project::BuiltInlineTestProject, RustAnalyzer) {
    let manifest =
        format!("[package]\nname = \"{package_name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n");
    let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
        .file("Cargo.toml", manifest)
        .file("src/lib.rs", source)
        .build();
    let analyzer = RustAnalyzer::new(fixture.project_dyn());
    (fixture, analyzer)
}

/// A Rust analyzer over the directory `root` whose source listing is certified.
///
/// Uses the production filesystem project's listing and snapshot build path.
#[track_caller]
pub(crate) fn certified_analyzer(
    root: &std::path::Path,
) -> (
    brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
    RustAnalyzer,
) {
    certified_analyzer_with_config(
        root,
        brokk_bifrost_core::analyzer::config::AnalyzerConfig::default(),
    )
}

#[track_caller]
pub(crate) fn certified_analyzer_with_config(
    root: &std::path::Path,
    config: brokk_bifrost_core::analyzer::config::AnalyzerConfig,
) -> (
    brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
    RustAnalyzer,
) {
    let budget = brokk_bifrost_core::retention_budget::RetentionBudget::for_test_capacity(
        config.retention_budget_bytes(),
    );
    let workspace =
        brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::build_ephemeral_footgun_with_budget(
            crate::inline_project::certified_project_at(root),
            config,
            &budget,
        )
        .expect("certified fixture workspace builds");
    let analyzer =
        brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<RustAnalyzer>(
            workspace.analyzer(),
        )
        .expect("workspace contains the Rust analyzer")
        .clone();
    (workspace, analyzer)
}

/// A temporary directory of fixture files and the workspace that certified its
/// listing. The analyzer cloned from the workspace is valid while this lives.
pub(crate) struct CertifiedFixture {
    _temp: tempfile::TempDir,
    _workspace: brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer,
}

/// [`project`] with a certified listing, so route answers are complete.
#[track_caller]
pub(crate) fn certified_project<R: AsRef<str>, C: AsRef<str>>(
    files: &[(R, C)],
) -> (CertifiedFixture, RustAnalyzer) {
    let (temp, _uncertified) = lazy_project(files);
    let (workspace, analyzer) = certified_analyzer(temp.path());
    let _ = analyzer.get_analyzed_files();
    (
        CertifiedFixture {
            _temp: temp,
            _workspace: workspace,
        },
        analyzer,
    )
}

pub(crate) fn analyzed_file(analyzer: &RustAnalyzer, suffix: &str) -> ProjectFile {
    analyzer
        .get_analyzed_files()
        .into_iter()
        .find(|file| file.rel_path().ends_with(suffix))
        .unwrap_or_else(|| panic!("{suffix} is analyzed"))
}

pub(crate) fn bounded_receiver_query<'a>(
    analyzer: &'a RustAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    tree: Option<&'a tree_sitter::Tree>,
    site: &'a ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&'a CancellationToken>,
) -> BoundedReceiverQuery<'a> {
    BoundedReceiverQuery {
        analyzer,
        file,
        source,
        tree,
        site,
        budget,
        cancellation,
    }
}

pub(crate) fn rustdoc_item(
    id: u32,
    name: Option<&str>,
    visibility: Visibility,
    inner: ItemEnum,
) -> Item {
    Item {
        id: Id(id),
        crate_id: 0,
        name: name.map(str::to_owned),
        span: None,
        visibility,
        docs: None,
        links: std::collections::HashMap::new(),
        attrs: Vec::new(),
        deprecation: None,
        stability: None,
        const_stability: None,
        inner,
    }
}

// Inject the stopped provider answer at the demand boundary, while retaining
// the real selection, Main bridge and deferred completion machinery (#12928).
thread_local! {
    pub(super) static LOCAL_GLOB_DEMAND_FAULT: std::cell::RefCell<Option<Result<(), brokk_bifrost_analysis::analyzer::store::StoreError>>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn with_local_glob_demand_fault<T>(
    fault: Result<(), brokk_bifrost_analysis::analyzer::store::StoreError>,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            LOCAL_GLOB_DEMAND_FAULT.with(|slot| {
                slot.take();
            });
        }
    }
    LOCAL_GLOB_DEMAND_FAULT.with(|slot| {
        assert!(slot.replace(Some(fault)).is_none());
    });
    let _reset = Reset;
    run()
}
