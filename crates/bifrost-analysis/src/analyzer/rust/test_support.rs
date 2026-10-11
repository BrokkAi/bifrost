use super::RustAnalyzer;
use crate::CancellationToken;
use crate::analyzer::languages::BoundedReceiverQuery;
use crate::analyzer::usages::get_definition::ResolvedReferenceSite;
use crate::analyzer::{CodeUnitIndex, Language, ProjectFile, TestProject};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use rustdoc_types::{Id, Item, ItemEnum, Visibility};

pub(super) fn project<R: AsRef<str>, C: AsRef<str>>(
    files: &[(R, C)],
) -> (tempfile::TempDir, RustAnalyzer) {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical root");
    for (relative_path, body) in files {
        ProjectFile::new(root.clone(), relative_path.as_ref())
            .write(body.as_ref())
            .expect("write fixture file");
    }
    let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
    let _ = analyzer.get_analyzed_files();
    (temp, analyzer)
}

pub(super) fn analyzed_file(analyzer: &RustAnalyzer, suffix: &str) -> ProjectFile {
    analyzer
        .get_analyzed_files()
        .into_iter()
        .find(|file| file.rel_path().ends_with(suffix))
        .unwrap_or_else(|| panic!("{suffix} is analyzed"))
}

pub(super) fn bounded_receiver_query<'a>(
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

pub(super) fn rustdoc_item(
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
