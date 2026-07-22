mod common;

use brokk_bifrost::reference_differential::{
    ReferenceClassification, ReferenceDifferentialConfig, run_reference_differential,
};
use brokk_bifrost::{AnalyzerConfig, Language};
use common::InlineTestProject;

fn rust_differential(
    files: &[(&str, &str)],
) -> brokk_bifrost::reference_differential::ReferenceDifferentialReport {
    let mut project = InlineTestProject::with_language(Language::Rust);
    for (path, source) in files {
        project = project.file(path, *source);
    }
    let project = project.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    run_reference_differential(
        workspace.analyzer(),
        &ReferenceDifferentialConfig {
            corpus_language: "rust".to_string(),
            max_files: 20,
            max_sites: 1_000,
            max_candidates_per_file: 1_000,
            max_source_bytes: 100_000,
            max_targets: 1_000,
            max_usage_files: 20,
            max_usages: 1_000,
            ..ReferenceDifferentialConfig::default()
        },
    )
    .expect("run inline Rust reference differential")
}

#[test]
fn typescript_export_alias_is_excluded_as_a_declaration_site() {
    let source = r#"const createListItem = () => {};
const createListItemWithValidation = () => {};
export { createListItemWithValidation as createListItem };
"#;
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("index.ts", source)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let report = run_reference_differential(
        workspace.analyzer(),
        &ReferenceDifferentialConfig {
            corpus_language: "ts".to_string(),
            max_files: 10,
            max_sites: 100,
            max_candidates_per_file: 100,
            max_source_bytes: 10_000,
            max_targets: 100,
            max_usage_files: 10,
            max_usages: 100,
            ..ReferenceDifferentialConfig::default()
        },
    )
    .expect("run one-file TypeScript reference differential");

    let export_line = "export { createListItemWithValidation as createListItem };";
    let export_start = source.find(export_line).expect("export statement");
    let value_start = export_start
        + export_line
            .find("createListItemWithValidation")
            .expect("export value");
    let alias_start =
        export_start + export_line.find("as createListItem").expect("export alias") + "as ".len();

    assert!(
        report
            .sites
            .iter()
            .all(|site| site.start_byte != alias_start),
        "the exported alias is a declaration name, not a reference site: {report:#?}"
    );
    let export_value = report
        .sites
        .iter()
        .find(|site| site.start_byte == value_start)
        .expect("export value remains a sampled reference site");
    assert_eq!(export_value.forward_status, "resolved", "{export_value:#?}");
    assert_eq!(
        export_value.classification,
        ReferenceClassification::EditorOnly,
        "export bindings remain visible to editor navigation: {export_value:#?}"
    );
    assert_eq!(report.summary.classifications.missing, 0, "{report:#?}");
}

#[test]
fn rust_nested_cargo_private_import_round_trips_to_its_physical_crate() {
    let consumer = r#"use crate::fs::asyncify;

pub async fn canonicalize() {
    asyncify(|| ()).await;
}
"#;
    let decoy = r#"mod fs {
    pub(crate) async fn asyncify<F, T>(f: F) -> T
    where
        F: FnOnce() -> T,
    {
        f()
    }
}

async fn unrelated_binary() {
    fs::asyncify(|| ()).await;
}
"#;
    let report = rust_differential(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/demo\"]\nresolver = \"2\"\n",
        ),
        (
            "crates/demo/Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        ),
        (
            "crates/demo/src/lib.rs",
            "macro_rules! cfg_fs { ($($item:item)*) => { $($item)* }; }\ncfg_fs! { pub mod fs; }\n",
        ),
        (
            "crates/demo/src/fs/mod.rs",
            "mod canonicalize;\npub(crate) async fn asyncify<F, T>(f: F) -> T where F: FnOnce() -> T { f() }\n",
        ),
        ("crates/demo/src/fs/canonicalize.rs", consumer),
        ("crates/demo/src/main.rs", decoy),
    ]);
    let start = consumer
        .find("asyncify(|| ())")
        .expect("imported asyncify call");
    let site = report
        .sites
        .iter()
        .find(|site| site.path == "crates/demo/src/fs/canonicalize.rs" && site.start_byte == start)
        .expect("imported asyncify reference site");

    assert_eq!(site.forward_status, "resolved", "{site:#?}");
    assert_eq!(
        site.targets
            .iter()
            .map(|target| target.path.as_str())
            .collect::<Vec<_>>(),
        ["crates/demo/src/fs/mod.rs"],
        "the binary-root decoy must remain unrelated: {site:#?}"
    );
    assert_eq!(
        site.classification,
        ReferenceClassification::Consistent,
        "{site:#?}"
    );
    assert!(
        site.inverse_hit.as_ref().is_some_and(|hit| {
            hit.path == "crates/demo/src/fs/canonicalize.rs"
                && hit.start_byte == start
                && hit.end_byte == start + "asyncify".len()
                && hit.exact_range
        }),
        "{site:#?}"
    );
}

#[test]
fn rust_same_file_enum_tuple_pattern_round_trips_owner_and_variant_exactly() {
    let source = r#"pub enum NodeValue {
    Document,
    Item(usize),
}

pub enum OtherValue {
    Item(usize),
}

impl<T> crate::arena_tree::Node<T> {
    pub fn accepts(&self, child: &NodeValue, other: &OtherValue) -> bool {
        let accepted = match *child {
            NodeValue::Document | NodeValue::Item(..) => matches!(*child, NodeValue::Item(..)),
        };
        accepted && matches!(*other, OtherValue::Item(..))
    }
}

"#;
    let report = rust_differential(&[
        (
            "Cargo.toml",
            "[package]\nname = \"enum-demo\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub mod arena_tree;\npub mod nodes;\n"),
        ("src/arena_tree.rs", "pub struct Node<T>(pub T);\n"),
        ("src/nodes.rs", source),
        (
            "examples/consumer.rs",
            "use enum_demo::nodes::NodeValue;\nfn consume(value: NodeValue) { let _ = NodeValue::Item(1); }\n",
        ),
    ]);
    let expression = "NodeValue::Item(..)";
    let owner_start = source.find(expression).expect("NodeValue tuple pattern");
    let variant_start = owner_start + "NodeValue::".len();

    for (start, end, target) in [
        (
            owner_start,
            owner_start + "NodeValue".len(),
            "nodes.NodeValue",
        ),
        (
            variant_start,
            variant_start + "Item".len(),
            "nodes.NodeValue.Item",
        ),
    ] {
        let site = report
            .sites
            .iter()
            .find(|site| site.path == "src/nodes.rs" && site.start_byte == start)
            .expect("enum tuple-pattern reference site");
        assert_eq!(site.forward_status, "resolved", "{site:#?}");
        assert_eq!(
            site.targets
                .iter()
                .map(|target| target.fq_name.as_str())
                .collect::<Vec<_>>(),
            [target],
            "the same-named OtherValue variant must not cross-resolve: {site:#?}"
        );
        assert_eq!(
            site.classification,
            ReferenceClassification::Consistent,
            "{site:#?}"
        );
        assert!(
            site.inverse_hit.as_ref().is_some_and(|hit| {
                hit.path == "src/nodes.rs"
                    && hit.start_byte == start
                    && hit.end_byte == end
                    && hit.exact_range
            }),
            "{site:#?}"
        );
    }
}

#[test]
fn rust_compositional_passthrough_wrapper_round_trips_physical_module() {
    let root = r#"
macro_rules! direct_items {
    ($($item:item)*) => { $($item)* };
}
macro_rules! unix_items {
    ($($item:item)*) => {
        #[cfg(unix)]
        direct_items! { $($item)* }
    };
}
unix_items! { pub mod process; }
pub mod signal;

macro_rules! opaque_items {
    ($($item:item)*) => { unresolved_wrapper! { $($item)* } };
}
opaque_items! { pub mod decoy; }

pub fn invalid(_: decoy::Decoy) {}
"#;
    let process = r#"use crate::signal::Handle as SignalHandle;
pub fn park(_: SignalHandle) {}
"#;
    let report = rust_differential(&[
        (
            "Cargo.toml",
            "[package]\nname = \"nested-wrapper\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", root),
        ("src/process.rs", process),
        ("src/signal.rs", "pub struct Handle;\n"),
        ("src/decoy.rs", "pub struct Decoy;\n"),
    ]);

    let handle_start = process.rfind("SignalHandle").expect("signal handle type");
    let handle = report
        .sites
        .iter()
        .find(|site| site.path == "src/process.rs" && site.start_byte == handle_start)
        .expect("reference within the generated process module");
    assert_eq!(handle.forward_status, "resolved", "{handle:#?}");
    assert_eq!(
        handle
            .targets
            .iter()
            .map(|target| (target.path.as_str(), target.fq_name.as_str()))
            .collect::<Vec<_>>(),
        [("src/signal.rs", "signal.Handle")],
        "the compositional wrapper must retain the physical source route: {handle:#?}"
    );
    assert_eq!(
        handle.classification,
        ReferenceClassification::Consistent,
        "{handle:#?}"
    );
    assert!(
        handle.inverse_hit.as_ref().is_some_and(|hit| {
            hit.path == "src/process.rs"
                && hit.start_byte == handle_start
                && hit.end_byte == handle_start + "SignalHandle".len()
                && hit.exact_range
        }),
        "{handle:#?}"
    );

    let decoy_start = root.find("decoy::Decoy").expect("decoy type") + "decoy::".len();
    let decoy = report
        .sites
        .iter()
        .find(|site| site.path == "src/lib.rs" && site.start_byte == decoy_start)
        .expect("opaque nested-wrapper reference site");
    assert_eq!(
        decoy.classification,
        ReferenceClassification::Missing,
        "the forward index may see the same-named file, but an unproven wrapper must not give it a physical inverse route: {decoy:#?}"
    );
    assert!(decoy.inverse_hit.is_none(), "{decoy:#?}");
}
