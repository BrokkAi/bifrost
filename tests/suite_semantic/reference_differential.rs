use crate::common::{InlineTestProject, call_search_tool_json};
use brokk_bifrost::reference_differential::{
    ExactReferenceSite, ProbeSeed, ReferenceClassification, ReferenceDifferentialConfig,
    run_reference_differential,
};
use brokk_bifrost::{AnalyzerConfig, Language};
use serde_json::json;

fn rust_census_differential(
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
            probe_seed: ProbeSeed::Census,
            ..ReferenceDifferentialConfig::default()
        },
    )
    .expect("run inline Rust census differential")
}

/// The census seed proposes an identifier occurrence inside a `macro_rules!`
/// body -- joint-blindness territory the analyzer's index-filtered frontier
/// never surfaces -- and every census site is tagged `seed == "census"`. This
/// is the core M1 capability: probe sites the index seed cannot reach.
#[test]
fn census_seed_proposes_macro_body_occurrence_the_index_seed_excludes() {
    let source = "macro_rules! call_it { () => { frobnicate() }; }\nfn frobnicate() {}\nfn run() { call_it!(); }\n";
    let census = rust_census_differential(&[("src/lib.rs", source)]);
    assert!(
        census.sites.iter().all(|site| site.seed == "census"),
        "every census site must be tagged census: {:#?}",
        census
            .sites
            .iter()
            .map(|s| (&s.text, &s.seed))
            .collect::<Vec<_>>()
    );
    let macro_body_start = source.find("frobnicate()").expect("macro body call");
    assert!(
        census
            .sites
            .iter()
            .any(|site| site.text == "frobnicate" && site.start_byte == macro_body_start),
        "census must propose the macro-body `frobnicate` occurrence: {:#?}",
        census
            .sites
            .iter()
            .map(|s| (&s.text, s.start_byte))
            .collect::<Vec<_>>()
    );
    // The census is a superset of the index frontier at the engine level: it
    // samples at least as many sites because it drops the per-language
    // reference exclusions the index seed applies.
    let index = rust_differential(&[("src/lib.rs", source)]);
    assert!(
        census.summary.sampled_sites >= index.summary.sampled_sites,
        "census sampled {} sites, index sampled {}; census must be a superset",
        census.summary.sampled_sites,
        index.summary.sampled_sites,
    );
    assert!(
        index.sites.iter().all(|site| site.seed == "index"),
        "index-seed sites must be tagged index"
    );
}

/// A forward-unresolvable census occurrence whose name has no same-file
/// declaration stays tier 3 (exploration-grade), never a missing finding, so
/// healthy code does not fabricate gaps.
#[test]
fn census_seed_stays_silent_without_a_same_file_declaration() {
    let source = "macro_rules! call_it { () => { frobnicate() }; }\nfn run() { call_it!(); }\n";
    let census = rust_census_differential(&[("src/lib.rs", source)]);
    let false_gap = census.sites.iter().find(|site| {
        site.text == "frobnicate" && site.classification == ReferenceClassification::Missing
    });
    assert!(
        false_gap.is_none(),
        "no same-file declaration must mean no census gap finding: {:#?}",
        census
            .sites
            .iter()
            .map(|s| (&s.text, &s.forward_status, s.tier, s.classification))
            .collect::<Vec<_>>()
    );
}

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

fn cpp_differential(
    files: &[(&str, &str)],
) -> brokk_bifrost::reference_differential::ReferenceDifferentialReport {
    let mut project = InlineTestProject::with_language(Language::Cpp);
    for (path, source) in files {
        project = project.file(path, *source);
    }
    let project = project.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    run_reference_differential(
        workspace.analyzer(),
        &ReferenceDifferentialConfig {
            corpus_language: "cpp".to_string(),
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
    .expect("run inline C++ reference differential")
}

fn go_differential(
    files: &[(&str, &str)],
) -> brokk_bifrost::reference_differential::ReferenceDifferentialReport {
    let mut project = InlineTestProject::with_language(Language::Go);
    for (path, source) in files {
        project = project.file(path, *source);
    }
    let project = project.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    run_reference_differential(
        workspace.analyzer(),
        &ReferenceDifferentialConfig {
            corpus_language: "go".to_string(),
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
    .expect("run inline Go reference differential")
}

fn scala_exact_site_differential(
    files: &[(&str, &str)],
    path: &str,
    start_byte: usize,
    end_byte: usize,
) -> brokk_bifrost::reference_differential::ReferenceDifferentialReport {
    let mut project = InlineTestProject::with_language(Language::Scala);
    for (file_path, source) in files {
        project = project.file(file_path, *source);
    }
    let project = project.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    run_reference_differential(
        workspace.analyzer(),
        &ReferenceDifferentialConfig {
            corpus_language: "scala".to_string(),
            max_files: 20,
            max_sites: 1_000,
            max_candidates_per_file: 1_000,
            max_source_bytes: 100_000,
            max_targets: 1_000,
            max_usage_files: 20,
            max_usages: 1_000,
            exact_site: Some(ExactReferenceSite {
                path: path.to_string(),
                start_byte,
                end_byte: Some(end_byte),
            }),
            ..ReferenceDifferentialConfig::default()
        },
    )
    .expect("run inline Scala exact-site reference differential")
}

fn lookup_by_location(
    root: &std::path::Path,
    path: &str,
    source: &str,
    start: usize,
) -> serde_json::Value {
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    call_search_tool_json(
        root,
        "get_definitions_by_location",
        &json!({"references": [{"path": path, "line": line, "column": column}]}).to_string(),
    )
}

#[test]
fn cpp_inherited_scoped_enum_qualifier_round_trips_to_lexical_owner() {
    let source = r#"
struct Client {
    enum class Failure { error, timeout };
};
struct RemoteStorage {
    struct Backend {
        enum class Failure { error, timeout };
    };
};
struct HelperBackend : RemoteStorage::Backend {
    Failure choose(Client::Failure input) {
        return input == Client::Failure::timeout ? Failure::timeout : Failure::error;
    }
};
"#;
    let report = cpp_differential(&[("failure.cpp", source)]);
    let site = report
        .sites
        .iter()
        .find(|site| {
            site.text == "Failure::timeout" && site.source_evidence.contains("? Failure::timeout")
        })
        .expect("inherited scoped-enum differential site");

    assert_eq!(site.forward_status, "resolved", "{site:#?}");
    assert_eq!(
        site.targets.first().map(|target| target.fq_name.as_str()),
        Some("RemoteStorage$Backend$Failure"),
        "{site:#?}"
    );
    assert_ne!(
        site.classification,
        ReferenceClassification::Missing,
        "{site:#?}"
    );
}

#[test]
fn cpp_recovered_export_class_typedef_does_not_hijack_base_qualifier() {
    let source = r#"
namespace spi {
class Filter {
public:
    enum FilterDecision { DENY, NEUTRAL, ACCEPT };
};
}
namespace decoy {
class Filter {
public:
    enum FilterDecision { ACCEPT };
};
}
namespace filter {
class LOG4CXX_EXPORT LevelRangeFilter : public spi::Filter
{
public:
    typedef spi::Filter BASE_CLASS;
    DECLARE_LOG4CXX_OBJECT(LevelRangeFilter)
    BEGIN_LOG4CXX_CAST_MAP()
    LOG4CXX_CAST_ENTRY(LevelRangeFilter)
    LOG4CXX_CAST_ENTRY_CHAIN(BASE_CLASS)
    END_LOG4CXX_CAST_MAP()
    FilterDecision decide() const;
};
}
using namespace filter;
using namespace spi;
using namespace decoy;
Filter::FilterDecision LevelRangeFilter::decide() const {
    return Filter::ACCEPT;
}
"#;
    let report = cpp_differential(&[("filter.cpp", source)]);
    let expression = "return Filter::ACCEPT";
    let owner_start = source.find(expression).expect("qualified base constant") + "return ".len();
    let site = report
        .sites
        .iter()
        .find(|site| site.start_byte == owner_start)
        .expect("base qualifier differential site");

    assert_eq!(site.forward_status, "resolved", "{site:#?}");
    assert_eq!(
        site.targets.first().map(|target| target.fq_name.as_str()),
        Some("spi.Filter"),
        "the recovered typedef must not publish its underlying type as a false nested alias: {site:#?}"
    );
    assert_eq!(
        site.classification,
        ReferenceClassification::Consistent,
        "{site:#?}"
    );
    assert!(
        site.inverse_hit.as_ref().is_some_and(|hit| {
            hit.path == "filter.cpp"
                && hit.start_byte == owner_start
                && hit.end_byte == owner_start + "Filter".len()
                && hit.exact_range
        }),
        "the inherited base owner must round-trip at the exact qualifier token: {site:#?}"
    );
}

#[test]
fn cpp_forward_definition_keeps_visible_declaration_route_for_inverse_lookup() {
    let consumer = r#"#pragma once
#define API_EXPORT
namespace demo {
class Widget;
class API_EXPORT Node {
public:
    Node* clone(Widget* target) const;
};
}
"#;
    let report = cpp_differential(&[
        ("aaa_helpers.h", "namespace demo { class Widget; }\n"),
        ("node.h", consumer),
        ("consumer.cc", "#include \"node.h\"\n"),
    ]);
    let start = consumer
        .find("Widget* target")
        .expect("parameter type reference");
    let site = report
        .sites
        .iter()
        .find(|site| site.path == "node.h" && site.start_byte == start)
        .unwrap_or_else(|| panic!("parameter type site: {:#?}", report.sites));

    assert_eq!(site.forward_status, "resolved", "{site:#?}");
    assert!(
        site.targets.iter().any(|target| target.path == "node.h"),
        "forward lookup must retain the physically visible declaration route: {site:#?}"
    );
    assert_eq!(
        site.classification,
        ReferenceClassification::Consistent,
        "a visible forward declaration must keep the inverse route to the parameter type: {site:#?}"
    );
    assert!(
        site.inverse_hit.as_ref().is_some_and(|hit| {
            hit.path == "node.h"
                && hit.start_byte == start
                && hit.end_byte == start + "Widget".len()
                && hit.exact_range
        }),
        "{site:#?}"
    );
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
fn go_package_and_import_declaration_names_are_excluded_as_declaration_sites() {
    let source = r#"package main

import sub "example.com/app/sub"

func Run() {
    sub.Helper()
}
"#;
    let report = go_differential(&[
        ("go.mod", "module example.com/app\n"),
        ("main.go", source),
        ("sub/sub.go", "package sub\n\nfunc Helper() {}\n"),
    ]);
    let package_name = source.find("main").expect("package name");
    let import_alias = source.find("sub").expect("import alias");
    let helper_call = source.rfind("Helper").expect("helper call");

    assert!(
        report
            .sites
            .iter()
            .all(|site| site.start_byte != package_name && site.start_byte != import_alias),
        "Go package/import declaration names are not reference sites: {report:#?}"
    );
    assert!(
        report.summary.declaration_sites_excluded >= 2,
        "Go package and import declaration names should count as excluded declaration sites: {report:#?}"
    );
    let helper_site = report
        .sites
        .iter()
        .find(|site| site.start_byte == helper_call)
        .expect("qualified helper call remains sampled");
    assert_eq!(helper_site.forward_status, "resolved", "{helper_site:#?}");
    assert_eq!(
        helper_site.classification,
        ReferenceClassification::Consistent,
        "{helper_site:#?}"
    );
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
            "enum_demo.nodes.NodeValue",
        ),
        (
            variant_start,
            variant_start + "Item".len(),
            "enum_demo.nodes.NodeValue.Item",
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
fn scala_exact_site_round_trips_an_intermediate_nested_owner() {
    let api = r#"package zio.http

final case class WebSocketConfig(sendCloseFrame: WebSocketConfig.CloseStatus)

object WebSocketConfig {
  sealed trait CloseStatus

  object CloseStatus {
    case object NormalClosure extends CloseStatus
    case object EndpointUnavailable extends CloseStatus
  }
}
"#;
    let consumer = r#"package zio.http.netty.socket

import zio.http.WebSocketConfig

private object NettySocketProtocol {
  private def closeStatusToNetty(closeStatus: WebSocketConfig.CloseStatus): Int =
    closeStatus match {
      case WebSocketConfig.CloseStatus.NormalClosure       => 0
      case WebSocketConfig.CloseStatus.EndpointUnavailable => 1
    }
}
"#;
    let files = [
        ("zio/http/WebSocketConfig.scala", api),
        ("zio/http/netty/socket/NettySocketProtocol.scala", consumer),
    ];
    let project = InlineTestProject::with_language(Language::Scala)
        .file(files[0].0, files[0].1)
        .file(files[1].0, files[1].1)
        .build();

    let needle = "WebSocketConfig.CloseStatus.NormalClosure";
    let start = consumer.find(needle).expect("qualified match owner") + "WebSocketConfig.".len();
    let end = start + "CloseStatus".len();
    let public = lookup_by_location(
        project.root(),
        "zio/http/netty/socket/NettySocketProtocol.scala",
        consumer,
        start,
    );
    let public_result = &public["results"][0];
    assert_eq!(public_result["status"], "resolved", "{public}");
    assert_eq!(
        public_result["definitions"][0]["fqn"], "zio.http.WebSocketConfig$.CloseStatus$",
        "{public}"
    );

    let report = scala_exact_site_differential(
        &files,
        "zio/http/netty/socket/NettySocketProtocol.scala",
        start,
        end,
    );
    assert_eq!(report.summary.sampled_sites, 1, "{report:#?}");
    let site = &report.sites[0];
    assert_eq!(site.path, "zio/http/netty/socket/NettySocketProtocol.scala");
    assert_eq!(site.forward_status, "resolved", "{site:#?}");
    assert_eq!(
        site.targets.first().map(|target| target.fq_name.as_str()),
        Some("zio.http.WebSocketConfig$.CloseStatus$"),
        "exact-site differential must agree with public lookup on the sampled middle owner: {site:#?}"
    );
    assert_eq!(
        site.classification,
        ReferenceClassification::Consistent,
        "{site:#?}"
    );
    assert!(
        site.inverse_hit.as_ref().is_some_and(|hit| {
            hit.path == "zio/http/netty/socket/NettySocketProtocol.scala"
                && hit.start_byte == start
                && hit.end_byte == end
                && hit.exact_range
        }),
        "{site:#?}"
    );
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
        [("src/signal.rs", "nested_wrapper.signal.Handle")],
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
        decoy.forward_status, "unresolvable_import_boundary",
        "an unproven wrapper must not turn a same-named physical file into a local declaration route: {decoy:#?}"
    );
    assert_eq!(
        decoy.classification,
        ReferenceClassification::Inconclusive,
        "a forward boundary is not a proven target and therefore cannot be an inverse omission: {decoy:#?}"
    );
    assert!(decoy.inverse_hit.is_none(), "{decoy:#?}");
}
