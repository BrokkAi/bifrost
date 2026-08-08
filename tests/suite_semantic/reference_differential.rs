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

fn js_census_differential(
    files: &[(&str, &str)],
) -> brokk_bifrost::reference_differential::ReferenceDifferentialReport {
    let mut project = InlineTestProject::with_language(Language::JavaScript);
    for (path, source) in files {
        project = project.file(path, *source);
    }
    let project = project.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    run_reference_differential(
        workspace.analyzer(),
        &ReferenceDifferentialConfig {
            corpus_language: "js".to_string(),
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
    .expect("run inline JavaScript census differential")
}

/// A Flow-typed `.js` file parsed with the plain JavaScript grammar loses its
/// whole class declaration to tree-sitter error recovery. The census must grade
/// nothing from that region (#1784): the Flow class-property declaration name
/// `registries` resolves by bare name through the import binder to another
/// module's export, which the differential would otherwise report as a missing
/// reference. The intact part of the same file stays audited.
#[test]
fn census_seed_grades_nothing_from_a_misparsed_region() {
    let install = concat!(
        "import {registries} from './registries.js';\n",
        "export default class Install {\n",
        "  registries: Array<RegistryNames>;\n",
        "  run(opts: {bailout: boolean}) {\n",
        "    return registries(opts);\n",
        "  }\n",
        "}\n",
    );
    let census = js_census_differential(&[
        ("src/registries.js", "export function registries() {}\n"),
        ("src/install.js", install),
    ]);

    let misparsed_region = install
        .find("export default")
        .expect("start of the recovered region");
    let graded: Vec<_> = census
        .sites
        .iter()
        .filter(|site| site.path.ends_with("install.js") && site.start_byte >= misparsed_region)
        .map(|site| (&site.text, site.start_byte, site.classification))
        .collect();
    assert!(
        graded.is_empty(),
        "no site may be graded from the ERROR region: {graded:#?}"
    );

    assert!(
        census.summary.structured_candidates > 0,
        "the census must still audit the file: {:#?}",
        census.summary
    );
}

/// A prototype/object-literal member is reachable only through a receiver, so
/// it is not evidence that a BARE call of the same name could have bound to it
/// (#1783). The angular.js witness: `src/ng/parse.js` declares
/// `Lexer.prototype.isNumber` and calls a bare `isNumber(value)` that resolves
/// to a different module's export; the census graded the unresolved bare call
/// tier 1 purely because the terminal segment of the member's fq name matched.
/// The bare name is not lexically bound in the file, so the site is
/// exploration-grade (tier 3), not an actionable forward gap.
///
/// The positive face of this contract -- a bare call that IS lexically bound in
/// the file yet forward cannot resolve -- has no honest inline witness after
/// #1782 taught the resolver `var` hoisting: every in-file lexical binder the
/// census can see is now one the forward resolver also follows, so the shape
/// would have to be a fresh forward bug. It is pinned instead by the direct
/// unit test on the bindability answer in
/// `bifrost-analysis/src/analyzer/reference_candidates.rs`.
#[test]
fn census_bare_call_is_not_graded_from_a_member_it_cannot_bind() {
    let parse = concat!(
        "function Lexer() {}\n",
        "Lexer.prototype = {\n",
        "  isNumber: function(ch) {\n",
        "    return ch >= '0' && ch <= '9';\n",
        "  },\n",
        "};\n",
        "function parseValue(value) {\n",
        "  return isNumber(value);\n",
        "}\n",
    );
    let census = js_census_differential(&[("src/parse.js", parse)]);

    let bare_call_start = parse.find("isNumber(value)").expect("bare call site");
    let site = census
        .sites
        .iter()
        .find(|site| site.start_byte == bare_call_start)
        .unwrap_or_else(|| panic!("census must propose the bare call: {:#?}", census.sites));
    assert_eq!(
        site.forward_status, "no_definition",
        "witness requires a forward-unresolvable bare call: {site:#?}"
    );
    assert_eq!(
        site.tier,
        Some(3),
        "a member the bare name cannot bind is not same-file evidence: {site:#?}"
    );
    assert_eq!(
        site.classification,
        ReferenceClassification::Inconclusive,
        "an unbindable member must not produce a missing finding: {site:#?}"
    );
}

fn java_census_differential(
    files: &[(&str, &str)],
) -> brokk_bifrost::reference_differential::ReferenceDifferentialReport {
    let mut project = InlineTestProject::with_language(Language::Java);
    for (path, source) in files {
        project = project.file(path, *source);
    }
    let project = project.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    run_reference_differential(
        workspace.analyzer(),
        &ReferenceDifferentialConfig {
            corpus_language: "java".to_string(),
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
    .expect("run inline Java census differential")
}

/// The control for #1783: a Java bare call reaches an enclosing-class method
/// through implicit `this`, so an OWNED same-file member is legitimate evidence
/// there and must keep grading exactly as before -- the JS bindability answer
/// must not become a blanket owner filter. The witness is a bare `helper()`
/// inside a nested class, which the forward resolver misses while
/// `Inner.helper` is indexed in the same file. It grades tier 2 rather than
/// tier 1 because `census_site_role` reads a bare-call callee from a
/// `function`/`callee` field, which Java's `method_invocation` spells as
/// `name`; that is a separate grading gap and this test pins today's answer.
#[test]
fn census_java_bare_call_keeps_owned_member_evidence() {
    let source = concat!(
        "class Inner {\n",
        "  void helper() {}\n",
        "  class Nested {\n",
        "    void go() { helper(); }\n",
        "  }\n",
        "}\n",
    );
    let census = java_census_differential(&[("Inner.java", source)]);

    let call_start = source.find("helper();").expect("bare call site");
    let site = census
        .sites
        .iter()
        .find(|site| site.start_byte == call_start)
        .unwrap_or_else(|| panic!("census must propose the bare call: {:#?}", census.sites));
    assert_eq!(
        site.forward_status, "no_definition",
        "witness requires a forward-unresolvable bare call: {site:#?}"
    );
    assert_eq!(
        site.tier,
        Some(2),
        "an owned same-class method stays same-file evidence in Java: {site:#?}"
    );
    assert_eq!(
        site.classification,
        ReferenceClassification::Missing,
        "Java grading must not change: {site:#?}"
    );
}

fn cpp_census_differential(
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
            probe_seed: ProbeSeed::Census,
            ..ReferenceDifferentialConfig::default()
        },
    )
    .expect("run inline C++ census differential")
}

/// A constructor or destructor declarator is a declaration occurrence, so the
/// census must not seed it (#1834). The log4cxx/brpc/abseil witnesses all sit in
/// a class body the parse never recovered as one: an export macro between
/// `class` and the class name turns the class into a `function_definition` whose
/// body is a `compound_statement`, and every constructor declaration inside it
/// into a call of the class's own name. Graded, each became a tier-1 forward gap
/// against its own class -- while the same site is `inconclusive` under the
/// index seed, which never proposes it.
///
/// The exclusion is confined to the declarators: the recovered body is still
/// audited, and a real call inside a method body there stays a probe.
#[test]
fn census_seed_skips_a_constructor_declarator_the_parse_read_as_a_call() {
    let properties = concat!(
        "namespace helpers {\n",
        "\n",
        "class SAMPLE_EXPORT Properties {\n",
        "\tpublic:\n",
        "\t\tProperties();\n",
        "\t\tProperties(const Properties&&) = delete;\n",
        "\t\tint size() const;\n",
        "\t\tint total() { return size(); }\n",
        "};\n",
        "\n",
        "}\n",
    );
    let census = cpp_census_differential(&[("include/properties.h", properties)]);

    for (label, declarator) in [
        (
            "default constructor",
            properties.find("Properties();").expect("default ctor"),
        ),
        (
            "deleted move constructor",
            properties
                .find("Properties(const Properties&&)")
                .expect("deleted move ctor"),
        ),
    ] {
        let seeded: Vec<_> = census
            .sites
            .iter()
            .filter(|site| site.start_byte == declarator)
            .map(|site| (&site.text, site.tier, site.classification, &site.note))
            .collect();
        assert!(
            seeded.is_empty(),
            "the {label} declarator at byte {declarator} must not be seeded: {seeded:#?}"
        );
    }

    // The parameter type is a genuine reference to the class, and so is the
    // `size()` call in the method body the recovery left intact.
    let parameter_type = properties
        .find("const Properties&&")
        .expect("parameter type reference")
        + "const ".len();
    let member_call = properties.find("return size();").expect("member call") + "return ".len();
    for kept in [parameter_type, member_call] {
        assert!(
            census.sites.iter().any(|site| site.start_byte == kept),
            "the recovered class body stays audited at byte {kept}: {:#?}",
            census
                .sites
                .iter()
                .map(|site| (&site.text, site.start_byte))
                .collect::<Vec<_>>()
        );
    }
}

/// Constructor CALL sites are references and keep their probes: `new Foo(...)`,
/// the direct-initialization `Foo value(...)` and the base-class member
/// initializer are all genuine occurrences of the type name. Only the
/// declarators -- here the out-of-line `Store::Store` definition name and the
/// destructor name -- leave the seed.
#[test]
fn census_seed_keeps_constructor_call_sites_it_excludes_declarators_from() {
    let header = concat!(
        "struct Base {\n",
        "  Base(int seed);\n",
        "};\n",
        "\n",
        "struct Store : Base {\n",
        "  Store(int seed);\n",
        "  ~Store();\n",
        "  int value_;\n",
        "};\n",
    );
    let body = concat!(
        "#include \"store.h\"\n",
        "\n",
        "Store::Store(int seed) : Base(seed), value_(seed) {}\n",
        "\n",
        "Store::~Store() {}\n",
        "\n",
        "Store* make(int seed) {\n",
        "  Store direct(seed);\n",
        "  return new Store(seed);\n",
        "}\n",
    );
    let census = cpp_census_differential(&[("store.h", header), ("store.cpp", body)]);

    let sites: Vec<usize> = census
        .sites
        .iter()
        .filter(|site| site.path.ends_with("store.cpp"))
        .map(|site| site.start_byte)
        .collect();
    let definition_name =
        body.find("Store::Store").expect("out-of-line definition") + "Store::".len();
    let destructor_name =
        body.find("Store::~Store").expect("out-of-line destructor") + "Store::~".len();
    for excluded in [definition_name, destructor_name] {
        assert!(
            !sites.contains(&excluded),
            "an out-of-line declarator name at byte {excluded} must not be seeded: {sites:?}"
        );
    }

    let owner_scope = body.find("Store::Store").expect("definition owner scope");
    let base_initializer = body.find(": Base(seed)").expect("base initializer") + ": ".len();
    let direct_initialization = body.find("Store direct").expect("direct initialization");
    let new_expression = body.find("new Store(seed)").expect("new expression") + "new ".len();
    for kept in [
        owner_scope,
        base_initializer,
        direct_initialization,
        new_expression,
    ] {
        assert!(
            sites.contains(&kept),
            "a constructor call or owner reference at byte {kept} must stay seeded: {sites:?}"
        );
    }
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

/// The census differential found Go receiver type mentions forward-resolving to
/// the type while the inverse listing omitted them entirely (#1765: 2462 of 2485
/// forward-adjudicated misses on the Go top-20 corpus). They are now inverse-
/// visible as `SelfReceiver`, so the site classifies `editor_only`, while an
/// ordinary type reference stays `consistent`.
#[test]
fn go_method_receiver_type_is_an_editor_only_reference_site() {
    let source = r#"package main

type ResourceType int

func (r ResourceType) String() string {
    return "resource"
}

func Describe(value ResourceType) string {
    return value.String()
}
"#;
    let report = go_differential(&[("go.mod", "module example.com/app\n"), ("main.go", source)]);
    let receiver_type = source.find("r ResourceType").expect("receiver type") + "r ".len();
    let parameter_type =
        source.find("value ResourceType").expect("parameter type") + "value ".len();

    let receiver_site = report
        .sites
        .iter()
        .find(|site| site.start_byte == receiver_type)
        .expect("the receiver type remains a sampled reference site");
    assert_eq!(
        receiver_site.forward_status, "resolved",
        "{receiver_site:#?}"
    );
    assert_eq!(
        receiver_site.classification,
        ReferenceClassification::EditorOnly,
        "the receiver type mention is editor-visible but not an external usage: {receiver_site:#?}"
    );

    let parameter_site = report
        .sites
        .iter()
        .find(|site| site.start_byte == parameter_type)
        .expect("the parameter type remains a sampled reference site");
    assert_eq!(
        parameter_site.classification,
        ReferenceClassification::Consistent,
        "{parameter_site:#?}"
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
