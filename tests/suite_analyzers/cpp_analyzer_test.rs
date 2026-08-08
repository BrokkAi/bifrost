use crate::common::{InlineTestProject, assert_code_eq, cpp_fixture_project};
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::{
    CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, ImportAnalysisProvider, Language, Project,
    ProjectFile, TestProject, TypeAliasProvider, TypeHierarchyProvider,
};
use std::collections::BTreeSet;
use tempfile::tempdir;

fn fixture_analyzer() -> CppAnalyzer {
    CppAnalyzer::from_project(cpp_fixture_project())
}

fn inline_cpp_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Cpp)
}

fn all_declarations(analyzer: &CppAnalyzer) -> Vec<CodeUnit> {
    analyzer
        .project()
        .all_files()
        .unwrap()
        .into_iter()
        .flat_map(|file| analyzer.get_declarations(&file))
        .collect()
}

#[test]
fn macro_field_terminator_restores_following_namespace_declaration_owners() {
    let source = r#"#pragma once

#include "api/envoy/v12/http/backend_auth/config.pb.h"
#include "source/common/common/logger.h"
#include "src/envoy/http/backend_auth/config_parser.h"

namespace espv2 {
namespace envoy {
namespace http_filters {
namespace backend_auth {
/**
 * All stats for the backend auth filter. @see stats_macros.h
 */
#define ALL_BACKEND_AUTH_FILTER_STATS(COUNTER) \
  COUNTER(denied_by_no_route)                  \
  COUNTER(denied_by_no_token)                  \
  COUNTER(allowed_by_auth_not_required)        \
  COUNTER(token_added)

/**
 * Wrapper struct for backend auth filter stats. @see stats_macros.h
 */
struct FilterStats {
  ALL_BACKEND_AUTH_FILTER_STATS(GENERATE_COUNTER_STRUCT)
};

class FilterConfig {
 public:
  virtual ~FilterConfig() = default;

  virtual FilterStats& stats() PURE;

  virtual const FilterConfigParser& cfg_parser() const PURE;
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;
}  // namespace backend_auth
}  // namespace http_filters
}  // namespace envoy
}  // namespace espv2
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("filter_config.h", source)
        .file(
            "near_miss.h",
            r#"namespace near_miss {
#define ALL_FILTER_STATS(COUNTER) COUNTER(one)
struct RealOwner {
  ALL_FILTER_STATS(GENERATE_COUNTER_STRUCT);
  class FilterConfig {};
  using FilterConfigSharedPtr = FilterConfig*;
};
}
namespace sibling {
class FilterConfig {};
using FilterConfigSharedPtr = FilterConfig*;
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let declarations = analyzer.get_declarations(&project.file("filter_config.h"));
    let fqs = declarations
        .iter()
        .map(|unit| unit.fq_name())
        .collect::<BTreeSet<_>>();
    let namespace = "espv2::envoy::http_filters::backend_auth";

    for expected in [
        format!("{namespace}.FilterStats"),
        format!("{namespace}.FilterConfig"),
        format!("{namespace}.FilterConfig.stats"),
        format!("{namespace}.FilterConfig.cfg_parser"),
        format!("{namespace}.FilterConfigSharedPtr"),
    ] {
        assert!(
            fqs.contains(expected.as_str()),
            "missing {expected}: {fqs:#?}"
        );
    }
    assert!(
        fqs.iter()
            .all(|fq| !fq.contains("FilterStats$FilterConfig")),
        "the displaced `}};` must fence the recovered class scope: {fqs:#?}"
    );

    let filter_stats = declarations
        .iter()
        .find(|unit| unit.fq_name() == format!("{namespace}.FilterStats"))
        .expect("FilterStats declaration");
    let ranges = analyzer.ranges(filter_stats);
    assert_eq!(ranges.len(), 1, "FilterStats ranges: {ranges:?}");
    let range = ranges[0];
    assert_eq!(
        &source[range.start_byte..range.end_byte],
        "struct FilterStats {\n  ALL_BACKEND_AUTH_FILTER_STATS(GENERATE_COUNTER_STRUCT)\n};",
        "the recovered declaration range must end at the structural terminator"
    );

    let near_miss_declarations = analyzer.get_declarations(&project.file("near_miss.h"));
    let near_miss_fqs = near_miss_declarations
        .iter()
        .map(|unit| unit.fq_name())
        .collect::<BTreeSet<_>>();
    for expected in [
        "near_miss.RealOwner$FilterConfig",
        "near_miss.RealOwner$FilterConfigSharedPtr",
        "sibling.FilterConfig",
        "sibling.FilterConfigSharedPtr",
    ] {
        assert!(
            near_miss_fqs.contains(expected),
            "missing near-miss declaration {expected}: {near_miss_fqs:#?}"
        );
    }
}

#[test]
fn preprocessor_split_primary_class_reowns_fragmented_tail_members() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "fragmented.hpp",
            r#"#if USE_STANDARD
#else
namespace lib {
#if nsel_P0323R <= 2
template< typename T, typename E = std::exception_ptr >
class expected
#else
template< typename T, typename E >
class expected
#endif // nsel_P0323R
{
private:
    template< typename, typename > friend class expected;

public:
    using value_type = T;
    template< typename U
        nsel_REQUIRES_T(
            std::is_constructible<T, U const &>::value
        )
    >
    nsel_constexpr14 explicit expected(expected<U, E> const& other)
    : stored(other.stored)
    {
        if (true) stored.construct(T{other.value()});
        else stored.construct(E{other.error()});
    }
    value_type& first() { throw 0; }
    value_type& emplace(int) { throw 0; }
    value_type& emplace(double) { throw 0; }
private:
    T stored;
};

void after_fragment() {}
}
#endif
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let declarations = analyzer.get_declarations(&project.file("fragmented.hpp"));
    let overloads = declarations
        .iter()
        .filter(|unit| unit.is_function() && unit.identifier() == "emplace")
        .collect::<Vec<_>>();

    assert_eq!(
        overloads.len(),
        2,
        "missing recovered overloads: {declarations:#?}"
    );
    let expected = analyzer
        .parent_of(overloads[0])
        .filter(|unit| unit.is_class() && unit.identifier() == "expected")
        .expect("recovered overload owner");
    let value_type = declarations
        .iter()
        .find(|unit| unit.identifier() == "value_type")
        .expect("recovered class alias");
    assert_eq!(
        analyzer.parent_of(value_type).as_ref(),
        Some(&expected),
        "the prefix alias and recovered tail overloads must share one class owner"
    );
    for overload in overloads {
        assert_eq!(
            analyzer.parent_of(overload).as_ref(),
            Some(&expected),
            "fragmented tail overload escaped to namespace scope: {overload:?}"
        );
    }
    let after = declarations
        .iter()
        .find(|unit| unit.is_function() && unit.identifier() == "after_fragment")
        .expect("post-class namespace function");
    assert_ne!(
        analyzer.parent_of(after).as_ref(),
        Some(&expected),
        "recovery crossed the displaced class terminator"
    );
}

#[test]
fn preprocessor_fragmented_partial_specialization_reowns_tail_members() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "fragmented_specialization.hpp",
            r#"namespace lib {
#if USE_STANDARD
using std::expected;
#else
template<typename T, typename E> class expected;

template<typename E>
class expected<void, E> {
public:
    constexpr expected() noexcept
        : contained(true)
    {}

    constexpr explicit expected(in_place_t(void))
        : contained(true)
    {}

    template<typename G = E
        nsel_REQUIRES_T(
            !std::is_convertible<G const&, E>::value
        )
    >
    nsel_constexpr14 explicit expected(G const& error)
        : contained(false)
    {
        contained.construct_error(E{error.error()});
    }

    template<typename G = E
        nsel_REQUIRES_T(
            std::is_convertible<G const&, E>::value
        )
    >
    nsel_constexpr14 expected(G const& error)
        : contained(false)
    {
        contained.construct_error(error.error());
    }

    bool has_value() const { return contained.has_value(); }

private:
    bool contained;
};

void after_specialization() {}
#endif
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let declarations = analyzer.get_declarations(&project.file("fragmented_specialization.hpp"));
    let contained = declarations
        .iter()
        .find(|unit| unit.is_field() && unit.identifier() == "contained")
        .expect("recovered specialization field");
    let specialization = analyzer.parent_of(contained);
    assert!(
        specialization
            .as_ref()
            .is_some_and(|unit| unit.is_class() && unit.fq_name() == "lib.expected<void, E>"),
        "missing recovered partial-specialization owner: {specialization:#?}; {declarations:#?}"
    );
    let specialization = specialization.unwrap();
    assert_eq!(
        analyzer.parent_of(contained).as_ref(),
        Some(&specialization),
        "fragmented specialization field escaped to namespace scope: {declarations:#?}"
    );
    let has_value = declarations
        .iter()
        .find(|unit| unit.is_function() && unit.identifier() == "has_value")
        .expect("recovered specialization method");
    assert_eq!(
        analyzer.parent_of(has_value).as_ref(),
        Some(&specialization),
        "fragmented specialization method escaped to namespace scope: {declarations:#?}"
    );
    let after = declarations
        .iter()
        .find(|unit| unit.is_function() && unit.identifier() == "after_specialization")
        .expect("post-specialization namespace function");
    assert_ne!(
        analyzer.parent_of(after).as_ref(),
        Some(&specialization),
        "recovery crossed the displaced class terminator"
    );
}

#[test]
fn named_inline_enum_with_trailing_field_keeps_both_declarations() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "types.hpp",
            r#"namespace app {
struct First {
    enum Kind { FirstValue } value;
};
struct Second {
    enum Kind { SecondValue } value;
    Kind choose(Kind input);
};
}
enum { AnonymousValue } anonymous_value;
class Referenced referenced_value;
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let declarations = analyzer.get_declarations(&project.file("types.hpp"));

    for expected in [
        "app.First$Kind",
        "app.First.value",
        "app.Second$Kind",
        "app.Second.value",
    ] {
        assert!(
            declarations.iter().any(|unit| unit.fq_name() == expected),
            "missing {expected}: {declarations:#?}"
        );
    }
    assert!(
        declarations
            .iter()
            .all(|unit| unit.identifier() != "Referenced"),
        "an elaborated type use must not manufacture a class definition: {declarations:#?}"
    );
    assert!(
        declarations.iter().all(|unit| {
            unit.kind() != CodeUnitType::Class || unit.identifier() != "anonymous_value"
        }),
        "an anonymous enum's object must not become a named type: {declarations:#?}"
    );
}

#[test]
fn macro_decorated_qualified_static_field_keeps_real_identity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "reader.hpp",
            r#"#define API_INLINE
struct Reader {
    static API_INLINE constexpr std::size_t npos = 1, other = 2;
    static API_INLINE constexpr std::size_t *pointer = nullptr;
    static API_INLINE constexpr std::size_t &reference = other;
};
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let declarations = analyzer.get_declarations(&project.file("reader.hpp"));

    for expected in [
        "Reader.npos",
        "Reader.other",
        "Reader.pointer",
        "Reader.reference",
    ] {
        assert!(
            declarations
                .iter()
                .any(|unit| unit.is_field() && unit.fq_name() == expected),
            "real field {expected} is missing: {declarations:#?}"
        );
    }
    assert!(
        declarations
            .iter()
            .all(|unit| unit.fq_name() != "Reader.std"),
        "qualified type prefix became a pseudo-field: {declarations:#?}"
    );
}

fn base_function_name(code_unit: &CodeUnit) -> String {
    let short_name = code_unit.short_name();
    if let Some((_, suffix)) = short_name.rsplit_once("::") {
        return suffix.to_string();
    }
    if let Some((_, suffix)) = short_name.rsplit_once('.') {
        return suffix.to_string();
    }
    if let Some((_, suffix)) = short_name.rsplit_once('$') {
        return suffix.to_string();
    }
    short_name.to_string()
}

#[test]
fn function_like_export_macro_preserves_class_declaration_identity() {
    let project = inline_cpp_project(&[(
        "gurl.h",
        "#define COMPONENT_EXPORT(component)\nnamespace url { class COMPONENT_EXPORT(URL) GURL { public: void Swap(GURL*); }; }\n",
    )]);
    let analyzer = CppAnalyzer::from_project(project);

    let classes = analyzer.get_definitions("url.GURL");
    assert_eq!(classes.len(), 1, "class declarations: {classes:#?}");
    assert_eq!(classes[0].kind(), CodeUnitType::Class);
    assert_eq!(classes[0].source().rel_path().to_string_lossy(), "gurl.h");

    let methods = analyzer.get_definitions("url.GURL.Swap");
    assert_eq!(methods.len(), 1, "method declarations: {methods:#?}");
    assert_eq!(methods[0].kind(), CodeUnitType::Function);
    assert_eq!(analyzer.parent_of(&methods[0]), Some(classes[0].clone()));
}

#[test]
fn recovered_export_macro_class_reuses_unique_namespace_forward_identity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "recovered.hpp",
            r#"#define API __attribute__((visibility("default")))
#define ASSERT(x) do {} while(false)
namespace ns {
class Foo;
class API Util {
public:
    static void first() { ASSERT(1); }
    static void second();
};
class API Foo {
public:
    void method();
};
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let declarations = analyzer.get_all_declarations();

    let foo_definitions: Vec<_> = declarations
        .iter()
        .filter(|unit| unit.kind() == CodeUnitType::Class && unit.identifier() == "Foo")
        .collect();
    assert_eq!(
        1,
        foo_definitions.len(),
        "the recovered class should keep one logical identity: {declarations:#?}"
    );
    assert_eq!(
        "ns.Foo",
        foo_definitions[0].fq_name(),
        "the recovered top-level export class must reconcile to its earlier namespace forward declaration"
    );

    let methods: Vec<_> = declarations
        .iter()
        .filter(|unit| unit.kind() == CodeUnitType::Function && unit.identifier() == "method")
        .collect();
    assert_eq!(
        methods.len(),
        1,
        "recovered method declarations: {declarations:#?}"
    );
    assert_eq!("ns.Foo.method", methods[0].fq_name());
}

#[test]
fn recovered_root_export_class_reuses_malformed_namespace_forward_identity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "tinyxml.h",
            r#"#define API __attribute__((visibility("default")))
namespace tinyxml2 {
class XMLElement;
class API XMLElement {
public:
    void method();
};
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let declarations = analyzer.get_all_declarations();
    let definitions: Vec<_> = declarations
        .iter()
        .filter(|unit| unit.kind() == CodeUnitType::Class && unit.identifier() == "XMLElement")
        .collect();
    assert_eq!(
        1,
        definitions
            .iter()
            .filter(|unit| unit.fq_name() == "tinyxml2.XMLElement")
            .count(),
        "the malformed namespace forward should identify the recovered class: {declarations:#?}"
    );
    let methods: Vec<_> = declarations
        .iter()
        .filter(|unit| unit.kind() == CodeUnitType::Function && unit.identifier() == "method")
        .collect();
    assert_eq!(
        1,
        methods.len(),
        "recovered method declarations: {declarations:#?}"
    );
    assert_eq!("tinyxml2.XMLElement.method", methods[0].fq_name());
}

#[test]
fn clean_unrelated_namespace_forward_does_not_rekey_root_export_class() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "unrelated.h",
            r#"#define API __attribute__((visibility("default")))
namespace unrelated {
class XMLElement;
}
class API XMLElement {
public:
    void method();
};
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let declarations = analyzer.get_all_declarations();
    assert!(
        declarations
            .iter()
            .any(|unit| { unit.kind() == CodeUnitType::Class && unit.fq_name() == "XMLElement" }),
        "the recovered class should remain at file scope without a malformed namespace anchor: {declarations:#?}"
    );
    let methods: Vec<_> = declarations
        .iter()
        .filter(|unit| unit.kind() == CodeUnitType::Function && unit.identifier() == "method")
        .collect();
    assert_eq!(
        1,
        methods.len(),
        "recovered method declarations: {declarations:#?}"
    );
    assert_eq!(
        "XMLElement.method",
        methods[0].fq_name(),
        "a clean unrelated namespace forward must not re-key the recovered class or its members"
    );
}

#[test]
fn malformed_exported_multiple_base_class_does_not_promote_object_declarators() {
    let project = inline_cpp_project(&[
        (
            "widget.h",
            r#"#define VIEWS_EXPORT
namespace internal { class NativeWidgetDelegate {}; }
namespace ui {
class EventSource {};
class NativeThemeObserver {};
class ColorProviderSource {};
class PropertyHandler {};
class AXModeObserver {};
namespace metadata { class MetaDataProvider {}; }
}
class FocusTraversable {};
namespace views {
class VIEWS_EXPORT Widget : public internal::NativeWidgetDelegate,
                            public ui::EventSource,
                            public FocusTraversable,
                            public ui::NativeThemeObserver,
                            public ui::ColorProviderSource,
                            public ui::PropertyHandler,
                            public ui::AXModeObserver,
                            public ui::metadata::MetaDataProvider {
    ADVANCED_MEMORY_SAFETY_CHECKS();

 public:
    Widget();
};
}

class Outer { class Nested; };
class API {};
class API *pointer_value;
class API &reference_value = *pointer_value;
class API array_value[1];
class API object_value{};
"#,
        ),
        (
            "two_base.h",
            r#"#define VIEWS_EXPORT
namespace views {
class VIEWS_EXPORT TwoBase : public internal::NativeWidgetDelegate,
                             public ui::EventSource {
public:
    TwoBase();
};
}
"#,
        ),
    ]);
    let analyzer = CppAnalyzer::from_project(project);

    let classes: Vec<_> = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| unit.kind() == CodeUnitType::Class && !unit.is_synthetic())
        .collect();
    assert_eq!(
        classes
            .iter()
            .filter(|unit| unit.fq_name() == "views.Widget")
            .count(),
        1,
        "recovered Widget identities: {classes:#?}"
    );
    let widget = classes
        .iter()
        .find(|unit| unit.fq_name() == "views.Widget")
        .expect("recovered Widget class");
    let ancestors: BTreeSet<_> = analyzer
        .get_direct_ancestors(widget)
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect();
    assert_eq!(
        ancestors,
        BTreeSet::from([
            "FocusTraversable".to_string(),
            "internal.NativeWidgetDelegate".to_string(),
            "ui.AXModeObserver".to_string(),
            "ui.ColorProviderSource".to_string(),
            "ui.EventSource".to_string(),
            "ui.NativeThemeObserver".to_string(),
            "ui.PropertyHandler".to_string(),
            "ui::metadata.MetaDataProvider".to_string(),
        ]),
        "recovered Widget supertypes"
    );
    assert_eq!(
        classes
            .iter()
            .filter(|unit| unit.fq_name() == "views.TwoBase")
            .count(),
        1,
        "two-base exported class identities: {classes:#?}"
    );
    assert!(
        classes.iter().any(|unit| unit.fq_name() == "Outer$Nested"),
        "nested forward declaration was not preserved: {classes:#?}"
    );
    assert_eq!(
        classes
            .iter()
            .filter(|unit| unit.fq_name() == "API")
            .count(),
        1,
        "ordinary API object declarators must not become classes: {classes:#?}"
    );
    for phantom in [
        "pointer_value",
        "reference_value",
        "array_value",
        "object_value",
    ] {
        assert!(
            classes.iter().all(|unit| unit.identifier() != phantom),
            "ordinary declarator {phantom} became a phantom class: {classes:#?}"
        );
    }

    let fields: Vec<_> = analyzer
        .get_all_declarations()
        .into_iter()
        .filter(|unit| unit.kind() == CodeUnitType::Field && !unit.is_synthetic())
        .collect();
    for expected in [
        "pointer_value",
        "reference_value",
        "array_value",
        "object_value",
    ] {
        assert!(
            fields.iter().any(|unit| unit.fq_name() == expected),
            "ordinary declarator {expected} lost its Field identity: {fields:#?}"
        );
    }
}

#[test]
fn newline_exported_class_with_templated_base_keeps_class_identity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "connection.hpp",
            r#"#define PN_CPP_CLASS_EXTERN
struct pn_connection_t;
namespace proton {
namespace internal { template <typename T> class object {}; }
class endpoint {};
class
PN_CPP_CLASS_EXTERN connection : public internal::object<pn_connection_t>, public endpoint {
 public:
    void open();
};
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let declarations = analyzer.get_all_declarations();

    let connections = declarations
        .iter()
        .filter(|unit| {
            unit.kind() == CodeUnitType::Class
                && unit.fq_name() == "proton.connection"
                && !unit.is_synthetic()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        connections.len(),
        1,
        "newline macro class must retain its displaced connection identity: {declarations:#?}"
    );

    let ancestors = analyzer
        .get_direct_ancestors(connections[0])
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ancestors,
        BTreeSet::from([
            "proton.endpoint".to_string(),
            "proton::internal.object".to_string(),
        ]),
        "templated and terminal bases must both survive structured recovery"
    );
    assert!(
        declarations.iter().all(|unit| {
            unit.kind() != CodeUnitType::Field || unit.fq_name() != "proton.endpoint"
        }),
        "the final base declarator must not leak as a phantom proton.endpoint Field: {declarations:#?}"
    );
}

#[test]
fn enum_enumerators_are_children_not_top_level_declarations() {
    let project = inline_cpp_project(&[(
        "colors.hpp",
        r#"namespace ui {
enum class color { alice_blue, antique_white, aqua };
enum stroke { thin, thick };
}
"#,
    )]);
    let analyzer = CppAnalyzer::from_project(project);
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "colors.hpp");

    let top_level = analyzer.get_top_level_declarations(&file);
    assert!(
        top_level.iter().any(|unit| unit.fq_name() == "ui.color"),
        "the enum itself must stay top-level: {top_level:#?}"
    );
    assert!(
        top_level
            .iter()
            .all(|unit| unit.kind() != CodeUnitType::Field),
        "enumerators must not appear as top-level declarations: {top_level:#?}"
    );

    let color = top_level
        .iter()
        .find(|unit| unit.fq_name() == "ui.color")
        .unwrap();
    let children: Vec<_> = analyzer
        .direct_children(color)
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect();
    for expected in [
        "ui.color.alice_blue",
        "ui.color.antique_white",
        "ui.color.aqua",
    ] {
        assert!(
            children.iter().any(|name| name == expected),
            "missing enumerator child {expected}: {children:#?}"
        );
    }
}

#[test]
fn stacked_sentinel_enum_keeps_later_sibling_declarations() {
    // fmt's color.h shape: two stacked unknown export macros make tree-sitter
    // wrap the whole file in one ERROR envelope, and the first enum's body is
    // recovered through the sentinel macro region. The declarations after the
    // recovered enum's close must survive as ordinary siblings.
    let project = inline_cpp_project(&[(
        "color.h",
        r#"FMT_BEGIN_NAMESPACE
FMT_BEGIN_EXPORT

enum class color : uint32_t {
  alice_blue = 0xF0F8FF,               // rgb(240,248,255)
  antique_white = 0xFAEBD7,            // rgb(250,235,215)
};  // enum class color

enum class terminal_color : uint8_t {
  black = 30,
  red
};

struct rgb {
  int r;
};

FMT_END_EXPORT
FMT_END_NAMESPACE
"#,
    )]);
    let analyzer = CppAnalyzer::from_project(project);
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "color.h");

    let declarations = analyzer.get_declarations(&file);
    for expected in [
        "color",
        "color.alice_blue",
        "terminal_color",
        "terminal_color.black",
        "terminal_color.red",
        "rgb",
        "rgb.r",
    ] {
        assert!(
            declarations.iter().any(|unit| unit.fq_name() == expected),
            "missing {expected}: {declarations:#?}"
        );
    }
    let color_count = declarations
        .iter()
        .filter(|unit| unit.fq_name() == "color")
        .count();
    assert_eq!(
        color_count, 1,
        "the recovered enum must not be indexed twice: {declarations:#?}"
    );

    let top_level = analyzer.get_top_level_declarations(&file);
    for expected in ["color", "terminal_color", "rgb"] {
        assert!(
            top_level.iter().any(|unit| unit.fq_name() == expected),
            "missing top-level {expected}: {top_level:#?}"
        );
    }
}

#[test]
fn cpp_iterative_visitor_preserves_top_level_source_order() {
    let project = inline_cpp_project(&[(
        "ordered.cpp",
        r#"
#include "a.h"
#include "b.h"
struct First {};
struct Second {};
"#,
    )]);
    let analyzer = CppAnalyzer::from_project(project);
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "ordered.cpp");

    let top_level: Vec<_> = analyzer
        .get_top_level_declarations(&file)
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect();
    assert_eq!(vec!["First", "Second"], top_level);
    assert_eq!(
        vec!["#include \"a.h\"", "#include \"b.h\""],
        analyzer.import_statements_of(&file)
    );
}

#[test]
fn cpp_identifier_collection_handles_deep_template_shape_iteratively() {
    let mut source = String::from("template <typename T> struct Box {};\nusing Deep = ");
    for _ in 0..256 {
        source.push_str("Box<");
    }
    source.push_str("int");
    for _ in 0..256 {
        source.push('>');
    }
    source.push_str(";\n");

    let project = inline_cpp_project(&[("deep.cpp", &source)]);
    let analyzer = CppAnalyzer::from_project(project);

    assert!(
        analyzer
            .get_all_declarations()
            .into_iter()
            .any(|unit| unit.fq_name() == "Box")
    );
}

#[test]
fn test_namespace_class_struct_and_global_analysis() {
    let analyzer = fixture_analyzer();
    let all = all_declarations(&analyzer);

    let namespaces: Vec<_> = all
        .iter()
        .filter(|cu| cu.kind() == CodeUnitType::Module)
        .collect();
    assert!(namespaces.iter().any(|cu| cu.short_name() == "graphics"));
    assert!(namespaces.iter().any(|cu| cu.short_name() == "ui::widgets"));

    let classes: Vec<_> = all
        .iter()
        .filter(|cu| cu.kind() == CodeUnitType::Class)
        .collect();
    assert!(classes.iter().any(|cu| cu.short_name().contains("Circle")));
    assert!(
        classes
            .iter()
            .any(|cu| cu.short_name().contains("Renderer"))
    );
    assert!(classes.iter().any(|cu| cu.short_name().contains("Widget")));
    assert!(classes.iter().any(|cu| cu.short_name().contains("Point")));

    let functions: Vec<_> = all
        .iter()
        .filter(|cu| cu.kind() == CodeUnitType::Function)
        .collect();
    assert!(functions.len() >= 3);
    assert!(
        functions
            .iter()
            .any(|cu| cu.package_name().is_empty() && cu.fq_name().contains("global_func"))
    );
    assert!(
        functions
            .iter()
            .any(|cu| cu.package_name().is_empty() && cu.fq_name().contains("uses_global_func"))
    );

    let fields: Vec<_> = all
        .iter()
        .filter(|cu| cu.kind() == CodeUnitType::Field)
        .collect();
    assert!(
        fields
            .iter()
            .any(|cu| cu.package_name().is_empty() && cu.fq_name().contains("global_var"))
    );

    let graphics_classes: Vec<_> = classes
        .iter()
        .filter(|cu| cu.package_name() == "graphics")
        .collect();
    let widget_classes: Vec<_> = classes
        .iter()
        .filter(|cu| cu.package_name() == "ui::widgets")
        .collect();
    assert!(graphics_classes.len() >= 2);
    assert!(!widget_classes.is_empty());
}

#[test]
fn test_cpp_skeleton_output_and_nested_classes() {
    let analyzer = fixture_analyzer();
    let root = analyzer.project().root().to_path_buf();
    let geometry_cpp = ProjectFile::new(root.clone(), "geometry.cpp");
    let nested_cpp = ProjectFile::new(root, "nested.cpp");

    let geometry_skeletons = analyzer.get_skeletons(&geometry_cpp);
    assert!(!geometry_skeletons.is_empty());
    let function_skeletons: Vec<_> = geometry_skeletons
        .iter()
        .filter(|(cu, _)| cu.kind() == CodeUnitType::Function)
        .collect();
    assert!(!function_skeletons.is_empty());
    for (code_unit, skeleton) in function_skeletons {
        if code_unit.fq_name().contains("getArea")
            || code_unit.fq_name().contains("print")
            || code_unit.fq_name().contains("global_func")
        {
            assert!(skeleton.contains("{...}"));
        }
    }

    let nested_skeletons = analyzer.get_skeletons(&nested_cpp);
    let outer = nested_skeletons
        .iter()
        .find(|(cu, _)| cu.short_name() == "Outer")
        .unwrap();
    assert!(outer.1.contains("class Inner"));
    assert!(
        nested_skeletons
            .keys()
            .any(|cu| cu.kind() == CodeUnitType::Function && cu.fq_name().contains("main"))
    );
}

#[test]
fn test_anonymous_namespace() {
    let analyzer = fixture_analyzer();
    let geometry_cpp = ProjectFile::new(analyzer.project().root().to_path_buf(), "geometry.cpp");
    let declarations = analyzer.get_declarations(&geometry_cpp);

    let anonymous: Vec<_> = declarations
        .iter()
        .filter(|cu| cu.is_function())
        .filter(|cu| {
            let base = base_function_name(cu);
            base.contains("anonymous_helper") || base.contains("anonymous_void_func")
        })
        .collect();
    assert!(!anonymous.is_empty());
    assert!(
        anonymous
            .iter()
            .any(|cu| cu.identifier() == "anonymous_helper")
    );

    let skeletons = analyzer.get_skeletons(&geometry_cpp);
    let anonymous_skeletons: Vec<_> = skeletons
        .iter()
        .filter(|(cu, _)| cu.is_function() && cu.short_name().contains("anonymous_"))
        .collect();
    assert!(!anonymous_skeletons.is_empty());
}

#[test]
fn test_cpp_overloads_and_signature_fields() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "simple_overloads.h",
    );
    let declarations = analyzer.get_declarations(&file);
    let overloads: Vec<_> = declarations
        .iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "overloadedFunction")
        .collect();
    assert_eq!(3, overloads.len());

    let signatures: BTreeSet<_> = overloads
        .iter()
        .map(|cu| cu.signature().unwrap_or("").to_string())
        .collect();
    assert_eq!(3, signatures.len());
    assert!(signatures.contains("(int)"));
    assert!(signatures.contains("(double)"));
    assert!(signatures.contains("(int, int)") || signatures.contains("(int,int)"));

    let defs = analyzer.get_definitions("overloadedFunction");
    let defs_here: Vec<_> = defs.into_iter().filter(|cu| cu.source() == &file).collect();
    assert_eq!(3, defs_here.len());

    let autocomplete = analyzer.autocomplete_definitions("overloadedFunction");
    assert!(autocomplete.len() >= 3);

    let namespace_file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "namespace_overloads.h",
    );
    let namespace_decls = analyzer.get_declarations(&namespace_file);
    let functions: Vec<_> = namespace_decls
        .iter()
        .filter(|cu| cu.is_function())
        .collect();
    assert!(functions.len() >= 4);
    for func in functions {
        assert!(func.signature().is_some());
        assert!(func.signature().unwrap().starts_with('('));
        assert!(!func.fq_name().contains('('));
        assert!(!func.short_name().contains('('));
        assert!(!func.fq_name().contains("ns.ns."));
    }
}

#[test]
fn test_cpp_duplicate_handling_and_definition_preference() {
    let analyzer = fixture_analyzer();
    let duplicates = ProjectFile::new(analyzer.project().root().to_path_buf(), "duplicates.h");
    let duplicate_decls = analyzer.get_declarations(&duplicates);
    assert!(!duplicate_decls.is_empty());
    let class_names: BTreeSet<_> = duplicate_decls
        .iter()
        .filter(|cu| cu.is_class())
        .map(|cu| cu.short_name().to_string())
        .collect();
    assert!(class_names.contains("ForwardDeclaredClass"));
    assert!(class_names.contains("ConditionalClass"));
    assert!(class_names.contains("TemplateClass"));
    assert!(class_names.contains("Point"));
    assert!(!analyzer.get_skeletons(&duplicates).is_empty());

    let dup_proto = ProjectFile::new(analyzer.project().root().to_path_buf(), "dupe_prototypes.h");
    let dup_proto_decls = analyzer.get_declarations(&dup_proto);
    let dup_funcs: Vec<_> = dup_proto_decls
        .iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "duplicated_function")
        .collect();
    assert_eq!(1, dup_funcs.len());
    assert!(
        analyzer
            .get_skeletons(&dup_proto)
            .contains_key(dup_funcs[0])
    );

    let forward_decl = ProjectFile::new(analyzer.project().root().to_path_buf(), "forward_decl.h");
    let skeletons = analyzer.get_skeletons(&forward_decl);
    let foo = skeletons
        .iter()
        .find(|(cu, _)| cu.is_function() && base_function_name(cu) == "foo")
        .unwrap();
    assert!(foo.1.contains("{...}"));
    let foo_count = skeletons
        .keys()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "foo")
        .count();
    assert_eq!(1, foo_count);
}

#[test]
fn test_cpp_include_resolution_and_c_file_support() {
    let analyzer = fixture_analyzer();
    let geometry_cpp = ProjectFile::new(analyzer.project().root().to_path_buf(), "geometry.cpp");
    let imports = analyzer.imported_code_units_of(&geometry_cpp);
    assert!(!imports.is_empty());
    assert!(imports.iter().any(|cu| cu.fq_name().contains("Point")));

    let c_file = ProjectFile::new(analyzer.project().root().to_path_buf(), "test_file.c");
    let declarations = analyzer.get_declarations(&c_file);
    assert!(!declarations.is_empty());
    assert!(
        declarations
            .iter()
            .any(|cu| cu.is_function() && base_function_name(cu) == "add_numbers")
    );
    assert!(
        declarations
            .iter()
            .any(|cu| cu.is_class() && cu.short_name() == "Point")
    );
}

/// The provider resolves an include the way the forward resolver's include
/// closure does: source-relative, then project-relative, then a *unique*
/// project header by suffix. A separate include root (`-I include`) is the
/// ordinary C++ layout, so `"helper.h"` from `src/main.cpp` is a real import
/// (#1829); an absolute path outside the project is not, and neither is a
/// basename two project headers answer to.
#[test]
fn test_cpp_imported_code_units_resolve_a_unique_project_header_and_refuse_the_rest() {
    let project = inline_cpp_project(&[
        (
            "src/main.cpp",
            r#"
            #include "helper.h"
            #include "/tmp/not-in-project.h"

            int main() { return 0; }
            "#,
        ),
        ("include/helper.h", "struct Helper {};"),
    ]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let main_cpp = ProjectFile::new(project.root().to_path_buf(), "src/main.cpp");

    let imports = analyzer.imported_code_units_of(&main_cpp);

    assert!(
        imports.iter().any(|cu| cu.short_name() == "Helper"),
        "a unique project header is reachable through its own include root: {imports:?}"
    );
    assert!(
        imports
            .iter()
            .all(|cu| cu.source().rel_path().ends_with("include/helper.h")),
        "an absolute include outside the project resolves to nothing: {imports:?}"
    );
}

#[test]
fn test_cpp_imported_code_units_refuse_an_ambiguous_include_basename() {
    let project = inline_cpp_project(&[
        (
            "src/main.cpp",
            r#"
            #include "helper.h"

            int main() { return 0; }
            "#,
        ),
        ("first/helper.h", "struct FirstHelper {};"),
        ("second/helper.h", "struct SecondHelper {};"),
    ]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let main_cpp = ProjectFile::new(project.root().to_path_buf(), "src/main.cpp");

    let imports = analyzer.imported_code_units_of(&main_cpp);

    assert!(
        imports.is_empty(),
        "two headers answer to this basename, so neither is the import: {imports:?}"
    );
}

#[test]
fn test_cpp_absolute_quoted_include_inside_project_is_normalized() {
    let project = inline_cpp_project(&[
        ("src/main.cpp", "int main() { return 0; }\n"),
        ("include/helper.h", "struct Helper {};"),
    ]);
    let root = project.root().to_path_buf();
    let helper_abs = root.join("include/helper.h");
    ProjectFile::new(root.clone(), "src/main.cpp")
        .write(format!(
            "#include \"{}\"\nint main() {{ return 0; }}\n",
            helper_abs.display()
        ))
        .unwrap();
    let analyzer = CppAnalyzer::from_project(project.clone());
    let main_cpp = ProjectFile::new(root, "src/main.cpp");

    let imports = analyzer.imported_code_units_of(&main_cpp);

    assert!(imports.iter().any(|cu| cu.short_name() == "Helper"));
}

#[test]
fn test_cpp_absolute_quoted_include_with_slash_normalization_inside_project() {
    let project = inline_cpp_project(&[
        ("src/main.cpp", "int main() { return 0; }\n"),
        ("include/helper.h", "struct Helper {};"),
    ]);
    let root = project.root().to_path_buf();
    let helper_abs = root.join("include/helper.h");
    let helper_slash_path = helper_abs.to_string_lossy().replace('\\', "/");
    ProjectFile::new(root.clone(), "src/main.cpp")
        .write(format!(
            "#include \"{}\"\nint main() {{ return 0; }}\n",
            helper_slash_path
        ))
        .unwrap();
    let analyzer = CppAnalyzer::from_project(project.clone());
    let main_cpp = ProjectFile::new(root, "src/main.cpp");

    let imports = analyzer.imported_code_units_of(&main_cpp);

    assert!(imports.iter().any(|cu| cu.short_name() == "Helper"));
}

#[test]
fn test_cpp_spaced_include_extraction_ignores_commented_out_includes() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("include/helper.h", "struct Helper {};\n")
        .file(
            "src/main.cpp",
            "/*\n# include \"commented.h\"\n*/\n// # include \"line_comment.h\"\n# include \"../include/helper.h\"\nint main() { return 0; }\n",
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let main_cpp = project.file("src/main.cpp");

    let imports = analyzer.import_statements_of(&main_cpp);
    assert_eq!(
        vec!["# include \"../include/helper.h\"".to_string()],
        imports
    );

    let imported = analyzer.imported_code_units_of(&main_cpp);
    assert!(imported.iter().any(|cu| cu.short_name() == "Helper"));
}

#[test]
fn test_cpp_qualifiers_templates_and_operators() {
    let analyzer = fixture_analyzer();
    let qualifiers = ProjectFile::new(analyzer.project().root().to_path_buf(), "qualifiers.h");
    let qualifier_decls = analyzer.get_declarations(&qualifiers);
    let f_overloads: Vec<_> = qualifier_decls
        .iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "f")
        .collect();
    assert!(f_overloads.len() >= 3);
    let signatures: BTreeSet<_> = f_overloads
        .iter()
        .map(|cu| cu.signature().unwrap_or("").to_string())
        .collect();
    assert!(signatures.len() >= 3);

    let qualifiers_extra = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "qualifiers_extra.h",
    );
    let extra_decls = analyzer.get_declarations(&qualifiers_extra);
    let extra_f: Vec<_> = extra_decls
        .iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "f")
        .collect();
    let extra_signatures: BTreeSet<_> = extra_f
        .iter()
        .map(|cu| cu.signature().unwrap_or("").to_string())
        .collect();
    assert!(extra_signatures.iter().any(|sig| sig.contains("volatile")));
    assert!(
        extra_signatures
            .iter()
            .any(|sig| sig.contains("const volatile"))
    );

    let template_fp = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "template_fpointers.h",
    );
    let template_decls = analyzer.get_declarations(&template_fp);
    let g = template_decls
        .iter()
        .find(|cu| cu.is_function() && base_function_name(cu) == "g")
        .unwrap();
    assert!(g.signature().unwrap_or("").contains("std::vector<int>"));

    let operators = ProjectFile::new(analyzer.project().root().to_path_buf(), "operators.h");
    let operator_decls = analyzer.get_declarations(&operators);
    let funcs: Vec<_> = operator_decls
        .iter()
        .filter(|cu| cu.is_function())
        .collect();
    assert!(
        funcs
            .iter()
            .any(|cu| base_function_name(cu) == "operator()")
    );
    assert!(
        funcs
            .iter()
            .any(|cu| base_function_name(cu) == "operator==")
    );
}

#[test]
fn test_struct_fields_enum_union_and_namespace_package_naming() {
    let analyzer = fixture_analyzer();
    let all = all_declarations(&analyzer);

    let geometry_h = ProjectFile::new(analyzer.project().root().to_path_buf(), "geometry.h");
    let geometry_skeletons = analyzer.get_skeletons(&geometry_h);
    let point = geometry_skeletons
        .iter()
        .find(|(cu, _)| cu.short_name() == "Point")
        .unwrap();
    assert!(point.1.contains("x"));
    assert!(point.1.contains("y"));

    let enums: Vec<_> = all
        .iter()
        .filter(|cu| cu.kind() == CodeUnitType::Class)
        .filter(|cu| {
            ["Color", "BlendMode", "Status", "WidgetType"]
                .iter()
                .any(|name| cu.short_name().contains(name))
        })
        .collect();
    assert!(!enums.is_empty());

    let unions: Vec<_> = all
        .iter()
        .filter(|cu| cu.kind() == CodeUnitType::Class)
        .filter(|cu| cu.short_name().contains("Pixel") || cu.short_name().contains("DataValue"))
        .collect();
    assert!(!unions.is_empty());

    let classes_with_namespaces: Vec<_> = all
        .iter()
        .filter(|cu| cu.kind() == CodeUnitType::Class && !cu.package_name().is_empty())
        .collect();
    assert!(
        classes_with_namespaces
            .iter()
            .filter(|cu| cu.package_name() == "graphics")
            .count()
            >= 2
    );
    assert!(
        classes_with_namespaces
            .iter()
            .any(|cu| cu.package_name() == "graphics" && cu.short_name().contains("Color"))
    );
    assert!(
        classes_with_namespaces
            .iter()
            .any(|cu| cu.package_name() == "graphics" && cu.short_name().contains("Renderer"))
    );
    assert!(
        classes_with_namespaces
            .iter()
            .any(|cu| cu.package_name() == "ui::widgets" && cu.short_name().contains("Widget"))
    );
}

#[test]
fn test_comprehensive_counts_specific_file_and_advanced_skeletons() {
    let analyzer = fixture_analyzer();
    let all = all_declarations(&analyzer);
    assert!(all.len() >= 10);
    assert!(all.iter().any(|cu| cu.kind() == CodeUnitType::Class));
    assert!(all.iter().any(|cu| cu.kind() == CodeUnitType::Function));

    let advanced = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "advanced_features.h",
    );
    let declarations = analyzer.get_declarations(&advanced);
    assert!(declarations.len() >= 5);

    let skeletons = analyzer.get_skeletons(&advanced);
    let graphics = skeletons
        .iter()
        .find(|(cu, _)| cu.kind() == CodeUnitType::Module && cu.fq_name() == "graphics")
        .unwrap();
    assert!(graphics.1.contains("Color"));
}

#[test]
fn test_autocomplete_preserves_overloads() {
    let analyzer = fixture_analyzer();
    let results = analyzer.autocomplete_definitions("overloadedFunction");
    let overloads: Vec<_> = results
        .into_iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "overloadedFunction")
        .collect();
    assert_eq!(6, overloads.len());

    let signatures: BTreeSet<_> = overloads
        .iter()
        .map(|cu| cu.signature().unwrap_or("").replace(", ", ","))
        .collect();
    assert_eq!(3, signatures.len());
    assert!(signatures.contains("(int)"));
    assert!(signatures.contains("(double)"));
    assert!(signatures.contains("(int,int)"));
}

#[test]
fn test_anonymous_struct_and_parse_once_equivalence() {
    let analyzer = fixture_analyzer();
    let advanced = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "advanced_features.h",
    );
    let declarations = analyzer.get_declarations(&advanced);
    assert!(!declarations.is_empty());
    assert!(
        declarations
            .iter()
            .any(|cu| cu.is_class() && cu.short_name().contains("Pixel"))
    );
    let skeletons = analyzer.get_skeletons(&advanced);
    assert!(!skeletons.is_empty());

    let geometry_cpp = ProjectFile::new(analyzer.project().root().to_path_buf(), "geometry.cpp");
    let first = analyzer.get_skeletons(&geometry_cpp);
    let second = analyzer.get_skeletons(&geometry_cpp);
    assert_eq!(first, second);
}

#[test]
fn test_function_pointer_and_template_parameter_parsing() {
    let analyzer = fixture_analyzer();
    let overload_edgecases = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "overload_edgecases.h",
    );
    let overloads = analyzer
        .get_declarations(&overload_edgecases)
        .into_iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "f")
        .collect::<Vec<_>>();
    assert_eq!(2, overloads.len());
    let signatures: BTreeSet<_> = overloads
        .iter()
        .map(|cu| cu.signature().unwrap_or("").to_string())
        .collect();
    assert!(
        signatures
            .iter()
            .any(|sig| sig.contains("map") || sig.contains("std::map"))
    );
    assert!(
        signatures
            .iter()
            .any(|sig| sig.contains("pair") || sig.contains("std::pair"))
    );

    let function_pointers = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "function_pointers.h",
    );
    let funcs = analyzer.get_declarations(&function_pointers);
    assert!(
        funcs
            .iter()
            .any(|cu| cu.is_function() && base_function_name(cu) == "g")
    );
    assert!(
        funcs
            .iter()
            .any(|cu| cu.is_function() && base_function_name(cu) == "h")
    );
}

#[test]
fn test_cpp_arrow_adaptive_builder_header_regression() {
    let project = inline_cpp_project(&[(
        ".venv/lib/python3.12/site-packages/pyarrow/include/arrow/array/builder_adaptive.h",
        r#"
namespace arrow {
namespace internal {

struct Status {};
struct ResizableBuffer {};
template <bool Cond, typename T>
struct enable_if {
  using type = T;
};

class AdaptiveIntBuilderBase {
 public:
  AdaptiveIntBuilderBase(unsigned char start_int_size, void* pool, long long alignment = 8);

 protected:
  template <typename new_type, typename old_type>
  typename enable_if<sizeof(old_type) >= sizeof(new_type), Status>::type
  ExpandIntSizeInternal();
  template <typename new_type, typename old_type>
  typename enable_if<(sizeof(old_type) < sizeof(new_type)), Status>::type
  ExpandIntSizeInternal();

  ResizableBuffer* data_;
  unsigned char* raw_data_ = NULLPTR;

  const unsigned char start_int_size_;
  unsigned char int_size_;

  static constexpr int pending_size_ = 1024;
  unsigned char pending_valid_[pending_size_];
  unsigned long long pending_data_[pending_size_];
  int pending_pos_ = 0;
  bool pending_has_nulls_ = false;
};

}  // namespace internal
}  // namespace arrow
"#,
    )]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(
        project.root().to_path_buf(),
        ".venv/lib/python3.12/site-packages/pyarrow/include/arrow/array/builder_adaptive.h",
    );

    let declarations = analyzer.get_declarations(&file);
    assert!(
        declarations
            .iter()
            .any(|cu| cu.is_class() && cu.short_name().contains("AdaptiveIntBuilderBase"))
    );

    let fields: BTreeSet<_> = declarations
        .iter()
        .filter(|cu| cu.kind() == CodeUnitType::Field)
        .map(|cu| cu.short_name().to_string())
        .collect();
    assert!(fields.contains("AdaptiveIntBuilderBase.data_"));
    assert!(fields.contains("AdaptiveIntBuilderBase.raw_data_"));
    assert!(fields.contains("AdaptiveIntBuilderBase.start_int_size_"));
    assert!(fields.contains("AdaptiveIntBuilderBase.int_size_"));
    assert!(fields.contains("AdaptiveIntBuilderBase.pending_size_"));
    assert!(fields.contains("AdaptiveIntBuilderBase.pending_valid_"));
    assert!(fields.contains("AdaptiveIntBuilderBase.pending_data_"));
    assert!(fields.contains("AdaptiveIntBuilderBase.pending_pos_"));
    assert!(fields.contains("AdaptiveIntBuilderBase.pending_has_nulls_"));
    assert!(!fields.iter().any(|name| name.is_empty()));
}

#[test]
fn cpp_declarations_survive_namespace_macro_statements() {
    let source = r#"
#ifndef VERSIONED_H
#define VERSIONED_H
namespace openvdb {
OPENVDB_USE_VERSION_NAMESPACE
namespace OPENVDB_VERSION_NAME {
namespace ax {
class Logger {
public:
    bool atErrorLimit() const;
};
}
}
}
#endif
"#;
    let project = inline_cpp_project(&[("versioned.h", source)]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "versioned.h");
    let declarations = analyzer.get_declarations(&file);

    assert!(
        declarations
            .iter()
            .any(|cu| cu.is_class() && cu.identifier() == "Logger"),
        "{declarations:#?}"
    );
    assert!(
        declarations
            .iter()
            .any(|cu| cu.is_function() && base_function_name(cu) == "atErrorLimit"),
        "{declarations:#?}"
    );
}

#[test]
fn test_constructor_destructor_scoped_definition_and_decl_vs_def_behavior() {
    let analyzer = fixture_analyzer();
    let ctor_dtor = ProjectFile::new(analyzer.project().root().to_path_buf(), "ctor_dtor.h");
    let decls = analyzer.get_declarations(&ctor_dtor);
    assert!(
        decls
            .iter()
            .any(|cu| cu.is_function() && base_function_name(cu) == "T")
    );
    assert!(
        decls
            .iter()
            .any(|cu| cu.is_function() && base_function_name(cu).starts_with("~T"))
    );

    let scoped_def = ProjectFile::new(analyzer.project().root().to_path_buf(), "scoped_def.cpp");
    let scoped = analyzer.get_declarations(&scoped_def);
    assert!(
        scoped
            .iter()
            .any(|cu| cu.is_function() && base_function_name(cu) == "m")
    );

    let decl_vs_def = ProjectFile::new(analyzer.project().root().to_path_buf(), "decl_vs_def.h");
    let decls = analyzer.get_declarations(&decl_vs_def);
    let out_of_line: Vec<_> = decls
        .iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "declaration_only")
        .filter(|cu| cu.fq_name().contains("DeclVsDef.declaration_only"))
        .collect();
    let unique_sigs: BTreeSet<_> = out_of_line.iter().filter_map(|cu| cu.signature()).collect();
    assert_eq!(1, unique_sigs.len());

    let skeletons = analyzer.get_skeletons(&decl_vs_def);
    let func_skeleton = skeletons
        .iter()
        .find(|(cu, _)| cu.is_function() && base_function_name(cu) == "declaration_only")
        .unwrap();
    assert!(func_skeleton.1.contains("{...}"));

    let class_skeleton = skeletons
        .iter()
        .find(|(cu, _)| cu.is_class() && cu.short_name().contains("DeclVsDef"))
        .map(|(_, skeleton)| skeleton)
        .unwrap();
    let decl_line = class_skeleton
        .lines()
        .find(|line| line.contains("declaration_only") && !line.contains("::"))
        .unwrap_or("");
    assert!(!decl_line.contains("{...}") && !decl_line.contains('{'));
}

#[test]
fn cpp_signature_metadata_labels_unnamed_pointer_parameters() {
    let project = inline_cpp_project(&[(
        "unnamed.hpp",
        r#"
        void consume(int*, int (*)());
        "#,
    )]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let function = analyzer
        .get_declarations(&ProjectFile::new(
            project.root().to_path_buf(),
            "unnamed.hpp",
        ))
        .into_iter()
        .find(|cu| cu.is_function() && base_function_name(cu) == "consume")
        .unwrap();
    let metadata = analyzer
        .signature_metadata(&function)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing metadata for {}", function.fq_name()));
    let labels: Vec<_> = metadata
        .parameters()
        .iter()
        .map(|parameter| &metadata.label()[parameter.start_byte()..parameter.end_byte()])
        .collect();
    assert_eq!(vec!["int*", "int (*)()"], labels);
}

#[test]
fn cpp_signature_metadata_records_optional_and_variadic_callable_arity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "callables.hpp",
            r#"
            void trace(const char *fmt, ...);
            void optional(int required, int value = 0);
            template<typename... Args>
            void pack(int required, Args... rest);
            "#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let declarations = analyzer.get_declarations(&project.file("callables.hpp"));

    for name in ["trace", "pack"] {
        let function = declarations
            .iter()
            .find(|unit| unit.is_function() && base_function_name(unit) == name)
            .unwrap_or_else(|| panic!("missing declaration for {name}: {declarations:#?}"));
        assert!(
            function
                .signature()
                .is_some_and(|signature| signature.contains("...")),
            "variadic marker missing from {name} signature: {function:#?}"
        );
    }

    let arity_for = |name: &str| {
        let function = declarations
            .iter()
            .find(|unit| unit.is_function() && base_function_name(unit) == name)
            .unwrap_or_else(|| panic!("missing declaration for {name}: {declarations:#?}"));
        analyzer
            .signature_metadata(function)
            .into_iter()
            .find_map(|metadata| metadata.callable_arity())
            .unwrap_or_else(|| panic!("missing callable arity for {}", function.fq_name()))
    };

    let trace = arity_for("trace");
    assert!(!trace.accepts(0));
    assert!(trace.accepts(1));
    assert!(trace.accepts(3));

    let optional = arity_for("optional");
    assert!(!optional.accepts(0));
    assert!(optional.accepts(1));
    assert!(optional.accepts(2));
    assert!(!optional.accepts(3));

    let pack = arity_for("pack");
    assert!(!pack.accepts(0));
    assert!(pack.accepts(1));
    assert!(pack.accepts(3));
}

#[test]
fn cpp_signature_metadata_persists_structured_return_types_for_declarations_and_definitions() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "returns.hpp",
            r#"#define BASE_EXPORT
struct T {
    T* pointer();
    T& reference();
    auto trailing() -> T*;
    BASE_EXPORT T* exported();
};
"#,
        )
        .file(
            "returns.cc",
            r#"#include "returns.hpp"
T* T::pointer() { return this; }
T& T::reference() { return *this; }
auto T::trailing() -> T* { return this; }
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    for (name, expected) in [("pointer", "T*"), ("reference", "T&"), ("trailing", "T*")] {
        let callables = analyzer
            .get_all_declarations()
            .iter()
            .filter(|unit| unit.is_function() && unit.fq_name() == format!("T.{name}"))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            callables.len(),
            2,
            "fixture must retain declaration and definition for {name}: {callables:#?}"
        );
        for callable in callables {
            let metadata = analyzer.signature_metadata(&callable);
            let return_types = metadata
                .iter()
                .filter_map(|metadata| metadata.return_type_text().map(str::to_owned))
                .collect::<BTreeSet<_>>();
            assert_eq!(
                return_types,
                BTreeSet::from([expected.to_owned()]),
                "persisted return type for {callable:#?}"
            );
            let identities = metadata
                .iter()
                .filter_map(|metadata| metadata.return_type_identity())
                .collect::<Vec<_>>();
            assert_eq!(identities.len(), 1, "structured return identity");
            assert_eq!(
                identities[0]
                    .nominal_name()
                    .expect("nominal return type")
                    .path(),
                &["T".to_string()],
                "AST-derived return path for {callable:#?}"
            );
            let wrapper_matches = match name {
                "pointer" | "trailing" => identities[0].is_pointer(),
                "reference" => identities[0].is_reference(),
                _ => false,
            };
            assert!(
                wrapper_matches,
                "AST-derived return wrapper for {callable:#?}: {:?}",
                identities[0]
            );
        }
    }
    let exported = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.is_function() && unit.fq_name() == "T.exported")
        .expect("macro-decorated exported declaration");
    assert!(
        analyzer
            .signature_metadata(&exported)
            .iter()
            .all(|metadata| {
                metadata.return_type_text().is_none() && metadata.return_type_identity().is_none()
            }),
        "the export macro token must not be persisted as the callable return type"
    );
}

#[test]
fn cpp_signature_metadata_anchors_multi_declarator_parameters() {
    let project = inline_cpp_project(&[(
        "multi.hpp",
        r#"
        void a(int value), b(int value);
        "#,
    )]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let function = analyzer
        .get_declarations(&ProjectFile::new(project.root().to_path_buf(), "multi.hpp"))
        .into_iter()
        .find(|cu| cu.is_function() && base_function_name(cu) == "b")
        .unwrap();
    let metadata = analyzer
        .signature_metadata(&function)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing metadata for {}", function.fq_name()));
    let parameter = metadata
        .parameters()
        .first()
        .unwrap_or_else(|| panic!("missing parameter metadata for {}", metadata.label()));
    assert_eq!(
        "value",
        &metadata.label()[parameter.start_byte()..parameter.end_byte()]
    );
    assert!(
        parameter.start_byte() > metadata.label().find("b(").expect("b declarator"),
        "parameter offset should point inside b declarator, got {} with {parameter:?}",
        metadata.label()
    );
}

#[test]
fn test_namespaced_overloaded_fq_names_and_signature_population() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "namespace_overloads.h",
    );
    let decls = analyzer.get_declarations(&file);
    assert!(!decls.is_empty());

    let free_funcs: Vec<_> = decls
        .iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "free_func")
        .collect();
    assert_eq!(2, free_funcs.len());
    for cu in &free_funcs {
        assert_eq!("ns", cu.package_name());
        assert!(!cu.fq_name().contains("ns.ns."));
        assert!(cu.fq_name().starts_with("ns."));
        assert!(!cu.short_name().starts_with("ns."));
        assert!(cu.signature().is_some());
        assert!(cu.signature().unwrap().starts_with('('));
        assert!(!cu.fq_name().contains('('));
        assert!(!cu.short_name().contains('('));
    }

    let methods: Vec<_> = decls
        .iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "method")
        .collect();
    assert_eq!(2, methods.len());
    for cu in &methods {
        assert_eq!("ns", cu.package_name());
        assert!(!cu.fq_name().contains("ns.ns."));
        assert!(cu.fq_name().starts_with("ns."));
        assert!(!cu.short_name().starts_with("ns."));
        assert!(cu.signature().is_some());
    }

    let free_func_int = free_funcs
        .iter()
        .find(|cu| cu.short_name() == "free_func" && cu.signature().unwrap_or("").contains("int"))
        .unwrap();
    assert_eq!("(int)", free_func_int.signature().unwrap());
    assert_eq!("ns.free_func", free_func_int.fq_name());

    let method_int = methods
        .iter()
        .find(|cu| cu.short_name() == "C.method" && cu.signature().unwrap_or("").contains("int"))
        .unwrap();
    assert_eq!("(int)", method_int.signature().unwrap());
    assert_eq!("ns.C.method", method_int.fq_name());
}

#[test]
fn test_definition_vs_declaration_detection_and_stable_definitions() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "decl_vs_def.h");
    let skeletons = analyzer.get_skeletons(&file);
    let class_skeleton = skeletons
        .iter()
        .find(|(cu, _)| cu.is_class() && cu.short_name().contains("DeclVsDef"))
        .map(|(_, skeleton)| skeleton)
        .unwrap();
    assert!(class_skeleton.contains("void declaration_only()"));
    let declaration_only_line = class_skeleton
        .lines()
        .find(|line| line.contains("declaration_only") && !line.contains("::"))
        .unwrap_or("");
    assert!(!declaration_only_line.contains("{...}") && !declaration_only_line.contains('{'));
    let inline_definition_line = class_skeleton
        .lines()
        .find(|line| line.contains("inline_definition"))
        .unwrap_or("");
    assert!(inline_definition_line.contains('{'));

    let out_of_line = skeletons
        .iter()
        .find(|(cu, skel)| {
            cu.is_function()
                && base_function_name(cu) == "declaration_only"
                && skel.contains("DeclVsDef::")
        })
        .unwrap();
    assert!(out_of_line.1.contains("{...}"));

    let defs = analyzer.get_definitions("overloadedFunction");
    assert!(defs.len() >= 3);
    let signatures: BTreeSet<_> = defs.iter().filter_map(|cu| cu.signature()).collect();
    assert!(!signatures.is_empty());
    assert!(signatures.len() >= 2);
}

#[test]
fn test_inline_template_class_and_function_overload_cases() {
    let project = inline_cpp_project(&[(
        "templates.hpp",
        r#"
        template <typename T>
        struct TemplateStruct;

        template <typename T>
        struct TemplateStruct {
            T value;
        };

        template <typename T, typename U>
        struct TemplateStruct {
            T t;
            U u;
        };

        struct TemplateStruct {
            int x;
        };
        "#,
    )]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "templates.hpp");
    let declarations: Vec<_> = analyzer
        .get_declarations(&file)
        .into_iter()
        .filter(|cu| cu.short_name() == "TemplateStruct" && cu.kind() == CodeUnitType::Class)
        .collect();
    assert_eq!(3, declarations.len());
    let signatures: BTreeSet<_> = declarations.iter().map(|cu| cu.signature()).collect();
    assert!(signatures.contains(&Some("<typename T>")));
    assert!(signatures.contains(&Some("<typename T, typename U>")));
    assert_eq!(
        1,
        declarations
            .iter()
            .filter(|cu| cu.signature().is_none())
            .count()
    );
    let single_t = declarations
        .iter()
        .find(|cu| cu.signature() == Some("<typename T>"))
        .unwrap();
    assert!(
        analyzer
            .get_skeleton(single_t)
            .unwrap()
            .contains("T value;")
    );

    let project = inline_cpp_project(&[(
        "function_templates.h",
        r#"
        template <class... Args>
        void process(const Args&... args) {}

        void process(int x) {}

        template <typename T>
        void process(const T& value, int count) {}
        "#,
    )]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "function_templates.h");
    let overloads: Vec<_> = analyzer
        .get_declarations(&file)
        .into_iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "process")
        .collect();
    assert_eq!(3, overloads.len());
    let signatures: BTreeSet<_> = overloads.iter().filter_map(|cu| cu.signature()).collect();
    assert_eq!(3, signatures.len());
    assert!(signatures.iter().any(|sig| sig.contains("<class... Args>")));
    assert!(signatures.iter().any(|sig| sig.contains("<typename T>")));
    assert!(signatures.iter().any(|sig| sig.starts_with('(')));
}

#[test]
fn test_inline_template_constructor_and_anonymous_parameter_cases() {
    let project = inline_cpp_project(&[(
        "ctor_templates.hpp",
        r#"
        template <typename T>
        class Container {
        public:
            Container(T value) : val(value) {}
        private:
            T val;
        };

        template <typename T, typename U>
        class PairContainer {
        public:
            PairContainer(T t, U u) : first(t), second(u) {}
        private:
            T first;
            U second;
        };
        "#,
    )]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "ctor_templates.hpp");
    let declarations: Vec<_> = analyzer
        .get_declarations(&file)
        .into_iter()
        .filter(|cu| cu.is_function())
        .collect();
    let container_ctor = declarations
        .iter()
        .find(|cu| cu.fq_name().ends_with("Container.Container"))
        .unwrap();
    let pair_ctor = declarations
        .iter()
        .find(|cu| cu.fq_name().ends_with("PairContainer.PairContainer"))
        .unwrap();
    assert!(
        container_ctor
            .signature()
            .unwrap_or("")
            .starts_with("<typename T>")
    );
    assert!(
        pair_ctor
            .signature()
            .unwrap_or("")
            .starts_with("<typename T, typename U>")
    );

    let project = inline_cpp_project(&[(
        "anonymous_overloads.hpp",
        r#"
        template <class T>
        struct TestContainer {
            static int foo(std::vector<double*> /*a*/) { return 1; }
            static int foo(std::vector<int*> /*a*/) { return 2; }
            static int foo(std::vector<double**> /*a*/) { return 3; }

            static int bar(std::map<int, double> /*x*/) { return 1; }
            static int bar(std::map<int, int> /*x*/) { return 2; }
        };
        "#,
    )]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "anonymous_overloads.hpp");
    let declarations = analyzer.get_declarations(&file);
    let foo: Vec<_> = declarations
        .iter()
        .filter(|cu| base_function_name(cu) == "foo")
        .collect();
    assert_eq!(3, foo.len());
    let foo_sigs: BTreeSet<_> = foo.iter().filter_map(|cu| cu.signature()).collect();
    assert_eq!(3, foo_sigs.len());
    assert!(foo_sigs.iter().any(|sig| sig.contains("vector<double*>")));
    assert!(foo_sigs.iter().any(|sig| sig.contains("vector<int*>")));
    assert!(foo_sigs.iter().any(|sig| sig.contains("vector<double**>")));

    let bar: Vec<_> = declarations
        .iter()
        .filter(|cu| base_function_name(cu) == "bar")
        .collect();
    assert_eq!(2, bar.len());
    let bar_sigs: BTreeSet<_> = bar.iter().filter_map(|cu| cu.signature()).collect();
    assert_eq!(2, bar_sigs.len());
    assert!(
        bar_sigs
            .iter()
            .any(|sig| sig.contains("std::map<int,double>"))
    );
    assert!(bar_sigs.iter().any(|sig| sig.contains("std::map<int,int>")));
}

#[test]
fn test_inline_field_initializer_parity_cases() {
    let project = inline_cpp_project(&[(
        "multifield.hpp",
        r#"
        struct MultiField {
            int x = 1, y = 2;
            static inline double a = 0.5, b = 1.5;
        };
        "#,
    )]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "multifield.hpp");
    let fields: Vec<_> = analyzer
        .get_declarations(&file)
        .into_iter()
        .filter(|cu| cu.is_field())
        .collect();
    assert_eq!(4, fields.len());
    let x = fields
        .iter()
        .find(|cu| cu.short_name().ends_with("x"))
        .unwrap();
    let y = fields
        .iter()
        .find(|cu| cu.short_name().ends_with("y"))
        .unwrap();
    let a = fields
        .iter()
        .find(|cu| cu.short_name().ends_with("a"))
        .unwrap();
    let b = fields
        .iter()
        .find(|cu| cu.short_name().ends_with("b"))
        .unwrap();
    assert_code_eq("int x = 1;", &analyzer.get_skeleton(x).unwrap());
    assert_code_eq("int y = 2;", &analyzer.get_skeleton(y).unwrap());
    assert_code_eq(
        "static inline double a = 0.5;",
        &analyzer.get_skeleton(a).unwrap(),
    );
    assert_code_eq(
        "static inline double b = 1.5;",
        &analyzer.get_skeleton(b).unwrap(),
    );

    let project = inline_cpp_project(&[(
        "initializer_assoc.hpp",
        r#"
        struct MultiField {
            int x = f(1, 2), y = g();
            int* p = &x, q = nullptr;
            int a, b = 2;
        };
        "#,
    )]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "initializer_assoc.hpp");
    let fields: Vec<_> = analyzer
        .get_declarations(&file)
        .into_iter()
        .filter(|cu| cu.is_field())
        .collect();
    let x = fields
        .iter()
        .find(|cu| cu.short_name().ends_with("x"))
        .unwrap();
    let y = fields
        .iter()
        .find(|cu| cu.short_name().ends_with("y"))
        .unwrap();
    let p = fields
        .iter()
        .find(|cu| cu.short_name().ends_with("p"))
        .unwrap();
    let q = fields
        .iter()
        .find(|cu| cu.short_name().ends_with("q"))
        .unwrap();
    let a = fields
        .iter()
        .find(|cu| cu.short_name().ends_with("a"))
        .unwrap();
    let b = fields
        .iter()
        .find(|cu| cu.short_name().ends_with("b"))
        .unwrap();
    assert_code_eq("int x;", &analyzer.get_skeleton(x).unwrap());
    assert_code_eq("int y;", &analyzer.get_skeleton(y).unwrap());
    assert_code_eq("int* p;", &analyzer.get_skeleton(p).unwrap());
    assert_code_eq("int* q;", &analyzer.get_skeleton(q).unwrap());
    assert_code_eq("int a;", &analyzer.get_skeleton(a).unwrap());
    assert_code_eq("int b = 2;", &analyzer.get_skeleton(b).unwrap());

    let project = inline_cpp_project(&[(
        "fields.hpp",
        r#"
        struct ComplexFields {
            int x = 1;
            int y = f(1, 2);
            static inline auto z = SomeBuilder().build();
        };
        "#,
    )]);
    let analyzer = CppAnalyzer::from_project(project);
    let x = analyzer
        .get_definitions("ComplexFields.x")
        .into_iter()
        .next()
        .unwrap();
    let y = analyzer
        .get_definitions("ComplexFields.y")
        .into_iter()
        .next()
        .unwrap();
    let z = analyzer
        .get_definitions("ComplexFields.z")
        .into_iter()
        .next()
        .unwrap();
    assert_code_eq("int x = 1;", &analyzer.get_skeleton(&x).unwrap());
    assert_code_eq("int y;", &analyzer.get_skeleton(&y).unwrap());
    assert_code_eq("static inline auto z;", &analyzer.get_skeleton(&z).unwrap());
}

#[test]
fn cpp_analyzer_indexes_macros_and_pointer_returning_prototypes() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "src/detection/codec/codec.h",
            r#"#pragma once
#include "common/option.h"

#define FF_CODEC_UNKNOWN 0
#define FF_CODEC_NAME(x) ffCodecName_##x
#define FF_AUTO_CLOSE(name) \
    do { \
        close(name); \
    } while (0)

const char* ffDetectCodec(void);
"#,
        )
        .file(
            "src/detection/bootmgr/bootmgr_apple.c",
            r#"#include "bootmgr.h"

const char* ffDetectBootmgr(FFBootmgrResult* result) {
    return "iBoot";
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());

    let header = project.file("src/detection/codec/codec.h");
    let header_decls = analyzer.get_declarations(&header);
    assert!(
        header_decls
            .iter()
            .any(|cu| cu.kind() == CodeUnitType::Macro && cu.short_name() == "FF_CODEC_UNKNOWN"),
        "{header_decls:#?}"
    );
    assert!(
        header_decls
            .iter()
            .any(|cu| cu.kind() == CodeUnitType::Macro && cu.short_name() == "FF_AUTO_CLOSE"),
        "{header_decls:#?}"
    );
    let prototype = header_decls
        .iter()
        .find(|cu| cu.kind() == CodeUnitType::Function && base_function_name(cu) == "ffDetectCodec")
        .unwrap();
    assert_eq!(Some("(void)"), prototype.signature());
    let prototype_skeleton = analyzer.get_skeleton(prototype).unwrap();
    assert!(
        prototype_skeleton.contains("const char* ffDetectCodec(void);"),
        "{prototype_skeleton}"
    );

    let source = project.file("src/detection/bootmgr/bootmgr_apple.c");
    let source_decls = analyzer.get_declarations(&source);
    let definition = source_decls
        .iter()
        .find(|cu| {
            cu.kind() == CodeUnitType::Function && base_function_name(cu) == "ffDetectBootmgr"
        })
        .unwrap();
    let source_skeleton = analyzer.get_skeleton(definition).unwrap();
    assert!(
        source_skeleton.contains("const char* ffDetectBootmgr(FFBootmgrResult* result)"),
        "{source_skeleton}"
    );
}

#[test]
fn test_extended_qualifier_and_operator_details() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "qualifiers_extra.h",
    );
    let decls = analyzer.get_declarations(&file);
    let f_signatures: BTreeSet<_> = decls
        .iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "f")
        .filter_map(|cu| cu.signature())
        .collect();
    assert!(
        f_signatures
            .iter()
            .any(|sig| sig.contains("volatile") && !sig.contains("const volatile"))
    );
    assert!(
        f_signatures
            .iter()
            .any(|sig| sig.contains("const volatile"))
    );
    assert!(f_signatures.iter().any(|sig| sig.contains('&')));
    assert!(f_signatures.iter().any(|sig| sig.contains("&&")));

    let h_signatures: BTreeSet<_> = decls
        .iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "h")
        .filter_map(|cu| cu.signature())
        .collect();
    assert!(
        h_signatures
            .iter()
            .any(|sig| sig.contains("noexcept(true)"))
    );
    assert!(
        h_signatures
            .iter()
            .any(|sig| sig.contains("noexcept(false)"))
    );

    let operators = ProjectFile::new(analyzer.project().root().to_path_buf(), "operators.h");
    let funcs: Vec<_> = analyzer
        .get_declarations(&operators)
        .into_iter()
        .filter(|cu| cu.is_function())
        .collect();
    let member_call_ops: Vec<_> = funcs
        .iter()
        .filter(|cu| base_function_name(cu) == "operator()")
        .collect();
    assert!(!member_call_ops.is_empty());
    assert!(
        member_call_ops
            .iter()
            .filter_map(|cu| cu.signature())
            .any(|sig| sig.contains("const"))
    );

    let non_member_eq: Vec<_> = funcs
        .iter()
        .filter(|cu| base_function_name(cu) == "operator==" && cu.package_name().is_empty())
        .collect();
    assert!(!non_member_eq.is_empty());
    assert!(
        non_member_eq
            .iter()
            .filter_map(|cu| cu.signature())
            .any(|sig| sig.contains("int"))
    );
}

#[test]
fn test_inline_template_class_constructor_signatures() {
    let project = inline_cpp_project(&[(
        "template_ctors.hpp",
        r#"
        template <class IdxSeq, class... ValueTypes>
        struct CombinedReducerValue;

        template <size_t... Idxs, class... ValueTypes>
        struct CombinedReducerValue<void, ValueTypes...> {
            CombinedReducerValue() = default;
            CombinedReducerValue(ValueTypes... args);
        };

        template <class T>
        struct CombinedReducerValue<T, int> {
            CombinedReducerValue() = default;
            CombinedReducerValue(int x);
        };
        "#,
    )]);
    let analyzer = CppAnalyzer::from_project(project.clone());
    let file = ProjectFile::new(project.root().to_path_buf(), "template_ctors.hpp");
    let declarations: Vec<_> = analyzer
        .get_declarations(&file)
        .into_iter()
        .filter(|cu| cu.is_function() && base_function_name(cu) == "CombinedReducerValue")
        .collect();
    assert!(declarations.len() >= 4);
    let signatures: BTreeSet<_> = declarations
        .iter()
        .filter_map(|cu| cu.signature())
        .collect();
    assert!(signatures.len() >= 2);
    assert!(
        signatures
            .iter()
            .any(|sig| sig.contains("size_t... Idxs") || sig.contains("class... ValueTypes"))
    );
    assert!(signatures.iter().any(|sig| sig.contains("<class T>")));
}

#[test]
fn cpp_template_alias_is_indexed_once_with_lexical_namespace_identity() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "canonical.h",
            r#"#pragma once
namespace jni_zero {
template <typename T>
class ScopedJavaGlobalRef {};
class Plain {};
}
"#,
        )
        .file(
            "aliases.h",
            r#"#pragma once
#include "canonical.h"
namespace base::android {
using Plain = jni_zero::Plain;
template <typename T = int>
using ScopedJavaGlobalRef = jni_zero::ScopedJavaGlobalRef<T>;
}
"#,
        )
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let aliases = analyzer
        .get_declarations(&project.file("aliases.h"))
        .into_iter()
        .filter(|unit| matches!(unit.identifier(), "Plain" | "ScopedJavaGlobalRef"))
        .collect::<Vec<_>>();

    assert_eq!(
        aliases.len(),
        2,
        "template wrapper and ordinary traversal must not emit duplicate aliases: {aliases:#?}"
    );
    let plain = aliases
        .iter()
        .find(|unit| unit.identifier() == "Plain")
        .expect("plain alias");
    let template = aliases
        .iter()
        .find(|unit| unit.identifier() == "ScopedJavaGlobalRef")
        .expect("template alias");
    for alias in [plain, template] {
        assert_eq!(alias.kind(), CodeUnitType::Class);
        assert_eq!(alias.package_name(), "base::android");
        assert!(analyzer.is_type_alias(alias));
        assert!(!alias.is_synthetic());
    }
    assert_eq!(plain.fq_name(), "base::android.Plain");
    assert_eq!(template.fq_name(), "base::android.ScopedJavaGlobalRef");
    assert_eq!(
        analyzer.get_source(template, false).as_deref(),
        Some("using ScopedJavaGlobalRef = jni_zero::ScopedJavaGlobalRef<T>;")
    );
    assert_eq!(
        template.signature(),
        Some("using ScopedJavaGlobalRef = jni_zero::ScopedJavaGlobalRef<T>;")
    );
}
