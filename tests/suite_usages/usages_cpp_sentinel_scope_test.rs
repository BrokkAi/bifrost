use crate::common::InlineTestProject;
use brokk_bifrost::usages::{ExplicitCandidateProvider, FuzzyResult, UsageFinder};
use brokk_bifrost::{CodeUnit, CodeUnitIndex, CodeUnitType, CppAnalyzer, Language, ProjectFile};
use std::collections::BTreeSet;
use std::sync::Arc;

type SourceRange = (usize, usize);
type UsageRanges = (BTreeSet<SourceRange>, BTreeSet<SourceRange>);

fn definition_by<F>(analyzer: &CppAnalyzer, mut predicate: F) -> CodeUnit
where
    F: FnMut(&CodeUnit) -> bool,
{
    let declarations = analyzer.get_all_declarations();
    declarations
        .iter()
        .find(|unit| predicate(unit))
        .cloned()
        .unwrap_or_else(|| panic!("missing matching C++ declaration in {declarations:#?}"))
}

fn authoritative_ranges(
    analyzer: &CppAnalyzer,
    target: &CodeUnit,
    candidate: &ProjectFile,
) -> UsageRanges {
    let provider =
        ExplicitCandidateProvider::new(Arc::new(std::iter::once(candidate.clone()).collect()));
    let query = UsageFinder::new()
        .with_authoritative_scope(true)
        .query_with_provider(
            analyzer,
            std::slice::from_ref(target),
            Some(&provider),
            1,
            1000,
        );
    assert_eq!(
        query.candidate_files,
        std::iter::once(candidate.clone()).collect(),
        "authoritative query must remain limited to the fixture file"
    );
    let FuzzyResult::Success {
        hits_by_overload,
        unproven_by_overload,
        ..
    } = query.result
    else {
        panic!("expected authoritative C++ success")
    };
    let proven = hits_by_overload
        .values()
        .flatten()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect();
    let unproven = unproven_by_overload
        .values()
        .flatten()
        .map(|hit| (hit.start_offset, hit.end_offset))
        .collect();
    (proven, unproven)
}

fn token_range(source: &str, line: &str, token: &str) -> SourceRange {
    let line_start = source
        .find(line)
        .unwrap_or_else(|| panic!("missing fixture line {line:?}"));
    let token_start = line
        .find(token)
        .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {line:?}"));
    let start = line_start + token_start;
    (start, start + token.len())
}

fn last_token_range(source: &str, line: &str, token: &str) -> SourceRange {
    let line_start = source
        .find(line)
        .unwrap_or_else(|| panic!("missing fixture line {line:?}"));
    let token_start = line
        .rfind(token)
        .unwrap_or_else(|| panic!("missing token {token:?} in fixture line {line:?}"));
    let start = line_start + token_start;
    (start, start + token.len())
}

fn contains_range(ranges: &BTreeSet<SourceRange>, expected: SourceRange) -> bool {
    ranges
        .iter()
        .any(|(start, end)| *start <= expected.0 && *end >= expected.1)
}

#[test]
fn aliases_and_out_of_line_owners_survive_unknown_namespace_sentinel() {
    let internal_header = r#"#pragma once
#include <type_traits>
namespace absl {
ABSL_NAMESPACE_BEGIN
namespace functional_internal {
template <bool C>
using EnableIf = typename std::enable_if_t<C, int>;
}
ABSL_NAMESPACE_END
}
"#;
    let function_ref_header = r#"#pragma once
#include "internal.h"
namespace absl {
ABSL_NAMESPACE_BEGIN
template <typename F,
          absl::functional_internal::EnableIf<std::is_function_v<F>> = 0>
struct FunctionRef {};
ABSL_NAMESPACE_END
}
"#;
    let structured_header = r#"#pragma once
namespace absl {
ABSL_NAMESPACE_BEGIN
namespace log_internal {
struct StructuredProtoField {
  using Varint = int;
};

inline void use_varint(StructuredProtoField field) {
  struct BufferSizeVisitor final {
    void operator()(StructuredProtoField::Varint value) { (void)value; }
  };
  (void)field;
}
}
ABSL_NAMESPACE_END
}
"#;
    let owner_header = r#"#pragma once
namespace absl {
ABSL_NAMESPACE_BEGIN
namespace internal {
class Widget {
 public:
  Widget();
  void run();
};
}
ABSL_NAMESPACE_END
}
#if defined(PLATFORM_WIDGET)
#define ENABLE_WIDGET 1
namespace absl {
ABSL_NAMESPACE_BEGIN
namespace internal {
class GuardedWidget {
 public:
  GuardedWidget();
  void run();
};
}
ABSL_NAMESPACE_END
}
#endif
"#;
    let owner_source = r#"#include "owner.h"
namespace absl {
ABSL_NAMESPACE_BEGIN
namespace internal {
Widget::Widget() {}
void Widget::run() {}
GuardedWidget::GuardedWidget() {}
void GuardedWidget::run() {}
}
ABSL_NAMESPACE_END
}
"#;
    let unrelated_source = r#"#include "function_ref.h"
#include "structured.h"
namespace unrelated {
template <bool C>
using EnableIf = long;
struct StructuredProtoField {
  using Varint = long;
};
}
void use_unrelated_alias(unrelated::EnableIf<true> value) {
  (void)value;
}
void use_unrelated_varint(unrelated::StructuredProtoField::Varint value) {
  (void)value;
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("internal.h", internal_header)
        .file("function_ref.h", function_ref_header)
        .file("structured.h", structured_header)
        .file("owner.h", owner_header)
        .file("owner.cpp", owner_source)
        .file("unrelated.cpp", unrelated_source)
        .build();
    let analyzer = CppAnalyzer::from_project(project.project().clone());
    let owner_source = project
        .file("owner.cpp")
        .read_to_string()
        .expect("owner source");
    let function_ref_source = project
        .file("function_ref.h")
        .read_to_string()
        .expect("function_ref source");
    let structured_source = project
        .file("structured.h")
        .read_to_string()
        .expect("structured source");
    let unrelated_source = project
        .file("unrelated.cpp")
        .read_to_string()
        .expect("unrelated source");
    let owner_file = project.file("owner.cpp");
    let function_ref_file = project.file("function_ref.h");
    let structured_file = project.file("structured.h");
    let unrelated_file = project.file("unrelated.cpp");

    let widget = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::internal.Widget"
            && unit.source() == &project.file("owner.h")
    });
    let guarded_widget = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::internal.GuardedWidget"
            && unit.source() == &project.file("owner.h")
    });
    let enable_if = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::functional_internal.EnableIf"
            && unit.source() == &project.file("internal.h")
            && unit.signature().is_some_and(|signature| {
                signature == "using EnableIf = typename std::enable_if_t<C, int>;"
            })
    });
    let varint = definition_by(&analyzer, |unit| {
        unit.kind() == CodeUnitType::Class
            && unit.fq_name() == "absl::log_internal.StructuredProtoField$Varint"
            && unit.source() == &project.file("structured.h")
            && unit
                .signature()
                .is_some_and(|signature| signature == "using Varint = int;")
    });

    let widget_constructor = token_range(&owner_source, "Widget::Widget() {}", "Widget");
    let widget_constructor_terminal =
        last_token_range(&owner_source, "Widget::Widget() {}", "Widget");
    let widget_method = token_range(&owner_source, "void Widget::run() {}", "Widget");
    let widget_method_terminal = last_token_range(&owner_source, "void Widget::run() {}", "run");
    let guarded_constructor = token_range(
        &owner_source,
        "GuardedWidget::GuardedWidget() {}",
        "GuardedWidget",
    );
    let enable_if_use = token_range(
        &function_ref_source,
        "          absl::functional_internal::EnableIf<std::is_function_v<F>> = 0>",
        "EnableIf",
    );
    let unrelated_enable_if = token_range(
        &unrelated_source,
        "void use_unrelated_alias(unrelated::EnableIf<true> value) {",
        "EnableIf",
    );
    let varint_reference = token_range(
        &structured_source,
        "    void operator()(StructuredProtoField::Varint value) { (void)value; }",
        "StructuredProtoField::Varint",
    );
    let unrelated_varint = token_range(
        &unrelated_source,
        "void use_unrelated_varint(unrelated::StructuredProtoField::Varint value) {",
        "Varint",
    );

    let (widget_hits, widget_unproven) = authoritative_ranges(&analyzer, &widget, &owner_file);
    assert!(
        contains_range(&widget_hits, widget_constructor)
            && contains_range(&widget_hits, widget_method),
        "sentinel owner qualifiers must remain exact: {widget_hits:#?}"
    );
    assert!(
        !contains_range(&widget_hits, widget_constructor_terminal)
            && !contains_range(&widget_hits, widget_method_terminal)
            && widget_unproven.is_empty(),
        "owner hits must cover only the leading owner token: proven={widget_hits:#?}, unproven={widget_unproven:#?}"
    );

    let (guarded_proven, guarded_unproven) =
        authoritative_ranges(&analyzer, &guarded_widget, &owner_file);
    // Issue #1814: `owner.h` selects the `PLATFORM_WIDGET` branch before
    // `owner.cpp` is parsed. `owner.cpp` compiles only when that branch is
    // active, so a compatible guard set proves the out-of-line owner.
    assert!(
        contains_range(&guarded_proven, guarded_constructor),
        "a compatible guarded owner is proven: proven={guarded_proven:#?}, unproven={guarded_unproven:#?}"
    );

    let (enable_if_hits, enable_if_unproven) =
        authoritative_ranges(&analyzer, &enable_if, &function_ref_file);
    assert!(
        enable_if_hits.len() == 1
            && contains_range(&enable_if_hits, enable_if_use)
            && enable_if_unproven.is_empty(),
        "namespace alias must retain one structured reference containing its terminal: proven={enable_if_hits:#?}, unproven={enable_if_unproven:#?}"
    );
    let (unrelated_enable_hits, unrelated_enable_unproven) =
        authoritative_ranges(&analyzer, &enable_if, &unrelated_file);
    assert!(
        !contains_range(&unrelated_enable_hits, unrelated_enable_if)
            && !contains_range(&unrelated_enable_unproven, unrelated_enable_if),
        "unrelated namespace alias must not match: proven={unrelated_enable_hits:#?}, unproven={unrelated_enable_unproven:#?}"
    );

    let (varint_hits, varint_unproven) = authoritative_ranges(&analyzer, &varint, &structured_file);
    assert_eq!(
        (varint_hits, varint_unproven),
        (BTreeSet::from([varint_reference]), BTreeSet::new()),
        "nested alias must retain its complete structured reference range"
    );
    let (unrelated_varint_hits, unrelated_varint_unproven) =
        authoritative_ranges(&analyzer, &varint, &unrelated_file);
    assert!(
        !contains_range(&unrelated_varint_hits, unrelated_varint)
            && !contains_range(&unrelated_varint_unproven, unrelated_varint),
        "unrelated nested alias must not match: proven={unrelated_varint_hits:#?}, unproven={unrelated_varint_unproven:#?}"
    );
}
