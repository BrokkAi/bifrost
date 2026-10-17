use crate::adapter::{parse_cpp_file, parse_cpp_file_with_readings};
use crate::declarations::cpp_unclosed_construct_openers;
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance;
use brokk_bifrost_core::analyzer::statement_facts::StatementFactKind;
use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
use tree_sitter::Tree;

fn tree(source: &str) -> Tree {
    crate::diagnostics::parse_cpp_tree(source)
}

#[test]
fn expression_facts_capture_structured_cpp_shapes() {
    let source = r#"
struct Bits { int signed_value : 3; unsigned value : 2; int : 2; };
enum class Kind { First, Second = 4, Third };
struct LargePayload { char bytes[65]; };
class Interface {
public:
  void arrays(int values[4], int (&reference)[4]);
  const int member_value();
  int clean_member() const;
};
const int free_value();
void inspect(int values[4]) { sizeof(values); }
void run(LargePayload payload) {
  for (int i = 0; i < 2; ++i) {
    for (int j = 0; j < 2; ++j) { sizeof(++i); }
  }
}
"#;
    let file = ProjectFile::new(std::env::temp_dir(), "expression_facts.cpp");
    let parsed = parse_cpp_file(&file, source, &tree(source));
    let facts = parsed.source_facts.as_ref().unwrap().cpp.as_ref().unwrap();
    assert!(
        facts
            .expressions
            .iter()
            .any(|fact| fact.kind.label() == "bit_field" && fact.bit_field_width == Some(3))
    );
    assert!(facts.expressions.iter().any(|fact| {
        fact.kind.label() == "bit_field" && fact.bit_field_anonymous == Some(true)
    }));
    assert!(facts.expressions.iter().any(|fact| {
        fact.kind.label() == "enumerator"
            && fact.enum_value == Some(4)
            && fact.enum_has_implicit_before_nonreference == Some(true)
    }));
    assert!(
        facts
            .expressions
            .iter()
            .any(|fact| { fact.kind.label() == "array_parameter" && fact.array_extent == Some(4) })
    );
    assert!(facts.expressions.iter().any(|fact| {
        fact.kind.label() == "sizeof_expression"
            && fact.sizeof_has_side_effect == Some(true)
            && fact.sizeof_operand_is_parameter == Some(false)
    }));
    assert!(facts.expressions.iter().any(|fact| {
        fact.kind.label() == "sizeof_expression" && fact.sizeof_operand_is_parameter == Some(true)
    }));
    assert!(facts.expressions.iter().any(|fact| {
        fact.kind.label() == "loop_variable"
            && fact.name.as_deref() == Some("j")
            && fact.loop_has_short_ancestor == Some(true)
    }));
    assert!(facts.expressions.iter().any(|fact| {
        fact.kind.label() == "function_parameter"
            && fact.name.as_deref() == Some("payload")
            && fact.type_size_bytes == Some(65)
            && fact.type_size_exact == Some(true)
    }));
    assert!(facts.expressions.iter().any(|fact| {
        fact.kind.label() == "function_signature"
            && fact.name.as_deref() == Some("member_value")
            && fact.member_function == Some(true)
            && fact.return_top_level_const == Some(true)
            && fact.member_function_const == Some(false)
    }));
    assert!(facts.expressions.iter().any(|fact| {
        fact.kind.label() == "array_parameter"
            && fact.name.as_deref() == Some("values")
            && fact.member_function == Some(true)
            && fact.array_is_reference == Some(false)
    }));
}

#[test]
fn captures_cpp_statement_rows_from_structured_nodes() {
    let source = r#"
enum Color { Red, Green, Blue };
int run(bool a, bool b, bool c, bool d, bool e, bool f, bool g, bool h, bool i, bool j, bool k, bool l) {
  label:
  if (a && b || c && d || e && f || g && h || i && j || k && l) {}
  for (int i = 0; i < 10; ++i) {
    for (i = 0; i < 10; ++i) {}
  }
  switch (Red) {
    case Red: break;
    case Green: break;
  }
  goto label;
}
"#;
    let rows = crate::source_facts::parse_statement_fact_rows(source);
    assert!(rows.valid());
    assert!(
        rows.conditions
            .iter()
            .any(|fact| fact.logical_operator_count > 5)
    );
    assert!(
        rows.loops
            .iter()
            .filter_map(|fact| fact.variable.as_deref())
            .any(|name| name == "i")
    );
    assert!(rows.switches.iter().any(|fact| fact.missing_enum_case));
    assert_eq!(rows.switch_cases.len(), 2);
    assert_eq!(rows.enums.len(), 1);
    assert_eq!(rows.enumerators.len(), 3);
    assert_eq!(rows.labels.len(), 1);
    assert_eq!(rows.gotos.len(), 1);
    assert!(!rows.gotos[0].forward);
    assert!(
        rows.statements
            .iter()
            .any(|fact| fact.kind == StatementFactKind::ComplexCondition)
    );
    assert!(
        rows.statements
            .iter()
            .any(|fact| fact.kind == StatementFactKind::MissingCaseInSwitch)
    );
}

#[test]
fn alloca_rows_exclude_tightly_bounded_and_outside_calls() {
    let source = r#"
void *alloca(unsigned long);
void probe() {
  for (int i = 0; i < 10; ++i) {
    alloca(16);
  }
  for (int i = 0; i < 1; ++i) {
    alloca(16);
  }
  alloca(16);
}
"#;
    let rows = crate::source_facts::parse_statement_fact_rows(source);
    let alloca_rows: Vec<_> = rows
        .statements
        .iter()
        .filter(|fact| fact.kind == StatementFactKind::AllocaInLoop)
        .collect();
    assert_eq!(alloca_rows.len(), 1);
    assert_eq!(alloca_rows[0].range.start_line, 5);
}

#[test]
fn primary_declarations_and_structural_bodies_share_occurrences_across_mounts() {
    let source = "struct Widget { int value; }; int run(Widget w) { return target(w.value); }";
    let tree = tree(source);
    let root = std::env::temp_dir();
    let first = ProjectFile::new(root.clone(), "one.cpp");
    let second = ProjectFile::new(root, "two.cpp");
    let parsed = parse_cpp_file(&first, source, &tree);
    let mounted = parse_cpp_file(&second, source, &tree);
    let facts = parsed.source_facts.as_ref().unwrap();
    assert_eq!(facts, mounted.source_facts.as_ref().unwrap());
    for name in ["Widget", "run"] {
        let (declaration, _) = parsed
            .source_declaration_units
            .iter()
            .find(|(_, unit)| unit.short_name() == name)
            .unwrap();
        let occurrence = facts.occurrences.declaration(*declaration).occurrence;
        assert!(
            facts
                .structural
                .nodes()
                .iter()
                .any(|node| node.occurrence == occurrence),
            "{name} shares its exact primary occurrence"
        );
    }
    assert!(
        facts
            .structural
            .nodes()
            .iter()
            .any(|node| node.kind == NormalizedKind::Call)
    );
    assert!(
        facts
            .structural
            .nodes()
            .iter()
            .any(|node| node.kind == NormalizedKind::FieldAccess)
    );
    assert!(
        parsed
            .source_declaration_units
            .iter()
            .all(|(_, unit)| unit.source() == &first)
    );
    assert!(
        mounted
            .source_declaration_units
            .iter()
            .all(|(_, unit)| unit.source() == &second)
    );
}

#[test]
fn header_readings_share_source_authority_with_distinct_c_tag_owners() {
    let source = "struct outer { struct inner { int v; } i; }; struct inner *p;";
    let tree = tree(source);
    let file = ProjectFile::new(std::env::temp_dir(), "tags.h");
    let ancestry = ParentIndex::new(tree.root_node());
    let (cpp, c) = parse_cpp_file_with_readings(&file, source, tree.root_node(), &ancestry);
    let c = c.expect("nested tag requires an alternate C reading");
    let single_cpp = crate::adapter::parse_cpp_file_in_dialect(
        &file,
        source,
        &tree,
        brokk_bifrost_core::analyzer::model::LanguageDialect::Standard(
            brokk_bifrost_core::analyzer::Language::Cpp,
        ),
    );
    let single_c = crate::adapter::parse_cpp_file_in_dialect(
        &file,
        source,
        &tree,
        brokk_bifrost_core::analyzer::model::LanguageDialect::CppC,
    );
    assert_eq!(cpp.source_facts, single_cpp.source_facts);
    assert_eq!(c.source_facts, single_c.source_facts);
    let cpp_inner = cpp
        .source_declaration_units
        .iter()
        .find(|(_, unit)| unit.short_name() == "outer$inner")
        .unwrap();
    let c_inner = c
        .source_declaration_units
        .iter()
        .find(|(_, unit)| unit.short_name() == "inner")
        .unwrap();
    let cpp_rows = &cpp.source_facts.as_ref().unwrap().occurrences;
    let c_rows = &c.source_facts.as_ref().unwrap().occurrences;
    assert_eq!(
        cpp_rows.occurrence(cpp_rows.declaration(cpp_inner.0).occurrence),
        c_rows.occurrence(c_rows.declaration(c_inner.0).occurrence)
    );
    assert_ne!(cpp_inner.1, c_inner.1);
}

#[test]
fn forward_and_definition_occurrences_remain_canonical_navigation_alternatives() {
    let source = "struct Forward; struct Forward { int value; };";
    let tree = tree(source);
    let file = ProjectFile::new(std::env::temp_dir(), "forward.cpp");
    let parsed = parse_cpp_file(&file, source, &tree);
    let facts = parsed.source_facts.as_ref().unwrap();
    let links: Vec<_> = parsed
        .source_declaration_units
        .iter()
        .filter(|(_, unit)| unit.short_name() == "Forward")
        .collect();
    assert_eq!(links.len(), 2);
    let mut starts: Vec<_> = links
        .iter()
        .map(|(id, _)| {
            facts
                .occurrences
                .occurrence(facts.occurrences.declaration(*id).occurrence)
                .range
                .start_byte
        })
        .collect();
    starts.sort_unstable();
    assert_eq!(starts, vec![0, source.find("struct Forward {").unwrap()]);
}

#[test]
fn includes_in_bodies_and_malformed_recovery_publish_canonical_imports() {
    let source = "#include <vector>\nvoid run() {\n#include \"local.h\"\n}\nclass Broken { void method(\n#include \"hidden.h\"\n";
    let tree = tree(source);
    let file = ProjectFile::new(std::env::temp_dir(), "includes.cpp");
    let parsed = parse_cpp_file(&file, source, &tree);
    let facts = parsed.source_facts.as_ref().unwrap();
    assert_eq!(facts.generic_imports.len(), parsed.imports.len());
    for target in ["vector", "local.h", "hidden.h"] {
        let include = facts
            .cpp
            .as_ref()
            .unwrap()
            .includes
            .iter()
            .find(|include| include.path == target)
            .unwrap();
        let target_range = facts.occurrences.occurrence(include.target).range;
        assert!(source[target_range.start_byte..target_range.end_byte].contains(target));
        let import = facts
            .imports
            .iter()
            .find(|import| import.statement.contains(target))
            .unwrap();
        let occurrence = facts.occurrences.occurrence(import.declaration);
        assert!(source[occurrence.range.start_byte..occurrence.range.end_byte].contains(target));
    }
    assert_eq!(
        facts
            .imports
            .iter()
            .map(|import| import.import_info(&facts.occurrences))
            .collect::<Vec<_>>(),
        parsed.imports
    );
}

#[test]
fn fragmented_class_recovery_keeps_embedded_source_provenance() {
    let source = r#"
#define SIMPLECPP_LIB
namespace simplecpp {
class SIMPLECPP_LIB Token {
  int prefix;
 public:
  Token(int value) : field(value) { flags(); }
  int field;
 private:
  void flags() { field = 1; }
};
}
"#;
    let tree = tree(source);
    let file = ProjectFile::new(std::env::temp_dir(), "recovery.hpp");
    let parsed = parse_cpp_file(&file, source, &tree);
    let ancestry = ParentIndex::new(tree.root_node());
    let (joint_cpp, joint_c) =
        parse_cpp_file_with_readings(&file, source, tree.root_node(), &ancestry);
    let single_c = crate::adapter::parse_cpp_file_in_dialect(
        &file,
        source,
        &tree,
        brokk_bifrost_core::analyzer::model::LanguageDialect::CppC,
    );
    assert_eq!(parsed.source_facts, joint_cpp.source_facts);
    assert_eq!(
        single_c.source_facts,
        joint_c.as_ref().unwrap_or(&joint_cpp).source_facts
    );

    let facts = parsed.source_facts.as_ref().unwrap();
    assert!(
        parsed
            .declarations()
            .iter()
            .any(|unit| unit.short_name().ends_with("flags"))
    );
    assert!(
        facts
            .occurrences
            .occurrences()
            .iter()
            .any(|occurrence| occurrence.provenance == SourceOccurrenceProvenance::Embedded)
    );
    assert!(parsed.declarations().iter().all(|unit| {
        parsed
            .source_declaration_units
            .iter()
            .any(|(_, linked)| linked == unit)
    }));
}

#[test]
fn canonical_properties_preserve_multiname_fields_aliases_and_cpp_owners() {
    let source = "namespace ns { struct Base {}; struct Type : virtual Base { int value, *pointer; using Alias = Base; using Base::method; }; enum class Kind { Value }; int Type::method(int value) const { return value; } }";
    let tree = tree(source);
    let file = ProjectFile::new(std::env::temp_dir(), "properties.cpp");
    let parsed = parse_cpp_file(&file, source, &tree);
    let source = parsed.source_facts.as_ref().unwrap();
    let mut links = brokk_bifrost_core::hash::HashMap::<_, Vec<_>>::default();
    for (declaration, unit) in &parsed.source_declaration_units {
        links.entry(*declaration).or_default().push(unit.clone());
    }
    let mounted = crate::source_facts::CppFileSourceFacts::new(
        source.occurrences.clone(),
        source.cpp.clone().unwrap(),
        links,
    );
    let fact = |name: &str| {
        let unit = parsed
            .declarations()
            .iter()
            .find(|unit| unit.identifier() == name)
            .unwrap();
        mounted.for_unit(unit).next().unwrap()
    };
    assert_eq!(fact("value").field_type.as_ref().unwrap().indirection, 0);
    assert_eq!(fact("pointer").field_type.as_ref().unwrap().indirection, 1);
    assert_ne!(fact("value").declaration, fact("pointer").declaration);
    assert!(
        fact("Type")
            .bases
            .iter()
            .any(|base| base.is_virtual && base.components == ["Base"])
    );
    assert!(
        fact("Type")
            .member_usings
            .iter()
            .any(|using| using.member == "method" && using.scope == ["Base"])
    );
    assert_eq!(fact("Alias").alias_target_text.as_deref(), Some("Base"));
    assert_eq!(
        fact("Kind").enum_kind,
        brokk_bifrost_core::analyzer::cpp_facts::CppEnumOwnerKind::Scoped
    );
    assert_eq!(fact("method").written_owner, ["Type"]);
    assert_eq!(fact("method").trailing_qualifiers, "const");
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "353d8206a88c: C++ override or typedef navigation lost the canonical declaration identity/mount"
)]
fn typedef_tag_navigation_preserves_the_definition_mount() {
    let source = "typedef struct internal_tag public_name;\nstruct internal_tag { static void member(); };\n";
    let tree = tree(source);
    let file = ProjectFile::new(std::env::temp_dir(), "visible.hpp");
    let parsed = parse_cpp_file(&file, source, &tree);
    let unit = parsed
        .declarations()
        .iter()
        .find(|unit| unit.is_class() && unit.identifier() == "internal_tag")
        .unwrap();
    let facts = parsed.source_facts.as_ref().unwrap();
    let mounts: Vec<_> = parsed
        .source_declaration_units
        .iter()
        .filter(|(_, mounted)| mounted == unit)
        .collect();
    assert!(
        !mounts.is_empty(),
        "unit {unit:?}, all mounts {:?}",
        parsed.source_declaration_units
    );
    assert!(
        mounts.iter().any(
            |(id, _)| facts
                .cpp
                .as_ref()
                .unwrap()
                .declarations
                .iter()
                .any(|fact| fact.declaration == *id
                    && fact.occurrence_role
                        == brokk_bifrost_core::analyzer::cpp_facts::CppOccurrenceRole::Definition)
        ),
        "facts {:?}, mounts {mounts:?}",
        facts.cpp
    );
}

#[test]
fn malformed_exported_class_publishes_structured_recovered_bases() {
    let source = include_str!("fixtures/malformed_exported_widget.h");
    let file = ProjectFile::new(std::env::temp_dir(), "widget.h");
    let parsed = parse_cpp_file(&file, source, &tree(source));
    let widget = parsed
        .declarations()
        .iter()
        .find(|unit| unit.fq_name() == "views.Widget")
        .expect("recovered Widget declaration");
    let facts = parsed.source_facts.as_ref().unwrap();
    let declaration = parsed
        .source_declaration_units
        .iter()
        .find(|(_, unit)| unit == widget)
        .map(|(id, _)| *id)
        .expect("Widget source bridge");
    let bases = facts
        .cpp
        .as_ref()
        .unwrap()
        .declarations
        .iter()
        .find(|fact| fact.declaration == declaration)
        .expect("Widget source fact")
        .bases
        .iter()
        .map(|base| base.components.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        bases,
        vec![
            vec!["internal", "NativeWidgetDelegate"],
            vec!["ui", "EventSource"],
            vec!["FocusTraversable"],
            vec!["ui", "NativeThemeObserver"],
            vec!["ui", "ColorProviderSource"],
            vec!["ui", "PropertyHandler"],
            vec!["ui", "AXModeObserver"],
            vec!["ui", "metadata", "MetaDataProvider"],
        ],
        "recovered Widget bases must remain structured"
    );
}

#[test]
fn newline_exported_class_publishes_structured_template_base() {
    let source = r#"#define PN_CPP_CLASS_EXTERN
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
"#;
    let file = ProjectFile::new(std::env::temp_dir(), "connection.hpp");
    let parsed = parse_cpp_file(&file, source, &tree(source));
    let connection = parsed
        .declarations()
        .iter()
        .find(|unit| unit.fq_name() == "proton.connection")
        .expect("recovered connection declaration");
    let facts = parsed.source_facts.as_ref().unwrap();
    let declaration = parsed
        .source_declaration_units
        .iter()
        .find(|(_, unit)| unit == connection)
        .map(|(id, _)| *id)
        .expect("connection source bridge");
    let bases = facts
        .cpp
        .as_ref()
        .unwrap()
        .declarations
        .iter()
        .find(|fact| fact.declaration == declaration)
        .expect("connection source fact")
        .bases
        .iter()
        .map(|base| base.components.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        bases,
        vec![vec!["internal", "object"], vec!["endpoint"],],
        "newline recovered class bases must keep template and terminal names"
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "353d8206a88c: recovered C++ macro namespace declarations preserve original conditional guards"
)]
fn compound_conditional_macro_namespace_declarations_preserve_guards() {
    let source = "namespace absl {\n#if defined(ABSL_USES_STD_SOURCE_LOCATION) && defined(ABSL_HAVE_STD_SOURCE_LOCATION)\nABSL_NAMESPACE_BEGIN\nusing SourceLocation = std::source_location;\nABSL_NAMESPACE_END\n#else\nABSL_NAMESPACE_BEGIN\nclass SourceLocation {};\nABSL_NAMESPACE_END\n#endif\n}\n";
    let tree = tree(source);
    let file = ProjectFile::new(std::env::temp_dir(), "source_location.h");
    let parsed = parse_cpp_file(&file, source, &tree);
    let source_facts = parsed.source_facts.as_ref().unwrap();
    for needle in ["using SourceLocation", "class SourceLocation"] {
        let start = source.find(needle).unwrap();
        let node = tree
            .root_node()
            .descendant_for_byte_range(start, start)
            .unwrap();
        let expected =
            crate::graph::resolver::preprocessor_guard_environment(node, source).unwrap();
        let facts = source_facts.cpp.as_ref().unwrap();
        let captured = parsed
            .source_declaration_units
            .iter()
            .filter(|(_, unit)| unit.identifier() == "SourceLocation")
            .find_map(|(id, _)| {
                let range = source_facts
                    .occurrences
                    .occurrence(source_facts.occurrences.declaration(*id).occurrence)
                    .range;
                (range.start_byte <= start && start < range.end_byte).then(|| {
                    facts
                        .declarations
                        .iter()
                        .find(|fact| fact.declaration == *id)
                        .unwrap()
                })
            })
            .expect("declaration property");
        let actual = crate::source_context::cpp_guard_set_to_runtime(
            captured.guard_requirements.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(actual, expected, "{needle}: {captured:?}");
        let family = captured
            .conditional_family
            .expect("original conditional family");
        assert_eq!(
            source_facts.occurrences.occurrence(family).range.start_byte,
            source.find("#if").unwrap()
        );
        assert_eq!(
            captured.lexical_path.first().map(String::as_str),
            Some("absl")
        );
        if let Some(alias) = captured.file_scope_alias.as_ref() {
            assert_eq!(alias.namespace.as_deref(), Some("absl"));
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "5610741cdb03: C++ override or typedef navigation lost the canonical declaration identity/mount"
)]
fn overriding_member_keeps_the_base_callable_identity_qualifiers() {
    let source = "struct Base { virtual void run(int value) const; }; struct Derived : Base { void run(int value) const override final {} };";
    let file = ProjectFile::new(std::env::temp_dir(), "override.hpp");
    let parsed = parse_cpp_file(&file, source, &tree(source));
    let facts = parsed.source_facts.as_ref().unwrap().cpp.as_ref().unwrap();
    for owner in ["Base", "Derived"] {
        let declaration = parsed
            .source_declaration_units
            .iter()
            .find(|(_, unit)| unit.is_function() && unit.fq_name() == format!("{owner}.run"))
            .map(|(declaration, _)| *declaration)
            .expect("callable declaration source");
        let fact = facts
            .declarations
            .iter()
            .find(|fact| fact.declaration == declaration)
            .unwrap();
        assert_eq!(
            fact.trailing_qualifiers, "const",
            "{owner} identity excludes override/final"
        );
    }
}

#[test]
fn globally_qualified_bases_keep_absolute_source_identity() {
    let source = r#"namespace outer {
struct Base {};
template <class T> struct Generic {};
}
namespace nested {
namespace outer { struct Base {}; template <class T> struct Generic {}; }
struct Ordinary : ::outer::Base {};
struct Templated : ::outer::Generic<int> {};
}
"#;
    let parsed_tree = tree(source);
    let file = ProjectFile::new(std::env::temp_dir(), "absolute_bases.hpp");
    let parsed = parse_cpp_file(&file, source, &parsed_tree);
    let facts = parsed.source_facts.as_ref().unwrap().cpp.as_ref().unwrap();
    for (owner, terminal) in [("Ordinary", "Base"), ("Templated", "Generic")] {
        let declaration = parsed
            .source_declaration_units
            .iter()
            .find(|(_, unit)| unit.is_class() && unit.identifier() == owner)
            .map(|(declaration, _)| *declaration)
            .expect("derived class source");
        let fact = facts
            .declarations
            .iter()
            .find(|fact| fact.declaration == declaration)
            .unwrap();
        let [base] = fact.bases.as_slice() else {
            panic!("{owner} bases: {:?}", fact.bases);
        };
        assert_eq!(base.components, ["outer", terminal]);
        assert!(
            base.absolute,
            "{owner} must bypass nested::outer; tree: {}",
            parsed_tree.root_node().to_sexp()
        );
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "c7baf85ab85c: displaced macro return type preserves unmatched namespace brace evidence"
)]
fn displaced_macro_return_type_retains_unmatched_namespace_brace_evidence() {
    let source = "#define FMT_API\nFMT_API void vformat_to(int& out);\n}\nvoid run() {}\n";
    let tree = tree(source);
    let file = ProjectFile::new(std::env::temp_dir(), "flattened.cpp");
    let parsed = parse_cpp_file(&file, source, &tree);
    let facts = parsed.source_facts.as_ref().unwrap();
    let (id, _) = parsed
        .source_declaration_units
        .iter()
        .find(|(_, unit)| unit.identifier() == "vformat_to")
        .unwrap();
    let fact = facts
        .cpp
        .as_ref()
        .unwrap()
        .declarations
        .iter()
        .find(|fact| fact.declaration == *id)
        .unwrap();
    assert!(fact.flattened_macro_namespace.is_none());
    let brace = facts
        .occurrences
        .occurrence(fact.displaced_namespace_closing_brace.unwrap());
    assert_eq!(&source[brace.range.start_byte..brace.range.end_byte], "}");
    let (id, _) = parsed
        .source_declaration_units
        .iter()
        .find(|(_, unit)| unit.identifier() == "run")
        .unwrap();
    let fact = facts
        .cpp
        .as_ref()
        .unwrap()
        .declarations
        .iter()
        .find(|fact| fact.declaration == *id)
        .unwrap();
    assert!(fact.displaced_namespace_closing_brace.is_none());
}

#[test]
fn nested_declarations_keep_dependency_order_and_descendant_member_usings() {
    let source = "struct Root { using Base::run; Foo first; struct Child { using Other::run; Bar second; Foo third; }; Foo fourth; };";
    let file = ProjectFile::new(std::env::temp_dir(), "dependencies.cpp");
    let parsed = parse_cpp_file(&file, source, &tree(source));
    let facts = parsed.source_facts.as_ref().unwrap().cpp.as_ref().unwrap();
    for (owner, names, using_scopes) in [
        (
            "Root",
            vec!["Root", "Base", "Foo", "Child", "Other", "Bar"],
            vec!["Base", "Other"],
        ),
        ("Child", vec!["Child", "Other", "Bar", "Foo"], vec!["Other"]),
    ] {
        let id = parsed
            .source_declaration_units
            .iter()
            .find(|(_, unit)| unit.is_class() && unit.identifier() == owner)
            .unwrap()
            .0;
        let fact = facts
            .declarations
            .iter()
            .find(|fact| fact.declaration == id)
            .unwrap();
        assert_eq!(fact.dependency_type_names, names, "{owner}");
        assert_eq!(
            fact.member_usings
                .iter()
                .map(|import| import.scope[0].as_str())
                .collect::<Vec<_>>(),
            using_scopes,
            "{owner}"
        );
    }
}

#[test]
fn recovered_member_keeps_its_dependency_evidence() {
    let source = "#define EXPORT\nclass EXPORT Recovered : public a::A, public b::B { Callback field; void run(Argument arg); };";
    let file = ProjectFile::new(std::env::temp_dir(), "recovered-dependencies.cpp");
    let parsed = parse_cpp_file(&file, source, &tree(source));
    let facts = parsed.source_facts.as_ref().unwrap();
    for (member, dependency) in [("field", "Callback"), ("run", "Argument")] {
        let id = parsed
            .source_declaration_units
            .iter()
            .find(|(_, unit)| unit.identifier() == member)
            .unwrap()
            .0;
        let fact = facts
            .cpp
            .as_ref()
            .unwrap()
            .declarations
            .iter()
            .find(|fact| fact.declaration == id)
            .unwrap();
        assert!(
            fact.dependency_type_names
                .iter()
                .any(|name| name == dependency),
            "{member}: {fact:?}"
        );
    }
}

#[test]
fn macro_parameter_expansion_uses_canonical_declaration_type_spelling() {
    let parameters = "const Event& event, LogString& out, Pool& p";
    let source = format!("void run({parameters}) const;");
    let file = ProjectFile::new(std::env::temp_dir(), "macro-parameters.cpp");
    let parsed = parse_cpp_file(&file, &source, &tree(&source));
    let unit = parsed
        .declarations()
        .iter()
        .find(|unit| unit.identifier() == "run")
        .unwrap();
    let types = parsed.signature_metadata.get(unit).unwrap()[0]
        .callable_parameter_types()
        .unwrap();
    assert_eq!(types, ["const Event &", "LogString &", "Pool &"]);
    assert_eq!(
        crate::graph::resolver::cpp_macro_parameter_types(parameters).unwrap(),
        types
    );
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#3501: recovered macro-exported C++ aliases retain their structured target"
)]
fn macro_exported_class_alias_retains_structured_target() {
    let source = r#"#pragma once
#include "callback.h"
namespace bluez {
class DEVICE_BLUETOOTH_EXPORT BluetoothGattCharacteristicClient {
 public:
    using ErrorCallback =
        base::OnceCallback<void(const std::string& error_name,
                                const std::string& error_message)>;
    virtual void Start(ErrorCallback error_callback) = 0;
};
}
"#;
    let file = ProjectFile::new(std::env::temp_dir(), "gatt.h");
    let tree = tree(source);
    let parsed = parse_cpp_file(&file, source, &tree);
    let facts = parsed.source_facts.as_ref().unwrap();
    let links: Vec<_> = parsed
        .source_declaration_units
        .iter()
        .filter(|(_, unit)| unit.identifier() == "ErrorCallback")
        .collect();
    assert!(!links.is_empty());
    for (id, unit) in links {
        let fact = facts
            .cpp
            .as_ref()
            .unwrap()
            .declarations
            .iter()
            .find(|fact| fact.declaration == *id)
            .unwrap();
        assert!(
            matches!(&fact.alias_target, Some(brokk_bifrost_core::analyzer::cpp_facts::CppStructuredAliasTarget::Named {components, ..}) if components == &["base", "OnceCallback"]),
            "{unit:?}: {fact:?}"
        );
    }
}

/// One header of the SQLite amalgamation's shape: an include guard around an
/// `extern "C"` block that `#if 0` opens and a second `#if 0` closes.
fn amalgamated_header(guard: &str, aggregate: &str) -> String {
    format!(
        "#ifndef {guard}\n#define {guard}\n#if 0\nextern \"C\" {{\n#endif\n\
         struct {aggregate} {{ int value; }};\n\
         #if 0\n}}  /* End of the 'extern \"C\"' block */\n#endif\n#endif\n"
    )
}

/// #3501: the 0.23.5 grammar left conditional `extern "C"` headers in
/// tree-sitter's whole-file ERROR root over the constructs still open at the
/// end of input. The 0.24.0 grammar recognizes those header pairs as linkage
/// nodes, so keep that former witness as a clean positive and use an actually
/// unclosed construct to retain the recovery contract below.
#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#3501: C grammar failure on large files dropped declarations inside constructs left open by recovery"
)]
fn declarations_inside_constructs_left_open_are_recorded_as_recovered() {
    use brokk_bifrost_core::analyzer::model::ParseCompleteness;
    use brokk_bifrost_core::analyzer::structural::materialization::MaterializationRecord;

    fn recovered(
        parsed: &brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    ) -> Vec<(String, usize, usize)> {
        let mut recovered: Vec<_> = parsed
            .materialization_records
            .iter()
            .filter_map(|record| match record {
                MaterializationRecord::RecoveredDeclaration { recovery, unit } => {
                    Some((unit.fq_name(), recovery.start_byte, recovery.end_byte))
                }
                _ => None,
            })
            .collect();
        recovered.sort();
        recovered
    }

    let open = "int sqlite3_open(void) { return 0; }\n";
    let file = ProjectFile::new(std::env::temp_dir(), "sqlite3.c");
    let repaired = format!(
        "#include <stdarg.h>\n{}{open}",
        amalgamated_header("SQLITE3_H", "sqlite3_file")
    );
    let repaired_tree = tree(&repaired);
    assert_eq!(repaired_tree.root_node().kind(), "translation_unit");
    assert!(cpp_unclosed_construct_openers(repaired_tree.root_node()).is_empty());
    let repaired_parsed = parse_cpp_file(&file, &repaired, &repaired_tree);
    assert_eq!(recovered(&repaired_parsed), Vec::new());
    assert_eq!(repaired_parsed.completeness, ParseCompleteness::Complete);

    let source = format!(
        "#include <stdarg.h>\n{}{}{open}",
        amalgamated_header("SQLITE3_H", "sqlite3_file"),
        amalgamated_header("_SQLITE3RTREE_H_", "sqlite3_rtree_geometry")
    );
    let clean_tree = tree(&source);
    let clean_root = clean_tree.root_node();
    assert_eq!(
        clean_root.kind(),
        "translation_unit",
        "{}",
        clean_root.to_sexp()
    );
    assert!(!clean_root.has_error(), "{}", clean_root.to_sexp());
    assert_eq!(clean_root.byte_range(), 0..source.len());
    assert!(cpp_unclosed_construct_openers(clean_root).is_empty());
    let clean_parsed = parse_cpp_file(&file, &source, &clean_tree);
    let mut names: Vec<_> = clean_parsed
        .declarations()
        .iter()
        .map(|unit| unit.fq_name())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "SQLITE3_H",
            "_SQLITE3RTREE_H_",
            "sqlite3_file",
            "sqlite3_file.value",
            "sqlite3_open",
            "sqlite3_rtree_geometry",
            "sqlite3_rtree_geometry.value",
        ],
        "the repaired linkage nodes keep every declaration it reads"
    );
    assert_eq!(recovered(&clean_parsed), Vec::new());
    assert_eq!(clean_parsed.completeness, ParseCompleteness::Complete);

    // Thirty-two unmatched braces are intentional: with fewer, tree-sitter's
    // EOF recovery synthesizes closes and keeps a translation_unit root rather
    // than producing the whole-root ERROR required by this contract.
    let unmatched_openers = 32;
    let malformed = format!("{}\n{}", "{".repeat(unmatched_openers), source);
    let malformed_tree = tree(&malformed);
    let malformed_root = malformed_tree.root_node();
    assert_eq!(
        malformed_root.kind(),
        "ERROR",
        "{}",
        malformed_root.to_sexp()
    );
    assert_eq!(malformed_root.byte_range(), 0..malformed.len());
    let malformed_parsed = parse_cpp_file(&file, &malformed, &malformed_tree);
    let mut malformed_names: Vec<_> = malformed_parsed
        .declarations()
        .iter()
        .map(|unit| unit.fq_name())
        .collect();
    malformed_names.sort();
    assert_eq!(
        malformed_names, names,
        "recovery keeps every declaration it reads"
    );
    assert_eq!(malformed_parsed.completeness, ParseCompleteness::Partial);
    // The first unmatched brace is at byte 0, and every declaration follows
    // it inside the root's recovered interval.
    assert_eq!(
        recovered(&malformed_parsed),
        names
            .iter()
            .map(|name| (name.clone(), 0, malformed.len()))
            .collect::<Vec<_>>()
    );
    let openers: Vec<_> = cpp_unclosed_construct_openers(malformed_root)
        .iter()
        .map(|opener| (opener.kind(), opener.start_byte()))
        .collect();
    assert_eq!(
        openers,
        (0..unmatched_openers)
            .map(|byte| ("{", byte))
            .chain([
                ("#ifndef", 53),
                ("#if", 89),
                ("{", 106),
                ("#ifndef", 210),
                ("#if", 260),
                ("{", 277),
            ])
            .collect::<Vec<_>>()
    );
}
