use crate::adapter::{parse_cpp_file, parse_cpp_file_with_readings};
use brokk_bifrost_core::analyzer::ProjectFile;
use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance;
use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
use brokk_bifrost_core::analyzer::tree_walk::ParentIndex;
use tree_sitter::{Parser, Tree};

fn tree(source: &str) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .unwrap();
    parser.parse(source, None).unwrap()
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
    let source = r#"#define VIEWS_EXPORT
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
"#;
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
