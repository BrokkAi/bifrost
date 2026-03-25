mod common;

use brokk_analyzer::{
    CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, ImportAnalysisProvider, Language, Project,
    ProjectFile, TestProject,
};
use common::{assert_code_eq, cpp_fixture_project};
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
fn is_empty_test() {
    let analyzer = fixture_analyzer();
    assert!(!analyzer.is_empty());
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
        declarations.iter().any(|cu| cu.is_class() && cu.short_name().contains("AdaptiveIntBuilderBase"))
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
fn test_cpp_type_alias_and_stable_definition_ordering() {
    let analyzer = fixture_analyzer();
    let all = all_declarations(&analyzer);
    let aliases: Vec<_> = all
        .iter()
        .filter(|cu| cu.is_class())
        .filter(|cu| {
            ["ColorValue", "PixelBuffer", "String", "uint32_t"]
                .iter()
                .any(|name| cu.short_name().contains(name))
        })
        .collect();
    assert!(aliases.is_empty());

    let defs = analyzer.get_definitions("overloadedFunction");
    assert!(defs.len() >= 3);
    let unique_signatures: BTreeSet<_> = defs.iter().filter_map(|cu| cu.signature()).collect();
    assert!(!unique_signatures.is_empty());
    assert!(unique_signatures.len() >= 2);
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
