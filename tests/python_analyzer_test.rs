mod common;

use brokk_analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ProjectFile, PythonAnalyzer, TypeHierarchyProvider,
};
use common::{assert_code_eq, normalize_nonempty_lines, py_fixture_project};
use std::collections::BTreeSet;

fn fixture_analyzer() -> PythonAnalyzer {
    PythonAnalyzer::from_project(py_fixture_project())
}

fn definition(analyzer: &PythonAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

#[test]
fn test_python_initialization_and_skeletons() {
    let analyzer = fixture_analyzer();
    let file_a = ProjectFile::new(analyzer.project().root().to_path_buf(), "a/A.py");

    let class_a = CodeUnit::new(
        file_a.clone(),
        brokk_analyzer::CodeUnitType::Class,
        "a.A",
        "A",
    );
    let func_a = definition(&analyzer, "a.A.funcA");

    let declarations = analyzer.get_declarations(&file_a);
    assert!(declarations.contains(&class_a));
    assert!(declarations.contains(&func_a));

    let top_level = analyzer.get_top_level_declarations(&file_a);
    assert!(top_level.contains(&class_a));
    assert!(top_level.contains(&func_a));

    let skeletons = analyzer.get_skeletons(&file_a);
    assert!(!skeletons.is_empty());
    assert!(skeletons.contains_key(&class_a));
    assert!(skeletons.contains_key(&func_a));
    assert_eq!("def funcA(): ...", skeletons.get(&func_a).unwrap().trim());
    assert_code_eq(
        r#"
        class A:
          def __init__(self): ...
          def method1(self) -> None: ...
          def method2(self, input_str: str, other_input: int = None) -> str: ...
          def method3(self) -> Callable[[int], int]: ...
          @staticmethod
          def method4(foo: float, bar: int) -> int: ...
          def method5(self) -> None: ...
          def method6(self) -> None: ...
        "#,
        skeletons.get(&class_a).unwrap(),
    );
    assert_code_eq(
        "def funcA(): ...",
        analyzer.get_skeleton(&func_a).unwrap().as_str(),
    );
}

#[test]
fn test_python_top_level_variables() {
    let analyzer = fixture_analyzer();
    let vars_py = ProjectFile::new(analyzer.project().root().to_path_buf(), "vars.py");
    let top_value = CodeUnit::new(
        vars_py.clone(),
        brokk_analyzer::CodeUnitType::Field,
        "vars",
        "TOP_VALUE",
    );
    let export_like = CodeUnit::new(
        vars_py.clone(),
        brokk_analyzer::CodeUnitType::Field,
        "vars",
        "export_like",
    );

    let skeletons = analyzer.get_skeletons(&vars_py);
    assert_eq!("TOP_VALUE = 99", skeletons.get(&top_value).unwrap().trim());
    assert_eq!(
        "export_like = \"not really\"",
        skeletons.get(&export_like).unwrap().trim()
    );

    let declarations = analyzer.get_declarations(&vars_py);
    assert!(declarations.contains(&top_value));
    assert!(declarations.contains(&export_like));
    assert!(!top_value.is_class());
    assert!(!export_like.is_class());

    let top_level = analyzer.get_top_level_declarations(&vars_py);
    assert!(top_level.contains(&top_value));
    assert!(top_level.contains(&export_like));
}

#[test]
fn test_python_get_class_source_with_comments() {
    let analyzer = fixture_analyzer();

    let documented_class = definition(&analyzer, "documented.DocumentedClass");
    let source = analyzer.get_source(&documented_class, true).unwrap();
    let normalized = normalize_nonempty_lines(&source);
    assert!(normalized.contains("# Comment before class"));
    assert!(normalized.contains("class DocumentedClass:"));
    assert!(normalized.contains("\"\"\""));

    let inner_class = definition(&analyzer, "documented.OuterClass$InnerClass");
    let inner_source = analyzer.get_source(&inner_class, true).unwrap();
    let inner_normalized = normalize_nonempty_lines(&inner_source);
    assert!(inner_normalized.contains("Comment before nested class"));
    assert!(inner_normalized.contains("class InnerClass:"));
}

#[test]
fn test_python_get_method_source_with_comments() {
    let analyzer = fixture_analyzer();

    let standalone = definition(&analyzer, "documented.standalone_function");
    let standalone_source = analyzer.get_source(&standalone, true).unwrap();
    let standalone_normalized = normalize_nonempty_lines(&standalone_source);
    assert!(standalone_normalized.contains("def standalone_function(param):"));
    assert!(standalone_normalized.contains("\"\"\""));

    let get_value = definition(&analyzer, "documented.DocumentedClass.get_value");
    let get_value_source = analyzer.get_source(&get_value, true).unwrap();
    let get_value_normalized = normalize_nonempty_lines(&get_value_source);
    assert!(get_value_normalized.contains("Comment before instance method"));
    assert!(get_value_normalized.contains("def get_value(self):"));
    assert!(get_value_normalized.contains("\"\"\""));

    let utility = definition(&analyzer, "documented.DocumentedClass.utility_method");
    let utility_source = analyzer.get_source(&utility, true).unwrap();
    let utility_normalized = normalize_nonempty_lines(&utility_source);
    assert!(utility_normalized.contains("Comment before static method"));
    assert!(utility_normalized.contains("@staticmethod"));
    assert!(utility_normalized.contains("def utility_method(data):"));

    let create_default = definition(&analyzer, "documented.DocumentedClass.create_default");
    let create_default_source = analyzer.get_source(&create_default, true).unwrap();
    let create_default_normalized = normalize_nonempty_lines(&create_default_source);
    assert!(create_default_normalized.contains("Comment before class method"));
    assert!(create_default_normalized.contains("@classmethod"));
    assert!(create_default_normalized.contains("def create_default(cls):"));
}

#[test]
fn test_python_comment_expansion_edge_cases_and_dual_range_extraction() {
    let analyzer = fixture_analyzer();

    let constructor = definition(&analyzer, "documented.DocumentedClass.__init__");
    let constructor_source = analyzer.get_source(&constructor, true).unwrap();
    let constructor_normalized = normalize_nonempty_lines(&constructor_source);
    assert!(constructor_normalized.contains("Comment before constructor"));
    assert!(constructor_normalized.contains("def __init__(self, value: int):"));

    let inner_method = definition(&analyzer, "documented.OuterClass$InnerClass.inner_method");
    let inner_method_source = analyzer.get_source(&inner_method, true).unwrap();
    let inner_method_normalized = normalize_nonempty_lines(&inner_method_source);
    assert!(inner_method_normalized.contains("Comment before inner method"));
    assert!(inner_method_normalized.contains("def inner_method(self):"));
    assert!(inner_method_normalized.contains("\"\"\""));

    let documented_class = definition(&analyzer, "documented.DocumentedClass");
    let class_with_comments = analyzer.get_source(&documented_class, true).unwrap();
    let class_without_comments = analyzer.get_source(&documented_class, false).unwrap();
    assert!(normalize_nonempty_lines(&class_with_comments).starts_with("# Comment before class"));
    assert!(
        normalize_nonempty_lines(&class_without_comments).starts_with("class DocumentedClass:")
    );

    let get_value = definition(&analyzer, "documented.DocumentedClass.get_value");
    let method_with_comments = analyzer.get_source(&get_value, true).unwrap();
    let method_without_comments = analyzer.get_source(&get_value, false).unwrap();
    assert!(
        normalize_nonempty_lines(&method_with_comments)
            .starts_with("# Comment before instance method")
    );
    assert!(normalize_nonempty_lines(&method_without_comments).starts_with("def get_value(self):"));
}

#[test]
fn test_python_duplicate_fields_and_property_filtering() {
    let analyzer = fixture_analyzer();

    let duplicate_fields = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "duplictad_fields_test.py",
    );
    let declarations = analyzer.get_declarations(&duplicate_fields);

    let srcfiles_fields: Vec<_> = declarations
        .iter()
        .filter(|cu| cu.is_field() && cu.identifier() == "SRCFILES")
        .collect();
    assert_eq!(1, srcfiles_fields.len());
    assert_eq!(
        "duplictad_fields_test.SRCFILES",
        srcfiles_fields[0].fq_name()
    );

    let local_var_fields: Vec<_> = declarations
        .iter()
        .filter(|cu| cu.is_field() && cu.fq_name().contains("LOCAL_VAR"))
        .collect();
    assert_eq!(0, local_var_fields.len());

    let class_var_fields: Vec<_> = declarations
        .iter()
        .filter(|cu| cu.is_field() && cu.identifier() == "CLASS_VAR")
        .collect();
    assert_eq!(1, class_var_fields.len());
    assert!(class_var_fields[0].fq_name().contains(".CLASS_VAR"));

    let method_var_fields: Vec<_> = declarations
        .iter()
        .filter(|cu| cu.is_field() && cu.identifier() == "METHOD_VAR")
        .collect();
    assert_eq!(0, method_var_fields.len());

    let value_getters: Vec<_> = declarations
        .iter()
        .filter(|cu| cu.is_function() && cu.fq_name() == "duplictad_fields_test.PropertyTest.value")
        .collect();
    let name_getters: Vec<_> = declarations
        .iter()
        .filter(|cu| cu.is_function() && cu.fq_name() == "duplictad_fields_test.PropertyTest.name")
        .collect();
    assert_eq!(1, value_getters.len());
    assert_eq!(1, name_getters.len());

    assert_eq!(
        1,
        declarations
            .iter()
            .filter(|cu| cu.is_function() && cu.identifier().contains("test_uncertainty_setter"))
            .count()
    );
    assert_eq!(
        1,
        declarations
            .iter()
            .filter(|cu| cu.is_function() && cu.identifier().contains("set_temperature"))
            .count()
    );
    assert_eq!(
        1,
        declarations
            .iter()
            .filter(|cu| cu.is_function() && cu.identifier().contains("process_data_setter"))
            .count()
    );
}

#[test]
fn test_python_property_setter_filtering() {
    let analyzer = fixture_analyzer();
    let test_file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "property_setter_test.py",
    );
    let declarations = analyzer.get_declarations(&test_file);

    let classes: Vec<_> = declarations.iter().filter(|cu| cu.is_class()).collect();
    assert_eq!(1, classes.len());
    assert_eq!("MplTimeConverter", classes[0].identifier());

    let methods: Vec<_> = declarations.iter().filter(|cu| cu.is_function()).collect();
    assert_eq!(3, methods.len());
    assert!(
        methods
            .iter()
            .any(|cu| cu.fq_name() == "property_setter_test.MplTimeConverter.format")
    );
    assert!(
        methods
            .iter()
            .any(|cu| cu.fq_name() == "property_setter_test.MplTimeConverter.value")
    );
    assert!(
        methods
            .iter()
            .any(|cu| cu.fq_name() == "property_setter_test.MplTimeConverter.regular_method")
    );
    assert_eq!(
        1,
        methods
            .iter()
            .filter(|cu| cu.identifier() == "format")
            .count()
    );
    assert_eq!(
        1,
        methods
            .iter()
            .filter(|cu| cu.identifier() == "value")
            .count()
    );
}

#[test]
fn test_astropy_duplicate_function_names_and_disambiguation() {
    let analyzer = fixture_analyzer();

    let astropy_duplicate = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "astropy_duplicate_test.py",
    );
    let declarations = analyzer.get_declarations(&astropy_duplicate);

    let log_d_classes: Vec<_> = declarations
        .iter()
        .filter(|cu| cu.is_class() && cu.fq_name().contains("LogDRepresentation"))
        .collect();
    assert_eq!(2, log_d_classes.len());

    let fq_names: BTreeSet<_> = log_d_classes.iter().map(|cu| cu.fq_name()).collect();
    assert_eq!(2, fq_names.len());
    assert!(fq_names.contains("astropy_duplicate_test.test_minimal_subclass$LogDRepresentation"));
    assert!(fq_names.contains("astropy_duplicate_test.another_test_function$LogDRepresentation"));

    let file_a = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "disambiguation_test_a.py",
    );
    let file_b = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "disambiguation_test_b.py",
    );
    let classes_a: Vec<_> = analyzer
        .get_declarations(&file_a)
        .into_iter()
        .filter(|cu| cu.is_class() && cu.fq_name().contains("LocalClass"))
        .collect();
    let classes_b: Vec<_> = analyzer
        .get_declarations(&file_b)
        .into_iter()
        .filter(|cu| cu.is_class() && cu.fq_name().contains("LocalClass"))
        .collect();

    assert_eq!(1, classes_a.len());
    assert_eq!(1, classes_b.len());
    assert_eq!(
        "disambiguation_test_a.test_func$LocalClass",
        classes_a[0].fq_name()
    );
    assert_eq!(
        "disambiguation_test_b.test_func$LocalClass",
        classes_b[0].fq_name()
    );
}

#[test]
fn test_nested_and_underscore_prefixed_function_local_classes() {
    let analyzer = fixture_analyzer();

    let nested = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "nested_local_classes.py",
    );
    let declarations = analyzer.get_declarations(&nested);
    let classes: Vec<_> = declarations.iter().filter(|cu| cu.is_class()).collect();
    assert_eq!(3, classes.len());

    let outer_local = classes
        .iter()
        .find(|cu| cu.fq_name() == "nested_local_classes.outer_function$OuterLocal")
        .unwrap();
    let inner_local = classes
        .iter()
        .find(|cu| cu.fq_name() == "nested_local_classes.outer_function$OuterLocal$InnerLocal")
        .unwrap();
    let deep_local = classes
        .iter()
        .find(|cu| {
            cu.fq_name() == "nested_local_classes.outer_function$OuterLocal$InnerLocal$DeepLocal"
        })
        .unwrap();

    assert!(
        analyzer
            .get_direct_children(inner_local)
            .iter()
            .any(|cu| cu == *deep_local)
    );
    assert!(
        analyzer
            .get_direct_children(outer_local)
            .iter()
            .any(|cu| cu == *inner_local)
    );

    let methods: Vec<_> = declarations
        .iter()
        .filter(|cu| cu.is_function() && cu.fq_name().contains("$Out"))
        .collect();
    assert_eq!(2, methods.len());
    assert!(methods.iter().any(|cu| {
        cu.fq_name() == "nested_local_classes.outer_function$OuterLocal$InnerLocal.inner_method"
    }));
    assert!(
        methods
            .iter()
            .any(|cu| cu.fq_name() == "nested_local_classes.outer_function$OuterLocal.outer_method")
    );

    let underscore = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "underscore_functions.py",
    );
    let underscore_classes: Vec<_> = analyzer
        .get_declarations(&underscore)
        .into_iter()
        .filter(|cu| cu.is_class())
        .collect();
    assert_eq!(5, underscore_classes.len());
    assert!(
        underscore_classes
            .iter()
            .any(|cu| cu.fq_name() == "underscore_functions._private_function$LocalClass")
    );
    assert!(
        underscore_classes
            .iter()
            .any(|cu| cu.fq_name() == "underscore_functions.__dunder_function__$AnotherLocal")
    );
    let nested_class = underscore_classes
        .iter()
        .find(|cu| cu.fq_name() == "underscore_functions._PrivateClass$NestedClass")
        .unwrap();
    let private_class = underscore_classes
        .iter()
        .find(|cu| cu.fq_name() == "underscore_functions._PrivateClass")
        .unwrap();
    assert!(
        analyzer
            .get_direct_children(private_class)
            .iter()
            .any(|cu| cu == nested_class)
    );
}

#[test]
fn test_function_redefinition_and_duplicate_children() {
    let analyzer = fixture_analyzer();

    let file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "function_redefinition.py",
    );
    let declarations = analyzer.get_declarations(&file);
    let functions: Vec<_> = declarations
        .iter()
        .filter(|cu| cu.is_function() && cu.fq_name().ends_with(".my_function"))
        .collect();
    assert_eq!(1, functions.len());
    let my_function = functions[0];

    let classes: Vec<_> = declarations.iter().filter(|cu| cu.is_class()).collect();
    assert_eq!(2, classes.len());
    assert!(
        classes
            .iter()
            .any(|cu| cu.fq_name() == "function_redefinition.MyClass")
    );
    let second_local = classes
        .iter()
        .find(|cu| cu.fq_name() == "function_redefinition.my_function$SecondLocal")
        .unwrap();
    assert!(!classes.iter().any(|cu| cu.fq_name().contains("FirstLocal")));
    let function_children = analyzer.get_direct_children(my_function);
    assert_eq!(1, function_children.len());
    assert!(function_children.iter().any(|cu| cu == *second_local));

    let file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "function_redefinition_with_imports.py",
    );
    let declarations = analyzer.get_declarations(&file);
    let my_functions: Vec<_> = declarations
        .iter()
        .filter(|cu| cu.is_function() && cu.short_name() == "my_function")
        .collect();
    assert_eq!(1, my_functions.len());
    let my_function = my_functions[0];
    let classes: Vec<_> = declarations.iter().filter(|cu| cu.is_class()).collect();
    let second_local = classes
        .iter()
        .find(|cu| cu.fq_name() == "function_redefinition_with_imports.my_function$SecondLocal")
        .unwrap();
    assert!(!classes.iter().any(|cu| cu.fq_name().contains("FirstLocal")));
    assert!(
        analyzer
            .get_direct_children(my_function)
            .iter()
            .any(|cu| cu == *second_local)
    );
    assert!(declarations.iter().any(|cu| cu.is_function()
        && cu.fq_name() == "function_redefinition_with_imports.other_function"));
    assert!(
        classes
            .iter()
            .any(|cu| cu.fq_name() == "function_redefinition_with_imports.MyClass")
    );

    let file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "duplicate_children.py",
    );
    let declarations = analyzer.get_declarations(&file);
    let test_duplicates = declarations
        .iter()
        .find(|cu| cu.is_class() && cu.fq_name() == "duplicate_children.TestDuplicates")
        .unwrap();
    let children = analyzer.get_direct_children(test_duplicates);
    assert_eq!(
        1,
        children
            .iter()
            .filter(|cu| cu.is_function() && cu.identifier() == "method")
            .count()
    );
    assert_eq!(
        1,
        children
            .iter()
            .filter(|cu| {
                cu.is_class()
                    && cu.short_name().contains("Inner")
                    && !cu.short_name().contains("Unique")
            })
            .count()
    );
    assert!(
        children
            .iter()
            .any(|cu| cu.is_function() && cu.identifier() == "unique_method")
    );
    assert!(
        children
            .iter()
            .any(|cu| cu.is_class() && cu.short_name().contains("UniqueInner"))
    );
}

#[test]
fn test_code_units_are_deduplicated_and_conditionals_are_captured() {
    let analyzer = fixture_analyzer();

    let all_decls = analyzer.get_all_declarations();
    let unique: BTreeSet<_> = all_decls.iter().cloned().collect();
    assert_eq!(unique.len(), all_decls.len());

    let top_level: Vec<_> = analyzer
        .get_analyzed_files()
        .into_iter()
        .flat_map(|file| analyzer.get_top_level_declarations(&file))
        .collect();
    let unique_top_level: BTreeSet<_> = top_level.iter().cloned().collect();
    assert_eq!(unique_top_level.len(), top_level.len());

    let base_py = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "conditional_pkg/base.py",
    );
    let declarations = analyzer.get_declarations(&base_py);
    let classes: Vec<_> = declarations.iter().filter(|cu| cu.is_class()).collect();
    let functions: Vec<_> = declarations.iter().filter(|cu| cu.is_function()).collect();
    let fields: Vec<_> = declarations.iter().filter(|cu| cu.is_field()).collect();

    assert!(
        classes
            .iter()
            .any(|cu| cu.fq_name() == "conditional_pkg.base.Base")
    );
    assert!(
        classes
            .iter()
            .any(|cu| cu.fq_name() == "conditional_pkg.base.Base$Config")
    );
    assert!(
        classes
            .iter()
            .any(|cu| cu.fq_name() == "conditional_pkg.base.FallbackBase")
    );
    assert!(
        classes
            .iter()
            .any(|cu| cu.fq_name() == "conditional_pkg.base.TryClass")
    );
    assert!(
        classes
            .iter()
            .any(|cu| cu.fq_name() == "conditional_pkg.base.ExceptClass")
    );

    assert!(
        functions
            .iter()
            .any(|cu| cu.identifier() == "conditional_function")
    );
    assert!(functions.iter().any(|cu| cu.identifier() == "try_function"));
    assert!(
        functions
            .iter()
            .any(|cu| cu.identifier() == "except_function")
    );
    assert!(
        functions
            .iter()
            .any(|cu| cu.identifier() == "elif_function")
    );
    assert!(
        functions
            .iter()
            .any(|cu| cu.identifier() == "try_else_function")
    );
    assert!(
        functions
            .iter()
            .any(|cu| cu.identifier() == "finally_function")
    );
    assert!(
        functions
            .iter()
            .any(|cu| cu.identifier() == "outer_conditional_function")
    );
    assert!(
        functions
            .iter()
            .any(|cu| cu.identifier() == "async_top_level")
    );
    assert!(functions.iter().any(|cu| cu.identifier() == "async_in_if"));
    assert!(functions.iter().any(|cu| cu.identifier() == "async_in_try"));

    assert!(fields.iter().any(|cu| cu.identifier() == "CONDITIONAL_VAR"));
    assert!(fields.iter().any(|cu| cu.identifier() == "TRY_VAR"));
    assert!(fields.iter().any(|cu| cu.identifier() == "EXCEPT_VAR"));
    assert!(fields.iter().any(|cu| cu.identifier() == "WITH_VAR"));
    assert!(fields.iter().any(|cu| cu.identifier() == "ELIF_VAR"));
    assert!(fields.iter().any(|cu| cu.identifier() == "TRY_ELSE_VAR"));
    assert!(fields.iter().any(|cu| cu.identifier() == "FINALLY_VAR"));

    assert!(
        !functions
            .iter()
            .any(|cu| cu.identifier() == "inner_nested_function")
    );
    assert!(!fields.iter().any(|cu| cu.identifier() == "INNER_VAR"));
    assert!(
        !functions
            .iter()
            .any(|cu| cu.identifier() == "nested_if_try_function")
    );
    assert!(
        !functions
            .iter()
            .any(|cu| cu.identifier() == "nested_if_except_function")
    );
    assert!(
        !fields
            .iter()
            .any(|cu| cu.identifier() == "NESTED_IF_TRY_VAR")
    );
    assert!(
        !functions
            .iter()
            .any(|cu| cu.identifier() == "deeply_nested_loop_function")
    );
    assert!(
        !fields
            .iter()
            .any(|cu| cu.identifier() == "DEEPLY_NESTED_VAR")
    );

    let subclass_py = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "conditional_pkg/subclass.py",
    );
    let subclass_decls = analyzer.get_declarations(&subclass_py);
    let my_subclass = subclass_decls
        .iter()
        .find(|cu| cu.identifier() == "MySubclass")
        .unwrap();
    assert!(
        analyzer
            .get_skeleton(my_subclass)
            .unwrap()
            .contains("(Base)")
    );

    let import_info = analyzer.import_info_of(&subclass_py);
    assert!(import_info.iter().any(|imp| {
        imp.raw_snippet
            .contains("from conditional_pkg.base import Base")
    }));

    let base_class = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|cu| cu.fq_name() == "conditional_pkg.base.Base")
        .unwrap();
    let ancestors = analyzer.get_direct_ancestors(my_subclass);
    assert_eq!(1, ancestors.len());
    assert_eq!(base_class.fq_name(), ancestors[0].fq_name());
}
