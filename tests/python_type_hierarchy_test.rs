use brokk_analyzer::{
    IAnalyzer, ImportAnalysisProvider, ProjectFile, PythonAnalyzer, TestProject,
    TypeHierarchyProvider,
};

fn fixture_project() -> TestProject {
    TestProject::new(
        std::fs::canonicalize("tests/fixtures/testcode-py").unwrap(),
        brokk_analyzer::Language::Python,
    )
}

#[test]
fn test_python_type_hierarchy() {
    let analyzer = PythonAnalyzer::from_project(fixture_project());

    let simple_py = ProjectFile::new(analyzer.project().root().to_path_buf(), "inheritance/simple.py");
    let simple_decls = analyzer.get_declarations(&simple_py);
    let dog = simple_decls.iter().find(|cu| cu.identifier() == "Dog").unwrap();
    let animal = simple_decls.iter().find(|cu| cu.identifier() == "Animal").unwrap();
    let dog_ancestors = analyzer.get_direct_ancestors(dog);
    assert_eq!(1, dog_ancestors.len());
    assert_eq!(animal.fq_name(), dog_ancestors[0].fq_name());

    let multilevel_py =
        ProjectFile::new(analyzer.project().root().to_path_buf(), "inheritance/multilevel.py");
    let multilevel_decls = analyzer.get_declarations(&multilevel_py);
    let child = multilevel_decls.iter().find(|cu| cu.identifier() == "Child").unwrap();
    assert_eq!(1, analyzer.get_direct_ancestors(child).len());
    assert_eq!(2, analyzer.get_ancestors(child).len());

    let child_py = ProjectFile::new(analyzer.project().root().to_path_buf(), "inheritance/child.py");
    let child_file_decls = analyzer.get_declarations(&child_py);
    let bird = child_file_decls.iter().find(|cu| cu.identifier() == "Bird").unwrap();
    assert_eq!(1, analyzer.get_direct_ancestors(bird).len());

    let multiple_py =
        ProjectFile::new(analyzer.project().root().to_path_buf(), "inheritance/multiple.py");
    let multiple_decls = analyzer.get_declarations(&multiple_py);
    let duck = multiple_decls.iter().find(|cu| cu.identifier() == "Duck").unwrap();
    assert_eq!(2, analyzer.get_direct_ancestors(duck).len());
}

#[test]
fn test_relative_import_and_inheritance_cases() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();

    ProjectFile::new(root.to_path_buf(), "mypackage/__init__.py")
        .write("# Package marker\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "mypackage/subdir/__init__.py")
        .write("# Subpackage marker\n")
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "mypackage/base.py")
        .write(
            r#"
            class BaseClass:
                def base_method(self):
                    pass
            "#,
        )
        .unwrap();
    ProjectFile::new(root.to_path_buf(), "mypackage/subdir/child.py")
        .write(
            r#"
            from ..base import BaseClass

            class ChildClass(BaseClass):
                def child_method(self):
                    pass
            "#,
        )
        .unwrap();

    let analyzer = PythonAnalyzer::from_project(TestProject::new(
        root,
        brokk_analyzer::Language::Python,
    ));
    let child_file = ProjectFile::new(root.to_path_buf(), "mypackage/subdir/child.py");
    let imports = analyzer.imported_code_units_of(&child_file);
    assert!(imports.iter().any(|cu| cu.fq_name() == "mypackage.base.BaseClass"));

    let child_decl = analyzer
        .get_definitions("mypackage.subdir.child.ChildClass")
        .into_iter()
        .next()
        .unwrap();
    let ancestors = analyzer.get_direct_ancestors(&child_decl);
    assert_eq!(1, ancestors.len());
    assert_eq!("mypackage.base.BaseClass", ancestors[0].fq_name());
}

#[test]
fn test_packaged_function_local_classes_and_top_level_names() {
    let analyzer = PythonAnalyzer::from_project(fixture_project());
    let packaged = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "mypackage/packaged_functions.py",
    );
    let declarations = analyzer.get_declarations(&packaged);

    let my_function = declarations
        .iter()
        .find(|cu| cu.identifier() == "my_function")
        .unwrap();
    let local_class = declarations
        .iter()
        .find(|cu| cu.fq_name().contains("LocalClass"))
        .unwrap();
    let function_children = analyzer.get_direct_children(my_function);
    assert!(function_children
        .iter()
        .any(|child| child.fq_name() == local_class.fq_name()));

    let test_utils = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "tests/units/utils/test_utils.py",
    );
    let top_level_classes: Vec<_> = analyzer
        .get_declarations(&test_utils)
        .into_iter()
        .filter(|cu| cu.is_class())
        .filter(|cu| !cu.fq_name().contains(".test_backend_variable_cls$"))
        .collect();
    assert!(top_level_classes
        .iter()
        .any(|cu| cu.fq_name() == "tests.units.utils.test_utils.ExampleTestState"));
    assert!(top_level_classes
        .iter()
        .any(|cu| cu.fq_name() == "tests.units.utils.test_utils.DataFrame"));
}
