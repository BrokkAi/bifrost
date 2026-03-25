use brokk_analyzer::{IAnalyzer, ProjectFile, PythonAnalyzer, TestProject};

fn inline_project(path: &str, source: &str) -> (TestProject, ProjectFile) {
    let temp = tempfile::tempdir().unwrap();
    let file = ProjectFile::new(temp.path().to_path_buf(), path);
    file.write(source).unwrap();
    (
        TestProject::new(temp.keep(), brokk_analyzer::Language::Python),
        file,
    )
}

#[test]
fn test_decorated_top_level_function_and_class() {
    let (project, file) = inline_project(
        "decorators.py",
        r#"
        def deco1(x):
            return x

        def class_deco(x):
            return x

        @deco1
        def top_func():
            pass

        @class_deco
        class TopClass:
            @deco1
            def method(self):
                pass

            @staticmethod
            @deco1
            def static_m():
                pass
        "#,
    );
    let analyzer = PythonAnalyzer::from_project(project);
    let declarations = analyzer.get_declarations(&file);

    assert!(
        declarations
            .iter()
            .any(|cu| cu.fq_name() == "decorators.top_func")
    );
    assert!(
        declarations
            .iter()
            .any(|cu| cu.fq_name() == "decorators.TopClass")
    );
    assert!(
        declarations
            .iter()
            .any(|cu| cu.fq_name() == "decorators.TopClass.method")
    );
    assert!(
        declarations
            .iter()
            .any(|cu| cu.fq_name() == "decorators.TopClass.static_m")
    );
}

#[test]
fn test_decorated_nested_in_function_and_class() {
    let (project, file) = inline_project(
        "decorators.py",
        r#"
        def deco1(x):
            return x

        def class_deco(x):
            return x

        def outer():
            @class_deco
            class Inner:
                @deco1
                def im(self):
                    pass
            return Inner
        "#,
    );
    let analyzer = PythonAnalyzer::from_project(project);
    let declarations = analyzer.get_declarations(&file);

    assert!(
        declarations
            .iter()
            .any(|cu| cu.fq_name() == "decorators.outer$Inner")
    );
    assert!(
        declarations
            .iter()
            .any(|cu| cu.fq_name() == "decorators.outer$Inner.im")
    );
}

#[test]
fn test_decorated_declarations_in_top_level_conditional() {
    let (project, file) = inline_project(
        "decorators.py",
        r#"
        def deco1(x):
            return x

        def class_deco(x):
            return x

        if True:
            @deco1
            def cond_func():
                pass

            @class_deco
            class CondClass:
                pass
        "#,
    );
    let analyzer = PythonAnalyzer::from_project(project);
    let declarations = analyzer.get_declarations(&file);

    assert!(
        declarations
            .iter()
            .any(|cu| cu.fq_name() == "decorators.cond_func")
    );
    assert!(
        declarations
            .iter()
            .any(|cu| cu.fq_name() == "decorators.CondClass")
    );
}
