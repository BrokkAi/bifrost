use brokk_analyzer::{IAnalyzer, ProjectFile, PythonAnalyzer, TestProject};

fn inline_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempfile::tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), brokk_analyzer::Language::Python)
}

#[test]
fn module_code_unit_created_with_top_level_children_only() {
    let project = inline_project(&[(
        "mod.py",
        r#"
        class A:
            class Inner:
                pass
        def f():
            pass
        x = 1
        "#,
    )]);
    let analyzer = PythonAnalyzer::from_project(project);

    let module = analyzer
        .get_definitions("mod")
        .into_iter()
        .find(|code_unit| code_unit.is_module())
        .unwrap();
    let child_fqns: Vec<_> = analyzer
        .get_direct_children(&module)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();

    assert_eq!(vec!["mod.A", "mod.f", "mod.x"], child_fqns);
}

#[test]
fn module_code_unit_created_for_init_py_package_name() {
    let project = inline_project(&[(
        "pkg/__init__.py",
        r#"
        class A:
            pass
        def f():
            pass
        "#,
    )]);
    let analyzer = PythonAnalyzer::from_project(project);

    let module = analyzer
        .get_definitions("pkg")
        .into_iter()
        .find(|code_unit| code_unit.is_module())
        .unwrap();
    let child_fqns: Vec<_> = analyzer
        .get_direct_children(&module)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();

    assert_eq!(vec!["pkg.A", "pkg.f"], child_fqns);
}

#[test]
fn module_code_units_are_per_file_in_packaged_directory() {
    let project = inline_project(&[
        (
            "pkg/a.py",
            r#"
            class A:
                pass
            "#,
        ),
        (
            "pkg/b.py",
            r#"
            def f():
                pass
            "#,
        ),
    ]);
    let analyzer = PythonAnalyzer::from_project(project);

    let mod_a = analyzer
        .get_definitions("pkg.a")
        .into_iter()
        .find(|code_unit| code_unit.is_module())
        .unwrap();
    let mod_b = analyzer
        .get_definitions("pkg.b")
        .into_iter()
        .find(|code_unit| code_unit.is_module())
        .unwrap();

    let children_a: Vec<_> = analyzer
        .get_direct_children(&mod_a)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();
    let children_b: Vec<_> = analyzer
        .get_direct_children(&mod_b)
        .into_iter()
        .map(|code_unit| code_unit.fq_name())
        .collect();

    assert_eq!(vec!["pkg.a.A"], children_a);
    assert_eq!(vec!["pkg.b.f"], children_b);
}
