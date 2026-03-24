use brokk_analyzer::ProjectFile;
use std::process::Command;

fn summarize_bin() -> &'static str {
    env!("CARGO_BIN_EXE_summarize")
}

#[test]
fn summarizes_fqcn_with_direct_ancestors() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();

    ProjectFile::new(root.clone(), "Base.java")
        .write("public class Base { public void baseMethod() {} }")
        .unwrap();
    ProjectFile::new(root.clone(), "Child.java")
        .write("public class Child extends Base { public void childMethod() {} }")
        .unwrap();

    let output = Command::new(summarize_bin())
        .current_dir(&root)
        .arg("Child")
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("package (default package);"));
    assert!(stdout.contains("public class Child extends Base {"));
    assert!(stdout.contains("// Direct ancestors of Child: Base"));
    assert!(stdout.contains("public class Base {"));
}

#[test]
fn summarizes_absolute_file_paths() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let file = ProjectFile::new(root.clone(), "demo/A.java");
    file.write(
        r#"
package demo;
public class A {
    void method1() {}
}
"#,
    )
    .unwrap();

    let output = Command::new(summarize_bin())
        .current_dir(&root)
        .arg(file.abs_path())
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("package demo;"));
    assert!(stdout.contains("public class A {"));
    assert!(stdout.contains("void method1()"));
}
