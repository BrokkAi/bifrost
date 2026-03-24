use brokk_analyzer::{
    DeclarationKind, IAnalyzer, JavaAnalyzer, Language, ProjectFile, TestProject,
};

fn analyzer_for(code: &str) -> (tempfile::TempDir, JavaAnalyzer, ProjectFile, String) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let file = ProjectFile::new(root.clone(), "Test.java");
    file.write(code).unwrap();
    let project = TestProject::new(root, Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);
    (temp, analyzer, file, code.to_string())
}

#[test]
fn finds_constructor_parameter_declaration() {
    let code = r#"
public class Test {
    public Test(String channel) {
        this.use(channel);
    }
}
"#;
    let (_temp, analyzer, file, content) = analyzer_for(code);
    let start = content.find("channel);").unwrap();
    let start_byte = content[..start].len();
    let end_byte = start_byte + "channel".len();

    let result = analyzer
        .find_nearest_declaration(&file, start_byte, end_byte, "channel")
        .unwrap();
    assert_eq!(DeclarationKind::Parameter, result.kind);
    assert_eq!("channel", result.identifier);
}

#[test]
fn finds_local_variable_declaration() {
    let code = r#"
public class Test {
    public void method() {
        String localVar = "hello";
        System.out.println(localVar);
    }
}
"#;
    let (_temp, analyzer, file, content) = analyzer_for(code);
    let start = content.find("localVar);").unwrap();
    let start_byte = content[..start].len();
    let end_byte = start_byte + "localVar".len();

    let result = analyzer
        .find_nearest_declaration(&file, start_byte, end_byte, "localVar")
        .unwrap();
    assert_eq!(DeclarationKind::LocalVariable, result.kind);
    assert_eq!("localVar", result.identifier);
}

#[test]
fn finds_enhanced_for_and_resource_and_lambda_declarations() {
    let code = r#"
import java.io.*;
import java.util.List;
public class Test {
    public void method(List<String> items) throws IOException {
        for (String item : items) {
            System.out.println(item);
        }
        try (InputStream stream = new FileInputStream("x")) {
            stream.read();
        }
        items.forEach(x -> System.out.println(x));
    }
}
"#;
    let (_temp, analyzer, file, content) = analyzer_for(code);

    let item_start = content.find("item);").unwrap();
    let item_start_byte = content[..item_start].len();
    let item = analyzer
        .find_nearest_declaration(
            &file,
            item_start_byte,
            item_start_byte + "item".len(),
            "item",
        )
        .unwrap();
    assert_eq!(DeclarationKind::EnhancedForVariable, item.kind);

    let stream_start = content.find("stream.read").unwrap();
    let stream_start_byte = content[..stream_start].len();
    let stream = analyzer
        .find_nearest_declaration(
            &file,
            stream_start_byte,
            stream_start_byte + "stream".len(),
            "stream",
        )
        .unwrap();
    assert_eq!(DeclarationKind::ResourceVariable, stream.kind);

    let x_start = content.rfind("println(x)").unwrap() + "println(".len();
    let x_start_byte = content[..x_start].len();
    let x = analyzer
        .find_nearest_declaration(&file, x_start_byte, x_start_byte + 1, "x")
        .unwrap();
    assert_eq!(DeclarationKind::LambdaParameter, x.kind);
}

#[test]
fn access_expression_filters_locals_but_keeps_field_access() {
    let code = r#"
public class ShadowTest {
    private String channel;
    public ShadowTest(String channel) {
        System.out.println(channel);
        System.out.println(this.channel);
    }
}
"#;
    let (_temp, analyzer, file, content) = analyzer_for(code);

    let local_use = content.find("println(channel)").unwrap() + "println(".len();
    let local_start = content[..local_use].len();
    assert!(!analyzer.is_access_expression(&file, local_start, local_start + "channel".len()));

    let field_use = content.find("this.channel").unwrap() + "this.".len();
    let field_start = content[..field_use].len();
    assert!(analyzer.is_access_expression(&file, field_start, field_start + "channel".len()));
}
