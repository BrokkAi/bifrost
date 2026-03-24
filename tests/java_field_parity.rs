use brokk_analyzer::{
    DeclarationKind, IAnalyzer, JavaAnalyzer, Language, ProjectFile, TestProject,
};
use std::collections::BTreeSet;

fn analyzer_for(
    code: &str,
    file_name: &str,
) -> (tempfile::TempDir, JavaAnalyzer, ProjectFile, String) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let file = ProjectFile::new(root.clone(), file_name);
    file.write(code).unwrap();
    let project = TestProject::new(root, Language::Java);
    let analyzer = JavaAnalyzer::from_project(project);
    (temp, analyzer, file, code.to_string())
}

#[test]
fn interface_constants_and_multiple_declarators_match_java_analyzer_test() {
    let code = r#"
import java.util.List;
public interface ComplexConstants {
    String SYNTAX_STYLE_NONE = "text/plain";
    String SYNTAX_STYLE_ACTIONSCRIPT = "text/actionscript";
    String SYNTAX_STYLE_C = "text/c";
    int DEFAULT_PRIORITY = 100;
    int CONST_A = 1, CONST_B = 2;
    String NAME_X = "x", NAME_Y = "y", NAME_Z = "z";
    List<String> ITEMS = List.of("a", "b");
    @Deprecated
    String DEPRECATED_VAL = "old";
    @SuppressWarnings("unchecked")
    List RAW_LIST = List.of();
}
"#;
    let (_temp, analyzer, _file, _content) = analyzer_for(code, "ComplexConstants.java");

    let declarations = analyzer.get_all_declarations();
    assert!(
        declarations
            .iter()
            .any(|code_unit| code_unit.fq_name() == "ComplexConstants")
    );

    let field_names: BTreeSet<_> = declarations
        .into_iter()
        .filter(|code_unit| code_unit.is_field())
        .map(|code_unit| code_unit.identifier().to_string())
        .collect();

    for expected in [
        "SYNTAX_STYLE_NONE",
        "SYNTAX_STYLE_ACTIONSCRIPT",
        "SYNTAX_STYLE_C",
        "DEFAULT_PRIORITY",
        "CONST_A",
        "CONST_B",
        "NAME_X",
        "NAME_Y",
        "NAME_Z",
        "ITEMS",
        "DEPRECATED_VAL",
        "RAW_LIST",
    ] {
        assert!(field_names.contains(expected), "missing field {expected}");
    }
}

#[test]
fn field_skeletons_preserve_literal_initializers_and_omit_complex_ones() {
    let code = r#"
import java.util.List;
public class Initializers {
    public int x = 1, y = 2;
    public static final String LITERAL = "hello";
    public static final int NUMBER = 42;
    public static final boolean FLAG_TRUE = true;
    public static final boolean FLAG_FALSE = false;
    public static final Object NULL_VAL = null;
    public static final Object COMPLEX = new Object();
    private final List<String> LIST = List.of("a");
}
"#;
    let (_temp, analyzer, _file, _content) = analyzer_for(code, "Initializers.java");

    assert_eq!(
        Some("public int x = 1;".to_string()),
        analyzer
            .get_definitions("Initializers.x")
            .first()
            .and_then(|code_unit| analyzer.get_skeleton(code_unit))
    );
    assert_eq!(
        Some("public int y = 2;".to_string()),
        analyzer
            .get_definitions("Initializers.y")
            .first()
            .and_then(|code_unit| analyzer.get_skeleton(code_unit))
    );
    assert_eq!(
        Some("public static final String LITERAL = \"hello\";".to_string()),
        analyzer
            .get_definitions("Initializers.LITERAL")
            .first()
            .and_then(|code_unit| analyzer.get_skeleton(code_unit))
    );
    assert_eq!(
        Some("public static final int NUMBER = 42;".to_string()),
        analyzer
            .get_definitions("Initializers.NUMBER")
            .first()
            .and_then(|code_unit| analyzer.get_skeleton(code_unit))
    );
    assert_eq!(
        Some("public static final boolean FLAG_TRUE = true;".to_string()),
        analyzer
            .get_definitions("Initializers.FLAG_TRUE")
            .first()
            .and_then(|code_unit| analyzer.get_skeleton(code_unit))
    );
    assert_eq!(
        Some("public static final boolean FLAG_FALSE = false;".to_string()),
        analyzer
            .get_definitions("Initializers.FLAG_FALSE")
            .first()
            .and_then(|code_unit| analyzer.get_skeleton(code_unit))
    );
    assert_eq!(
        Some("public static final Object NULL_VAL = null;".to_string()),
        analyzer
            .get_definitions("Initializers.NULL_VAL")
            .first()
            .and_then(|code_unit| analyzer.get_skeleton(code_unit))
    );
    assert_eq!(
        Some("public static final Object COMPLEX;".to_string()),
        analyzer
            .get_definitions("Initializers.COMPLEX")
            .first()
            .and_then(|code_unit| analyzer.get_skeleton(code_unit))
    );
    assert_eq!(
        Some("private final List<String> LIST;".to_string()),
        analyzer
            .get_definitions("Initializers.LIST")
            .first()
            .and_then(|code_unit| analyzer.get_skeleton(code_unit))
    );
}

#[test]
fn final_varargs_and_overloads_keep_distinct_signatures() {
    let code = r#"
public class FinalVarargs {
    public void foo(final Object... args) {}
    public void bar(final String s) {}
    public void baz(final int... numbers) {}
    public void process(String single) {}
    public void process(String... multiple) {}
}
"#;
    let (_temp, analyzer, _file, _content) = analyzer_for(code, "FinalVarargs.java");

    assert_eq!(
        Some("(Object[])"),
        analyzer
            .get_definitions("FinalVarargs.foo")
            .first()
            .and_then(|code_unit| code_unit.signature())
    );
    assert_eq!(
        Some("(String)"),
        analyzer
            .get_definitions("FinalVarargs.bar")
            .first()
            .and_then(|code_unit| code_unit.signature())
    );
    assert_eq!(
        Some("(int[])"),
        analyzer
            .get_definitions("FinalVarargs.baz")
            .first()
            .and_then(|code_unit| code_unit.signature())
    );

    let overload_signatures: BTreeSet<_> = analyzer
        .get_definitions("FinalVarargs.process")
        .into_iter()
        .filter_map(|code_unit| code_unit.signature().map(ToOwned::to_owned))
        .collect();
    assert_eq!(
        BTreeSet::from(["(String)".to_string(), "(String[])".to_string()]),
        overload_signatures
    );
}

#[test]
fn access_expression_comment_filtering_and_method_parameters_match_java_analyzer_test() {
    let code = r#"
public class Test {
    // Target should not be found
    /* Target should not be found */
    /** Target in javadoc */
    private Target myTarget;
    public void method(String param) {
        new Target();
        System.out.println(param);
    }
}
"#;
    let (_temp, analyzer, file, content) = analyzer_for(code, "Test.java");

    let occurrences: Vec<_> = content
        .match_indices("Target")
        .map(|(idx, _)| idx)
        .collect();
    for idx in occurrences.iter().take(3) {
        let start = content[..*idx].len();
        let end = start + "Target".len();
        assert!(!analyzer.is_access_expression(&file, start, end));
    }

    let type_use = occurrences[3];
    let type_use_start = content[..type_use].len();
    assert!(analyzer.is_access_expression(&file, type_use_start, type_use_start + "Target".len()));

    let ctor_use = occurrences[4];
    let ctor_use_start = content[..ctor_use].len();
    assert!(analyzer.is_access_expression(&file, ctor_use_start, ctor_use_start + "Target".len()));

    let param_use = content.find("println(param)").unwrap() + "println(".len();
    let param_start = content[..param_use].len();
    let declaration = analyzer
        .find_nearest_declaration(&file, param_start, param_start + "param".len(), "param")
        .unwrap();
    assert_eq!(DeclarationKind::Parameter, declaration.kind);
    assert_eq!("param", declaration.identifier);
}
