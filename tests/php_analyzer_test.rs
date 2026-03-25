mod common;

use brokk_analyzer::{CodeUnit, IAnalyzer, PhpAnalyzer, ProjectFile};
use common::{assert_code_eq, definition, normalize_nonempty_lines, php_fixture_project};

fn fixture_analyzer() -> PhpAnalyzer {
    PhpAnalyzer::from_project(php_fixture_project())
}

#[test]
fn test_php_initialization() {
    let analyzer = fixture_analyzer();
    assert!(!analyzer.is_empty());
}

#[test]
fn test_php_determine_package_name() {
    let analyzer = fixture_analyzer();

    let foo_class = definition(&analyzer, "My.Lib.Foo");
    assert_eq!("My.Lib", foo_class.package_name());

    let bar_class = definition(&analyzer, "Another.SubNs.Bar");
    assert_eq!("Another.SubNs", bar_class.package_name());

    let no_ns_class = definition(&analyzer, "NoNsClass");
    assert_eq!("", no_ns_class.package_name());
}

#[test]
fn test_php_get_declarations_in_file_foo() {
    let analyzer = fixture_analyzer();
    let foo_file = ProjectFile::new(analyzer.project().root().to_path_buf(), "Foo.php");
    let declarations = analyzer.get_declarations(&foo_file);
    let fq_names: std::collections::BTreeSet<_> =
        declarations.iter().map(CodeUnit::fq_name).collect();

    assert_eq!(
        std::collections::BTreeSet::from([
            "My.Lib.Foo".to_string(),
            "My.Lib.Foo.MY_CONST".to_string(),
            "My.Lib.Foo.staticProp".to_string(),
            "My.Lib.Foo.value".to_string(),
            "My.Lib.Foo.nullableProp".to_string(),
            "My.Lib.Foo.__construct".to_string(),
            "My.Lib.Foo.getValue".to_string(),
            "My.Lib.Foo.abstractMethod".to_string(),
            "My.Lib.Foo.refReturnMethod".to_string(),
            "My.Lib.IFoo".to_string(),
            "My.Lib.MyTrait".to_string(),
            "My.Lib.MyTrait.traitMethod".to_string(),
            "My.Lib.util_func".to_string(),
        ]),
        fq_names
    );
}

#[test]
fn test_php_get_declarations_in_file_no_namespace() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "NoNamespace.php");
    let declarations = analyzer.get_declarations(&file);
    let fq_names: std::collections::BTreeSet<_> =
        declarations.iter().map(CodeUnit::fq_name).collect();
    assert_eq!(
        std::collections::BTreeSet::from([
            "NoNsClass".to_string(),
            "NoNsClass.property".to_string(),
            "globalFuncNoNs".to_string(),
        ]),
        fq_names
    );
}

#[test]
fn test_php_get_skeletons_foo_class() {
    let analyzer = fixture_analyzer();
    let foo_class = definition(&analyzer, "My.Lib.Foo");
    assert_code_eq(
        r#"
        #[Attribute1]
        class Foo extends BaseFoo implements IFoo, IBar {
          private const MY_CONST = "hello";
          public static $staticProp = 123;
          protected $value;
          private ?string $nullableProp;
          #[Attribute2]
          public function __construct(int $v) { ... }
          public function getValue(): int { ... }
          abstract protected function abstractMethod();
          final public static function &refReturnMethod(): array { ... }
        }
        "#,
        &analyzer.get_skeleton(&foo_class).unwrap(),
    );
}

#[test]
fn test_php_get_skeletons_global_function() {
    let analyzer = fixture_analyzer();
    let util_func = definition(&analyzer, "My.Lib.util_func");
    assert_code_eq(
        "function util_func(): void { ... }",
        &analyzer.get_skeleton(&util_func).unwrap(),
    );
}

#[test]
fn test_php_get_skeletons_top_level_constant() {
    let analyzer = fixture_analyzer();
    let top_level_const = definition(&analyzer, "_module_.TOP_LEVEL_CONST");
    assert_code_eq(
        "const TOP_LEVEL_CONST = 456;",
        &analyzer.get_skeleton(&top_level_const).unwrap(),
    );
}

#[test]
fn test_php_get_skeletons_interface_and_trait() {
    let analyzer = fixture_analyzer();
    let interface = definition(&analyzer, "My.Lib.IFoo");
    assert_code_eq(
        "interface IFoo { }",
        &analyzer.get_skeleton(&interface).unwrap(),
    );

    let trait_unit = definition(&analyzer, "My.Lib.MyTrait");
    assert_code_eq(
        r#"
        trait MyTrait {
          public function traitMethod() { ... }
        }
        "#,
        &analyzer.get_skeleton(&trait_unit).unwrap(),
    );
}

#[test]
fn test_php_get_symbols() {
    let analyzer = fixture_analyzer();
    let foo_class = definition(&analyzer, "My.Lib.Foo");
    let symbols = analyzer.get_symbols(&std::collections::BTreeSet::from([foo_class]));
    assert_eq!(
        std::collections::BTreeSet::from([
            "Foo".to_string(),
            "MY_CONST".to_string(),
            "staticProp".to_string(),
            "value".to_string(),
            "nullableProp".to_string(),
            "__construct".to_string(),
            "getValue".to_string(),
            "abstractMethod".to_string(),
            "refReturnMethod".to_string(),
        ]),
        symbols
    );
}

#[test]
fn test_php_get_method_source() {
    let analyzer = fixture_analyzer();

    let get_value = definition(&analyzer, "My.Lib.Foo.getValue");
    let get_value_source = analyzer.get_source(&get_value, true).unwrap();
    assert_eq!(
        normalize_nonempty_lines(
            r#"
            /** Some doc */
            public function getValue(): int {
              return $this->value;
            }
            "#,
        ),
        normalize_nonempty_lines(&get_value_source)
    );

    let constructor = definition(&analyzer, "My.Lib.Foo.__construct");
    let constructor_source = analyzer.get_source(&constructor, true).unwrap();
    assert_eq!(
        normalize_nonempty_lines(
            r#"
            #[Attribute2]
            public function __construct(int $v) {
              $this->value = $v;
            }
            "#,
        ),
        normalize_nonempty_lines(&constructor_source)
    );
}

#[test]
fn test_php_get_class_source() {
    let analyzer = fixture_analyzer();
    let foo_class = definition(&analyzer, "My.Lib.Foo");
    let class_source = analyzer.get_source(&foo_class, true).unwrap();
    let normalized = normalize_nonempty_lines(&class_source);
    assert!(
        normalized.starts_with("#[Attribute1]\nclass Foo extends BaseFoo implements IFoo, IBar {")
    );
    assert!(normalized.contains("private const MY_CONST = \"hello\";"));
    assert!(normalized.contains("public function getValue(): int {"));
    assert!(normalized.ends_with('}'));
}

#[test]
fn test_php_is_constructor() {
    let analyzer = fixture_analyzer();
    let class_unit = definition(&analyzer, "My.Lib.Foo");
    let constructor = definition(&analyzer, "My.Lib.Foo.__construct");
    let other_method = definition(&analyzer, "My.Lib.Foo.getValue");

    assert!(analyzer.is_constructor(&constructor, &class_unit, ""));
    assert!(!analyzer.is_constructor(&other_method, &class_unit, ""));
}

#[test]
fn test_php_complex_field_initializer_is_omitted() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let file = ProjectFile::new(root.to_path_buf(), "fields.php");
    file.write(
        r#"
        <?php
        class ComplexFields {
            public const LITERAL = 1;
            public const COMPLEX = SOME_FUNC();
            public $x = 1;
            public $y = new Object();
            public $multiA = 1, $multiB = foo();
        }
        "#,
    )
    .unwrap();

    let analyzer = PhpAnalyzer::from_project(brokk_analyzer::TestProject::new(
        root,
        brokk_analyzer::Language::Php,
    ));

    assert_code_eq(
        "public const LITERAL = 1;",
        &analyzer
            .get_skeleton(&definition(&analyzer, "ComplexFields.LITERAL"))
            .unwrap(),
    );
    assert_code_eq(
        "public const COMPLEX;",
        &analyzer
            .get_skeleton(&definition(&analyzer, "ComplexFields.COMPLEX"))
            .unwrap(),
    );
    assert_code_eq(
        "public $x = 1;",
        &analyzer
            .get_skeleton(&definition(&analyzer, "ComplexFields.x"))
            .unwrap(),
    );
    assert_code_eq(
        "public $y;",
        &analyzer
            .get_skeleton(&definition(&analyzer, "ComplexFields.y"))
            .unwrap(),
    );
    assert_code_eq(
        "public $multiA = 1;",
        &analyzer
            .get_skeleton(&definition(&analyzer, "ComplexFields.multiA"))
            .unwrap(),
    );
    assert_code_eq(
        "public $multiB;",
        &analyzer
            .get_skeleton(&definition(&analyzer, "ComplexFields.multiB"))
            .unwrap(),
    );
}
