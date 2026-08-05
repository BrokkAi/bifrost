//! The analysis-side entry point for PHP's semantic diagnostics.
//!
//! The language logic lives in [`brokk_bifrost_php::diagnostics`]. What stays
//! here is the one downcast that turns an `&dyn IAnalyzer` into the arguments
//! that function takes -- the PHP analysis source, the dispatching analyzer's
//! declaration index, and the bounded definition lookup -- plus the
//! analyzer-bound fixture suite, which needs a real `PhpAnalyzer` over a
//! `TestProject`.

use crate::analyzer::{IAnalyzer, PhpAnalyzer, ProjectFile, resolve_analyzer};
use brokk_bifrost_php::diagnostics::PhpSemanticDiagnostic;

pub(crate) fn collect_php_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> Vec<PhpSemanticDiagnostic> {
    let Some(php) = resolve_analyzer::<PhpAnalyzer>(analyzer) else {
        return Vec::new();
    };
    let support = analyzer.global_usage_definition_index();
    brokk_bifrost_php::diagnostics::collect_php_semantic_diagnostics(
        php, analyzer, &support, file, source,
    )
}

#[cfg(test)]
mod tests {
    use super::collect_php_semantic_diagnostics;
    use crate::analyzer::{Language, PhpAnalyzer, ProjectFile, TestProject};
    use brokk_bifrost_php::diagnostics::{PHP_UNRECOGNIZED_MEMBER, PHP_UNRECOGNIZED_SYMBOL};
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        analyzer: PhpAnalyzer,
        root: std::path::PathBuf,
    }

    impl Fixture {
        fn file(&self, rel_path: &str) -> ProjectFile {
            ProjectFile::new(self.root.clone(), rel_path)
        }

        fn diagnostics_for(&self, rel_path: &str) -> Vec<super::PhpSemanticDiagnostic> {
            let file = self.file(rel_path);
            let source = file.read_to_string().expect("read source");
            collect_php_semantic_diagnostics(&self.analyzer, &file, &source)
        }
    }

    fn fixture(files: &[(&str, &str)]) -> Fixture {
        let temp = TempDir::new().expect("temp dir");
        let root = temp.path().to_path_buf();
        for (path, source) in files {
            ProjectFile::new(root.clone(), path)
                .write(*source)
                .unwrap_or_else(|err| panic!("write {path}: {err}"));
        }
        let project = TestProject::new(root.clone(), Language::Php);
        let analyzer = PhpAnalyzer::from_project(project);
        Fixture {
            _temp: temp,
            analyzer,
            root,
        }
    }

    #[test]
    fn php_semantic_diagnostics_report_unknown_namespaced_type_function_and_constant() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Anchor {}

class Service {
    private MissingType $value;

    public function run(): void {
        \App\missing_function();
        \App\MISSING_CONSTANT;
    }
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert_eq!(3, diagnostics.len(), "{diagnostics:#?}");
        assert!(
            diagnostics
                .iter()
                .all(|diagnostic| diagnostic.kind == PHP_UNRECOGNIZED_SYMBOL),
            "{diagnostics:#?}"
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("MissingType")),
            "{diagnostics:#?}"
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("missing_function")),
            "{diagnostics:#?}"
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("MISSING_CONSTANT")),
            "{diagnostics:#?}"
        );
    }

    #[test]
    fn php_semantic_diagnostics_suppress_imported_aliases_and_builtins() {
        let fixture = fixture(&[
            (
                "src/Service.php",
                r#"<?php
namespace App;

class Service {}
function render_view(): void {}
const READY = 1;
"#,
            ),
            (
                "src/Controller.php",
                r#"<?php
namespace App\Http;

use App\Service as S;
use function App\render_view as rv;
use const App\READY as READY_FLAG;

class Controller {
    public function handle(S $service): void {
        rv();
        READY_FLAG;
        strlen("ok");
    }
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("src/Controller.php");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn php_semantic_diagnostics_suppress_unqualified_functions_and_constants() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Anchor {}

function run(): void {
    str_replace("old", "new", "old");
    may_fallback_to_global();
    MAY_FALLBACK_TO_GLOBAL;
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn php_semantic_diagnostics_suppress_composer_psr4_project_classes() {
        let fixture = fixture(&[
            (
                "composer.json",
                r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#,
            ),
            (
                "src/Domain/Service.php",
                "<?php\nnamespace App\\Domain;\nclass Service {}\n",
            ),
            (
                "src/Http/Controller.php",
                r#"<?php
namespace App\Http;

use App\Domain\Service;

class Controller {
    public function handle(Service $service): void {}
}
"#,
            ),
        ]);

        let diagnostics = fixture.diagnostics_for("src/Http/Controller.php");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn php_semantic_diagnostics_suppress_dynamic_constructs_and_malformed_files() {
        let fixture = fixture(&[
            (
                "src/Dynamic.php",
                r#"<?php
namespace App;

class Anchor {}

function run($target, $method, $className): void {
    $target->$method();
    $className::factory();
    $callable();
    new $className();
}
"#,
            ),
            (
                "src/Broken.php",
                "<?php\nnamespace App;\nclass Broken { public function run(: void { MissingType; }\n",
            ),
        ]);

        let dynamic_diagnostics = fixture.diagnostics_for("src/Dynamic.php");
        assert!(dynamic_diagnostics.is_empty(), "{dynamic_diagnostics:#?}");
        let broken_diagnostics = fixture.diagnostics_for("src/Broken.php");
        assert!(broken_diagnostics.is_empty(), "{broken_diagnostics:#?}");
    }

    #[test]
    fn php_semantic_diagnostics_report_only_known_receiver_missing_members() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Base {
    public function inherited(): void {}
}

class Service extends Base {
    public function present(): void {}

    public function run(Service $service): void {
        $this->present();
        self::present();
        static::present();
        parent::inherited();
        $service->missing();
        $unknown->missing();
    }
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(PHP_UNRECOGNIZED_MEMBER, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("missing"));
    }

    #[test]
    fn php_semantic_diagnostics_suppress_magic_and_trait_members() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

trait SharedMethods {
    public function shared(): void {}
}

class DynamicService {
    public function __call(string $name, array $args): mixed {}
    public function __get(string $name): mixed {}
    public static function __callStatic(string $name, array $args): mixed {}
}

class TraitService {
    use SharedMethods;

    public function run(): void {
        $this->shared();
    }
}

function run(DynamicService $service): void {
    $service->dynamicCall();
    $service->dynamicProperty;
    DynamicService::dynamicStaticCall();
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn php_semantic_diagnostics_do_not_leak_bindings_into_nested_functions() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Service {}

function run(Service $service): void {
    function inner(): void {
        $service->missing();
    }
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }

    #[test]
    fn php_semantic_diagnostics_report_missing_static_receiver_type() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Anchor {}

function run(): void {
    MissingStatic::run();
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert_eq!(1, diagnostics.len(), "{diagnostics:#?}");
        assert_eq!(PHP_UNRECOGNIZED_SYMBOL, diagnostics[0].kind);
        assert!(diagnostics[0].message.contains("MissingStatic"));
    }

    #[test]
    fn php_semantic_diagnostics_suppress_external_vendor_boundaries() {
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Service {
    private \Vendor\Package\MissingType $value;
}
"#,
        )]);

        let diagnostics = fixture.diagnostics_for("src/Service.php");
        assert!(diagnostics.is_empty(), "{diagnostics:#?}");
    }
}
