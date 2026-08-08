//! The analysis-side entry point for PHP's semantic diagnostics.
//!
//! The language logic lives in [`brokk_bifrost_php::diagnostics`]. What stays
//! here is the one downcast that turns an `&dyn IAnalyzer` into the arguments
//! that function takes -- the PHP analysis source, the dispatching analyzer's
//! declaration index, and the bounded definition lookup -- the implementation
//! of the external-surface window over the semantic-model overlay and retained
//! discovery evidence, and the analyzer-bound fixture suite, which needs a real
//! `PhpAnalyzer` over a `TestProject`.

use std::sync::Arc;

use crate::analyzer::semantic_model::{
    DependencyDiscoveryEvidence, SemanticModelCompleteness, SemanticModelOverlay,
    SemanticModelSymbol, SemanticModelSymbolKind, dependency_discovery_incomplete_reasons,
};
use crate::analyzer::{
    IAnalyzer, Language, PhpAnalyzer, ProjectFile, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticReport, resolve_analyzer,
};
use brokk_bifrost_php::external_surface::{
    PhpExternalMember, PhpExternalSurface, PhpExternalSymbol,
};

pub(crate) fn collect_php_semantic_diagnostics(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
) -> SemanticDiagnosticReport {
    let Some(php) = resolve_analyzer::<PhpAnalyzer>(analyzer) else {
        return SemanticDiagnosticReport::new();
    };
    let support = analyzer.global_usage_definition_index();
    // Both reads are of state a host already published. Neither starts
    // dependency discovery nor touches a vendor tree.
    let external = AnalyzerPhpExternalSurface {
        overlay: analyzer.semantic_model_overlay(),
        evidence: analyzer.dependency_discovery_evidence(Language::Php),
    };
    brokk_bifrost_php::diagnostics::collect_php_semantic_diagnostics(
        php, analyzer, &support, &external, file, source,
    )
}

/// The overlay and discovery evidence an analyzer already holds, presented as
/// the narrow window PHP's collector reads.
struct AnalyzerPhpExternalSurface {
    overlay: Option<Arc<SemanticModelOverlay>>,
    evidence: Option<Arc<DependencyDiscoveryEvidence>>,
}

impl AnalyzerPhpExternalSurface {
    /// PHP declarations in the overlay whose qualified name is exactly `fqn`.
    ///
    /// Matching on the qualified name keeps a terminal-name posting for an
    /// unrelated symbol from answering a fully qualified question.
    fn php_symbols_named<'a>(
        overlay: &'a SemanticModelOverlay,
        fqn: &str,
    ) -> Vec<&'a SemanticModelSymbol> {
        overlay
            .symbols_named(fqn)
            .records
            .into_iter()
            .filter(|symbol| symbol.language == "php" && symbol.qualified_name == fqn)
            .collect()
    }

    fn classify(records: &[&SemanticModelSymbol]) -> PhpExternalSymbol {
        match records {
            [] => PhpExternalSymbol::Absent,
            [symbol] if !symbol.provenance.ambiguous => PhpExternalSymbol::Indexed {
                id: symbol.id.clone(),
            },
            _ => PhpExternalSymbol::Ambiguous,
        }
    }
}

impl PhpExternalSurface for AnalyzerPhpExternalSurface {
    fn lookup_type(&self, fqn: &str) -> PhpExternalSymbol {
        let Some(overlay) = &self.overlay else {
            return PhpExternalSymbol::Absent;
        };
        let records = Self::php_symbols_named(overlay, fqn);
        // A namespace scaffold is not a type a reference can name.
        let records = records
            .into_iter()
            .filter(|symbol| symbol.kind != SemanticModelSymbolKind::Module)
            .collect::<Vec<_>>();
        Self::classify(&records)
    }

    fn lookup_member(&self, owner_id: &str, member: &str) -> PhpExternalMember {
        let Some(overlay) = &self.overlay else {
            return PhpExternalMember::Unproven {
                detail: "no active semantic pack publishes a PHP surface".to_owned(),
            };
        };
        let owner = overlay
            .symbols_with_id(owner_id)
            .records
            .first()
            .copied()
            .expect("the owner identity came from a lookup_type match on this overlay");
        // A member can be inherited, so the owner's whole ancestry is part of
        // the surface the lookup must check, and only a closure with no gap can
        // report the member absent.
        let surface = overlay.owner_surface(owner);
        let mut found = Vec::new();
        for ancestor in &surface.closure {
            found.extend(
                overlay
                    .members_of(&ancestor.id)
                    .records
                    .into_iter()
                    .filter(|symbol| symbol.name == member),
            );
        }
        if found.is_empty() {
            return match surface.gaps.first() {
                Some(gap) => PhpExternalMember::Unproven {
                    detail: gap.to_string(),
                },
                None => PhpExternalMember::Absent,
            };
        }
        // More than one hit is the ordinary shape of an override, not a
        // conflict: a class and the interface it implements both declare the
        // method. Only a declaration an indexed pack itself flagged ambiguous
        // makes the answer ambiguous.
        if found.iter().any(|symbol| !symbol.provenance.ambiguous) {
            PhpExternalMember::Indexed
        } else {
            PhpExternalMember::Ambiguous
        }
    }

    fn namespace_surface_is_complete(&self, namespace_fq: &str) -> bool {
        let Some(overlay) = &self.overlay else {
            return false;
        };
        if namespace_fq.is_empty() {
            return false;
        }
        // A complete PSR-4 surface for `Vendor\Widget\` also covers every
        // namespace below it, so walk back toward the root.
        let mut candidate = namespace_fq;
        loop {
            let covered = Self::php_symbols_named(overlay, candidate)
                .into_iter()
                .any(|symbol| {
                    symbol.kind == SemanticModelSymbolKind::Module
                        && symbol.provenance.completeness == SemanticModelCompleteness::Complete
                });
            if covered {
                return true;
            }
            match candidate.rsplit_once('.') {
                Some((head, _)) => candidate = head,
                None => return false,
            }
        }
    }

    fn declares_unindexed(&self, fqn: &str) -> bool {
        self.evidence
            .as_ref()
            .is_some_and(|evidence| evidence.declares_module_path(fqn))
    }

    fn discovery_incomplete_reasons(&self) -> Vec<SemanticDiagnosticIncompleteReason> {
        dependency_discovery_incomplete_reasons(self.evidence.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::collect_php_semantic_diagnostics;
    use crate::analyzer::{
        Language, PhpAnalyzer, ProjectFile, SemanticDiagnostic, SemanticDiagnosticOutcome,
        TestProject,
    };
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

        fn diagnostics_for(&self, rel_path: &str) -> Vec<SemanticDiagnostic> {
            self.report_for(rel_path).into_diagnostics()
        }

        fn report_for(&self, rel_path: &str) -> crate::analyzer::SemanticDiagnosticReport {
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
    fn php_semantic_diagnostics_record_an_unknown_vendor_boundary_without_erroring() {
        // Nothing indexed `Vendor\Package` and no host ran Composer discovery,
        // so the reference must stay silent -- but the report now says why
        // instead of dropping the reference on the floor.
        let fixture = fixture(&[(
            "src/Service.php",
            r#"<?php
namespace App;

class Service {
    private \Vendor\Package\MissingType $value;
}
"#,
        )]);

        let report = fixture.report_for("src/Service.php");

        assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
        assert!(
            report.outcomes().iter().any(|outcome| matches!(
                outcome,
                SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                    if reasons.iter().any(|reason| matches!(
                        reason,
                        crate::analyzer::SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery { .. }
                    ))
            )),
            "{:#?}",
            report.outcomes()
        );
    }

    #[test]
    fn php_semantic_diagnostics_record_dynamic_behavior_instead_of_silence() {
        let fixture = fixture(&[(
            "src/Dynamic.php",
            r#"<?php
namespace App;

class Anchor {}

function run($target, $method, $className): void {
    $target->$method();
    new $className();
}
"#,
        )]);

        let report = fixture.report_for("src/Dynamic.php");

        assert!(report.diagnostics().is_empty(), "{:#?}", report.outcomes());
        assert!(
            report.outcomes().iter().any(|outcome| matches!(
                outcome,
                SemanticDiagnosticOutcome::Incomplete { reasons, .. }
                    if reasons.iter().any(|reason| matches!(
                        reason,
                        crate::analyzer::SemanticDiagnosticIncompleteReason::DynamicBehavior { .. }
                    ))
            )),
            "{:#?}",
            report.outcomes()
        );
    }
}
