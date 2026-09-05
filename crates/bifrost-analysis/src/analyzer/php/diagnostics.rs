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
    let support = crate::analyzer::AnalyzerDefinitionLookup::new(analyzer, Language::None);
    // Both reads are of state a host already published. Neither starts
    // dependency discovery nor touches a vendor tree.
    let external = AnalyzerPhpExternalSurface {
        overlay: analyzer.semantic_model_overlay(),
        evidence: analyzer.dependency_discovery_evidence(Language::Php),
    };
    let report = brokk_bifrost_php::diagnostics::collect_php_semantic_diagnostics(
        php, analyzer, &support, &external, file, source,
    );
    crate::analyzer::semantic_model::degrade_pack_gap_absences(analyzer, report)
}

/// What the activated packs say about one member of one PHP owner, asked by
/// qualified owner name rather than by an already-resolved overlay identity.
///
/// This is the question the definition path asks. The boundary trace's PHP arm
/// cannot ask it: PHP spells qualified names with `\`, which the
/// reference-site scanner does not span, so the trace holds one written
/// segment (`prepare`) and would answer it with any activated PHP symbol of
/// that name. The definition site knows the receiver's owner, so it can ask
/// the owner-scoped question and name the exact target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PhpOverlayMember {
    /// Exactly one activated declaration answers the member; the string is its
    /// overlay identity.
    Indexed(String),
    /// The owner is published, its whole inherited surface is published with
    /// no gap, and the member is not on it.
    DeclaredAbsent,
    /// Nothing activated publishes the owner, more than one pack does, or the
    /// owner's surface has a gap. Nothing is proven either way.
    Unknown,
}

/// The synthetic owner every PHP global-namespace function and constant hangs
/// off. Kept in step with `super::source_artifact::PHP_GLOBAL_NAMESPACE`,
/// which is the producer side of the same identity.
pub(crate) const PHP_GLOBAL_NAMESPACE_OWNER: &str = super::source_artifact::PHP_GLOBAL_NAMESPACE;

/// PHP declarations in the overlay whose qualified name is exactly `fqn`.
///
/// Matching on the qualified name keeps a terminal-name posting for an
/// unrelated symbol from answering a fully qualified question, and filtering
/// to PHP keeps another ecosystem's posting from answering at all.
fn php_overlay_symbols_named<'a>(
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

/// What the activated packs say about one PHP type name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PhpOverlayType {
    /// Exactly one activated declaration answers the name; the string is its
    /// overlay identity.
    Indexed(String),
    /// Nothing activated publishes the name, or more than one pack does.
    Unknown,
}

/// Resolve one PHP type name against the activated packs.
///
/// A namespace scaffold is filtered out: it exists so free functions have an
/// owner, and no reference can name it as a type.
pub(crate) fn php_overlay_type(
    overlay: Option<&SemanticModelOverlay>,
    fqn: &str,
) -> PhpOverlayType {
    let Some(overlay) = overlay else {
        return PhpOverlayType::Unknown;
    };
    let records = php_overlay_symbols_named(overlay, fqn)
        .into_iter()
        .filter(|symbol| symbol.kind != SemanticModelSymbolKind::Module)
        .collect::<Vec<_>>();
    match records.as_slice() {
        [symbol] if !symbol.provenance.ambiguous => PhpOverlayType::Indexed(symbol.id.clone()),
        _ => PhpOverlayType::Unknown,
    }
}

/// Resolve one member of one PHP owner against the activated packs.
///
/// The walk is the same one `AnalyzerPhpExternalSurface::lookup_member` takes
/// -- the owner's whole inherited closure, gated on that closure having no gap
/// -- so the definition path and the semantic-diagnostics collector agree
/// about what "the activated packs declare this member" means.
pub(crate) fn php_overlay_member(
    overlay: Option<&SemanticModelOverlay>,
    owner: &str,
    member: &str,
) -> PhpOverlayMember {
    let Some(overlay) = overlay else {
        return PhpOverlayMember::Unknown;
    };
    let owners = php_overlay_symbols_named(overlay, owner);
    let [owner_symbol] = owners.as_slice() else {
        // Nothing publishes the owner, or two packs disagree about it.
        return PhpOverlayMember::Unknown;
    };
    if owner_symbol.provenance.ambiguous {
        return PhpOverlayMember::Unknown;
    }
    let surface = overlay.owner_surface(owner_symbol);
    // `owner_surface` puts the owner first and its ancestors after, so the
    // first hit is the most derived declaration, which is the one PHP
    // dispatches to.
    let found = surface
        .closure
        .iter()
        .flat_map(|ancestor| overlay.members_of(&ancestor.id).records)
        .filter(|symbol| symbol.name == member)
        .collect::<Vec<_>>();
    if let Some(symbol) = found.iter().find(|symbol| !symbol.provenance.ambiguous) {
        return PhpOverlayMember::Indexed(symbol.id.clone());
    }
    if !found.is_empty() {
        // Every declaration that answers the name was flagged ambiguous by the
        // pack that published it, so no single target can be named.
        return PhpOverlayMember::Unknown;
    }
    // The global namespace is the one owner whose presence is never a claim of
    // coverage: PHP's builtin global surface is far larger than any one pack,
    // so a name missing from the scaffold proves nothing. Every other owner is
    // absent only when its whole published surface has no gap.
    if owner == PHP_GLOBAL_NAMESPACE_OWNER || !surface.gaps.is_empty() {
        PhpOverlayMember::Unknown
    } else {
        PhpOverlayMember::DeclaredAbsent
    }
}

/// The overlay and discovery evidence an analyzer already holds, presented as
/// the narrow window PHP's collector reads.
struct AnalyzerPhpExternalSurface {
    overlay: Option<Arc<SemanticModelOverlay>>,
    evidence: Option<Arc<DependencyDiscoveryEvidence>>,
}

impl AnalyzerPhpExternalSurface {
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
        let records = php_overlay_symbols_named(overlay, fqn);
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
            let covered = php_overlay_symbols_named(overlay, candidate)
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
