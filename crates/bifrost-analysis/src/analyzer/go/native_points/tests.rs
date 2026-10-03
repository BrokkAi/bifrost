use super::*;
use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    DependencyPackLimits, SemanticModelActivationRequest, SemanticModelRuntimeLimits,
    SemanticPackCatalog,
};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupStatus, ExactExternalCallProof, ResolvedReferenceSite,
};
use crate::analyzer::{
    AnalyzerConfig, CodeUnitIndex, DependencyPackEcosystem, DependencyPackWorkspaceContext,
    GoAnalyzerConfig, GoDependencyDiscoveryConfig, GoDependencyDiscoveryMode, Language, Project,
    Range,
};
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use std::sync::Arc;

const PROVIDER: &str = "provider/item.go";
const CALLER: &str = "consumer/use.go";

fn fixture(source: &str) -> (BuiltInlineTestProject, GoAnalyzer) {
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(PROVIDER, "package vocabulary; type Item struct {}")
        .file(CALLER, source)
        .file("decoy/item.go", "package vocabulary; type Item struct {}")
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    (fixture, analyzer)
}

fn site(source: &str) -> ResolvedReferenceSite {
    site_for(source, "Item")
}

fn site_for(source: &str, identifier: &str) -> ResolvedReferenceSite {
    let start_byte = source.rfind(identifier).unwrap();
    ResolvedReferenceSite {
        path: CALLER.into(),
        text: identifier.into(),
        range: Range {
            start_byte,
            end_byte: start_byte + identifier.len(),
            start_line: 0,
            end_line: 0,
        },
        focus_start_byte: start_byte,
        focus_end_byte: start_byte + identifier.len(),
    }
}

fn complete(result: BoundedResolution<DefinitionLookupOutcome>) -> DefinitionLookupOutcome {
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };
    value
}

fn complete_with_evidence(
    result: BoundedResolution<GoNativeDefinitionResolution>,
) -> GoNativeDefinitionResolution {
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };
    value
}

#[test]
fn go_native_point_binds_standard_package_and_external_member_identity() {
    // The standard library comes from the host Go toolchain. Without one the
    // qualifier is correctly incomplete, so this test needs `go` on PATH.
    if std::process::Command::new("go")
        .arg("version")
        .output()
        .is_err()
    {
        return;
    }
    let source =
        "package consumer\n\nimport \"strings\"\n\nfunc use() {\n _ = strings.ToUpper(\"x\")\n}\n";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let config = AnalyzerConfig {
        go: GoAnalyzerConfig {
            dependency_discovery: GoDependencyDiscoveryConfig {
                mode: GoDependencyDiscoveryMode::FullProduction,
                ..GoDependencyDiscoveryConfig::default()
            },
        },
        ..AnalyzerConfig::default()
    };
    let workspace = fixture.workspace_analyzer(config.clone());
    let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
    let activation = SemanticModelActivationRequest {
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    let cancellation = CancellationToken::default();
    let discovery = workspace.activate_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Go],
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation: &cancellation,
        },
    );
    assert_eq!(discovery.ecosystems.len(), 1);
    assert_eq!(
        discovery.ecosystems[0].ecosystem,
        DependencyPackEcosystem::Go
    );
    let analyzer = workspace.analyzer();
    let file = fixture.file(CALLER);
    let tree = crate::analyzer::usages::get_definition::parse_go_tree(source)
        .expect("parse Go package member calls");
    let resolve_at = |needle: &str| {
        let start_byte = source.rfind(needle).expect("source contains focused token");
        let site = ResolvedReferenceSite {
            path: CALLER.into(),
            text: needle.into(),
            range: Range {
                start_byte,
                end_byte: start_byte + needle.len(),
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + needle.len(),
        };
        complete_with_evidence(resolve_go_definition_with_evidence_bounded(
            BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ))
    };

    let qualifier = resolve_at("strings").outcome;
    let Some(qualifier_binding) = qualifier.lexical_definition.as_ref() else {
        panic!("the package qualifier must bind to the selected import: {qualifier:?}");
    };
    assert_eq!(qualifier_binding.identifier, "strings");
    assert_eq!(
        &source[qualifier_binding.declaration_range.start_byte
            ..qualifier_binding.declaration_range.end_byte],
        "\"strings\""
    );

    let member_resolution = resolve_at("ToUpper");
    let member = member_resolution.outcome;
    assert_eq!(
        member.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "the standard-library member must carry an external identity: {member:?}"
    );
    assert_eq!(
        member.resolved_reference_target(),
        Some("strings.ToUpper"),
        "the member identity uses the selected Go import path"
    );
    assert!(
        member.diagnostics.iter().any(|diagnostic| {
            diagnostic.claim.as_ref().is_some_and(|claim| {
                claim.kind
                    == crate::analyzer::usages::get_definition::UnindexedClaimKind::ExternalBoundary
                    && claim.subjects == ["strings"]
            })
        }),
        "an unmodeled member may claim only its discovered package boundary: {member:?}"
    );
    assert!(
        member_resolution.exact_external_call.is_none(),
        "an absent strings model cannot prove exact call applicability"
    );
}

#[test]
fn go_native_point_binds_model_backed_import_without_discovery() {
    let source = "package consumer\nimport \"example.com/acme/codec\"\nvar value wire.Buffer\n";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let overlay = crate::analyzer::semantic_model::go_external_receiver_test_overlay();
    let _overlay_scope =
        crate::analyzer::AnalyzerQueryScope::with_semantic_model_overlay(analyzer, Some(overlay));
    let file = fixture.file(CALLER);
    let tree = crate::analyzer::usages::get_definition::parse_go_tree(source)
        .expect("parse model-backed Go import");
    let resolve_at = |identifier: &str| {
        complete_with_evidence(resolve_go_definition_with_evidence_bounded(
            BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site_for(source, identifier),
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ))
    };

    let qualifier = resolve_at("wire").outcome;
    let Some(binding) = qualifier.lexical_definition.as_ref() else {
        panic!("the exact model package identity binds the import: {qualifier:?}");
    };
    assert_eq!(binding.identifier, "wire");
    assert_eq!(
        &source[binding.declaration_range.start_byte..binding.declaration_range.end_byte],
        "\"example.com/acme/codec\""
    );

    let member = resolve_at("Buffer").outcome;
    assert_eq!(
        member.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "the package member uses the exact modeled import identity: {member:?}"
    );
    assert_eq!(
        member.resolved_reference_target(),
        Some("example.com/acme/codec.Buffer")
    );
}

#[test]
fn go_native_point_proves_os_file_close_from_model_backed_import() {
    let source = r#"package client

import "os"

func caller(file *os.File) {
	file.Close()
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    super::super::persist_live_go_sources_for_test(&analyzer);
    let overlay = crate::analyzer::semantic_model::go_external_receiver_test_overlay();
    let _overlay_scope =
        crate::analyzer::AnalyzerQueryScope::with_semantic_model_overlay(&analyzer, Some(overlay));
    let file = fixture.file(CALLER);
    let tree = crate::analyzer::usages::get_definition::parse_go_tree(source)
        .expect("parse modeled os receiver call");
    let resolution = complete_with_evidence(resolve_go_definition_with_evidence_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: Some(&tree),
            site: &site_for(source, "Close"),
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));

    assert_eq!(
        resolution.outcome.status,
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "the modeled receiver is an exact external boundary: {:?}",
        resolution.outcome
    );
    assert_eq!(
        resolution
            .exact_external_call
            .as_ref()
            .map(ExactExternalCallProof::canonical_callee),
        Some("os.File.Close"),
        "the selected model-backed os import supplies exact receiver authority"
    );
}

#[test]
fn go_native_external_receiver_calls_use_typed_imported_models() {
    let source = r#"package consumer

import (
	"image"
	"os"
	"strings"
)

func use() {
	var point image.Point
	_ = point.String()

	var builder strings.Builder
	builder.WriteString("x")

	var file *os.File
	_ = file.Close()
}

func useUnknown[T interface{ Release() error }](receiver T) {
	_ = receiver.Release()
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let config = AnalyzerConfig {
        go: GoAnalyzerConfig {
            dependency_discovery: GoDependencyDiscoveryConfig {
                mode: GoDependencyDiscoveryMode::FullProduction,
                ..GoDependencyDiscoveryConfig::default()
            },
        },
        ..AnalyzerConfig::default()
    };
    let workspace = fixture.workspace_analyzer(config.clone());
    let catalog = SemanticPackCatalog::open_ephemeral(Default::default()).unwrap();
    let activation = SemanticModelActivationRequest {
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: Vec::new(),
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    };
    let cancellation = CancellationToken::default();
    let discovery = workspace.activate_dependency_packs(
        &config,
        &[DependencyPackEcosystem::Go],
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &activation,
            limits: DependencyPackLimits::default(),
            cancellation: &cancellation,
        },
    );
    assert_eq!(discovery.ecosystems.len(), 1);
    let analyzer = workspace.analyzer();
    let file = fixture.file(CALLER);
    let tree = crate::analyzer::usages::get_definition::parse_go_tree(source)
        .expect("parse external receiver calls");
    let overlay = crate::analyzer::semantic_model::go_external_receiver_test_overlay();
    let _overlay_scope =
        crate::analyzer::AnalyzerQueryScope::with_semantic_model_overlay(analyzer, Some(overlay));
    let resolve_at = |selector: &str| {
        let selector_start = source
            .find(selector)
            .expect("source contains focused receiver selector");
        assert_eq!(
            source.matches(selector).count(),
            1,
            "receiver selector `{selector}` is unique"
        );
        let member_offset = selector
            .rfind('.')
            .expect("receiver selector contains a member separator")
            + 1;
        let start_byte = selector_start + member_offset;
        let member = &selector[member_offset..];
        let line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count();
        let site = ResolvedReferenceSite {
            path: CALLER.into(),
            text: member.into(),
            range: Range {
                start_byte,
                end_byte: start_byte + member.len(),
                start_line: line,
                end_line: line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: start_byte + member.len(),
        };
        complete_with_evidence(resolve_go_definition_with_evidence_bounded(
            BoundedReceiverQuery {
                analyzer,
                file: &file,
                source,
                tree: Some(&tree),
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ))
    };

    for (selector, expected) in [
        ("point.String", "image.Point.String"),
        ("builder.WriteString", "strings.Builder.WriteString"),
        ("file.Close", "os.File.Close"),
    ] {
        let resolution = resolve_at(selector);
        assert_eq!(
            resolution.outcome.status,
            DefinitionLookupStatus::UnresolvableImportBoundary,
            "{selector}: {:?}",
            resolution.outcome
        );
        assert_eq!(
            resolution.outcome.resolved_reference_target(),
            Some(expected),
            "{selector}: {:?}",
            resolution.outcome
        );
        assert_eq!(
            resolution
                .exact_external_call
                .as_ref()
                .map(ExactExternalCallProof::canonical_callee),
            Some(expected),
            "{selector} proof: {:?}",
            resolution.exact_external_call
        );
    }

    let unknown = resolve_at("receiver.Release");
    assert_eq!(
        unknown.outcome.status,
        DefinitionLookupStatus::Incomplete,
        "unknown receiver stays incomplete: {:?}",
        unknown.outcome
    );
    assert!(
        unknown.exact_external_call.is_none(),
        "unknown receiver has no exact model proof"
    );
}

#[test]
fn go_native_point_uses_selected_alias_and_canonical_package_name() {
    for source in [
        "package consumer; import renamed \"example.test/native/provider\"; var Value renamed.Item",
        "package consumer; import \"example.test/native/provider\"; var Value vocabulary.Item",
    ] {
        let (fixture, analyzer) = fixture(source);
        let file = fixture.file(CALLER);
        let site = site(source);
        let outcome = complete(resolve_go_definition_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ));
        assert_eq!(
            outcome.status,
            DefinitionLookupStatus::Incomplete,
            "source={source}, {outcome:?}"
        );
        assert_eq!(outcome.definitions.len(), 1, "source={source}, {outcome:?}");
        let provider = fixture.file(PROVIDER);
        assert_eq!(outcome.definitions[0].source(), &provider);
        assert!(
            analyzer
                .declarations(&provider)
                .contains(&outcome.definitions[0])
        );
    }
}

#[test]
fn go_native_point_does_not_guess_package_basename_or_ignore_shadowing() {
    for source in [
        "package consumer; import \"example.test/native/provider\"; var Value provider.Item",
        "package consumer; import renamed \"example.test/native/provider\"; func use() { var renamed int; _ = renamed.Item }",
    ] {
        let (fixture, analyzer) = fixture(source);
        let file = fixture.file(CALLER);
        let site = site(source);
        let outcome = complete(resolve_go_definition_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ));
        assert!(
            outcome.definitions.is_empty(),
            "source={source}, {outcome:?}"
        );
        assert_ne!(
            outcome.status,
            DefinitionLookupStatus::Resolved,
            "{outcome:?}"
        );
    }
}

#[test]
fn go_native_point_preserves_cancel_budget_and_source_admission() {
    let source =
        "package consumer; import renamed \"example.test/native/provider\"; var Value renamed.Item";
    let (fixture, analyzer) = fixture(source);
    let file = fixture.file(CALLER);
    let site = site(source);
    let cancellation = CancellationToken::new();
    let result = resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: Some(&cancellation),
        },
        || cancellation.cancel(),
    );
    assert!(
        matches!(result, BoundedResolution::Cancelled { .. }),
        "{result:?}"
    );
    let result = resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::tiny(),
            cancellation: None,
        },
        || {},
    );
    assert!(
        matches!(result, BoundedResolution::Exceeded { .. }),
        "{result:?}"
    );
    let outcome = complete(resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: "package consumer; var Value Item",
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Unavailable,
        "{outcome:?}"
    );
    assert_eq!(outcome.diagnostics[0].kind, "native_source_mismatch");
}

#[test]
fn go_native_point_unsaved_import_does_not_borrow_disk_package_membership() {
    let source =
        "package consumer; import renamed \"example.test/native/provider\"; var Value renamed.Item";
    let (fixture, disk) = fixture(source);
    let file = fixture.file(CALLER);
    let changed = source.replace("native/provider", "native/decoy");
    let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
    assert!(overlay.set(file.abs_path(), changed.clone()));
    let analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);
    assert!(!analyzer.declarations(&file).is_empty());
    let site = site(&changed);
    let outcome = complete(resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source: &changed,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Unavailable,
        "{outcome:?}"
    );
    assert!(outcome.definitions.is_empty(), "{outcome:?}");
    assert_eq!(std::fs::read_to_string(file.abs_path()).unwrap(), source);
}

fn unsaved(
    fixture: &BuiltInlineTestProject,
    disk: &GoAnalyzer,
    edits: &[(&str, &str)],
) -> GoAnalyzer {
    let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
    for (path, source) in edits {
        assert!(overlay.set(fixture.file(path).abs_path(), (*source).to_owned()));
    }
    disk.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>)
}

fn resolve_last(
    analyzer: &GoAnalyzer,
    fixture: &BuiltInlineTestProject,
    path: &str,
    source: &str,
    needle: &str,
) -> DefinitionLookupOutcome {
    let start_byte = source.rfind(needle).unwrap();
    resolve_at(analyzer, fixture, path, source, start_byte, needle)
}

fn resolve_at(
    analyzer: &GoAnalyzer,
    fixture: &BuiltInlineTestProject,
    path: &str,
    source: &str,
    start_byte: usize,
    reference: &str,
) -> DefinitionLookupOutcome {
    let site = ResolvedReferenceSite {
        path: path.into(),
        text: reference.into(),
        range: Range {
            start_byte,
            end_byte: start_byte + reference.len(),
            start_line: 0,
            end_line: 0,
        },
        focus_start_byte: start_byte,
        focus_end_byte: start_byte + reference.len(),
    };
    let file = fixture.file(path);
    complete(resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ))
}

const UNPLACED: &str = "go-transient-placement-unproven";

fn reports_unplaced(outcome: &DefinitionLookupOutcome) -> bool {
    outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == UNPLACED)
}

#[test]
fn go_native_point_unsaved_body_edit_keeps_selected_package_membership() {
    let source =
        "package consumer; import renamed \"example.test/native/provider\"; var Value renamed.Item";
    let (fixture, disk) = fixture(source);
    // The bytes through the imports are unchanged, so the Go tool would place
    // the edited file exactly where it placed the saved one.
    let changed = format!("{source}\nvar Other renamed.Item\n");
    let analyzer = unsaved(&fixture, &disk, &[(CALLER, &changed)]);
    let outcome = resolve_last(&analyzer, &fixture, CALLER, &changed, "Item");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:?}"
    );
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(outcome.definitions[0].source(), &fixture.file(PROVIDER));
    assert!(!reports_unplaced(&outcome), "{outcome:?}");
    assert_eq!(
        std::fs::read_to_string(fixture.file(CALLER).abs_path()).unwrap(),
        source
    );
}

#[test]
fn go_native_point_reads_unsaved_package_peer_only_with_proven_placement() {
    const USE: &str = "consumer/use.go";
    const LOCAL: &str = "consumer/local.go";
    const OTHER: &str = "consumer/other.go";
    let use_source = "package consumer\n\nvar Value Local\n\nvar Second Other\n";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(USE, use_source)
        .file(LOCAL, "package consumer\n\ntype Local struct{}\n")
        .file(OTHER, "package consumer\n\ntype Other struct{}\n")
        .build();
    let disk = GoAnalyzer::new(fixture.project_dyn());
    let local = fixture.file(LOCAL);
    let other = fixture.file(OTHER);

    let body_edit = "package consumer\n\ntype Local struct{ Added int }\n";
    let analyzer = unsaved(&fixture, &disk, &[(LOCAL, body_edit)]);
    let outcome = resolve_last(&analyzer, &fixture, USE, use_source, "Local");
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(outcome.definitions[0].source(), &local);
    assert!(!reports_unplaced(&outcome), "{outcome:?}");
    let outcome = resolve_last(&analyzer, &fixture, USE, use_source, "Other");
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert!(!reports_unplaced(&outcome), "{outcome:?}");

    // A new import changes what the Go tool reads for placement. The peer
    // keeps its declaration, but no selected membership vouches for it, so
    // the saved caller must report that gap instead of a settled answer.
    let header_edit = "package consumer\n\nimport \"strings\"\n\ntype Local struct{}\n\nvar _ = strings.ToUpper\n";
    let analyzer = unsaved(&fixture, &disk, &[(LOCAL, header_edit)]);
    let outcome = resolve_last(&analyzer, &fixture, USE, use_source, "Local");
    assert!(outcome.definitions.is_empty(), "{outcome:?}");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:?}"
    );
    // A saved peer's declaration is still found, but the unplaced file could
    // declare the same name in this package, so the answer names that gap.
    let outcome = resolve_last(&analyzer, &fixture, USE, use_source, "Other");
    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(outcome.definitions[0].source(), &other);
    assert!(reports_unplaced(&outcome), "{outcome:?}");
    let outcome = resolve_last(&analyzer, &fixture, LOCAL, header_edit, "Local");
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Unavailable,
        "{outcome:?}"
    );
}

#[test]
fn go_native_type_retains_nominal_target_and_universe_incompleteness() {
    use crate::analyzer::usages::get_type::TypeLookupStatus;
    for source in [
        "package consumer; import renamed \"example.test/native/provider\"; var Value renamed.Item",
        "package consumer; func f(Item int) int { return Item }",
    ] {
        let (fixture, analyzer) = fixture(source);
        let file = fixture.file(CALLER);
        let site = site(source);
        let result = resolve_go_type_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        );
        let BoundedResolution::Complete { value, work } = result else {
            panic!("{result:?}")
        };
        assert!(work.scope_nodes > 0);
        assert_eq!(value.status, TypeLookupStatus::Incomplete, "{value:?}");
        if source.contains("renamed") {
            assert_eq!(value.types.len(), 1, "{value:?}");
            assert_eq!(value.types[0].definitions.len(), 1);
            let unit = &value.types[0].definitions[0];
            assert_eq!(unit.source(), &fixture.file(PROVIDER));
            assert_eq!(value.types[0].fqn, unit.fq_name().to_string());
        } else {
            assert!(value.types.is_empty(), "{value:?}");
            assert!(
                value
                    .diagnostics
                    .iter()
                    .any(|reason| reason.kind == "incomplete_native_type")
            );
        }
    }
}

#[test]
fn go_native_definition_projects_parameters_receivers_and_locals() {
    use brokk_bifrost_core::analyzer::model::DeclarationKind;
    for (source, kind) in [
        (
            "package consumer; func f(Item int) int { return Item }",
            DeclarationKind::Parameter,
        ),
        (
            "package consumer; type T struct{}; func (Item T) f() T { return Item }",
            DeclarationKind::ReceiverParameter,
        ),
        (
            "package consumer; func f() { var Item int; _ = Item }",
            DeclarationKind::LocalVariable,
        ),
        (
            "package consumer; func f() { Item := 1; _ = Item }",
            DeclarationKind::LocalVariable,
        ),
    ] {
        let (fixture, analyzer) = fixture(source);
        let file = fixture.file(CALLER);
        let site = site(source);
        let outcome = complete(resolve_go_definition_bounded(
            BoundedReceiverQuery {
                analyzer: &analyzer,
                file: &file,
                source,
                tree: None,
                site: &site,
                budget: ReceiverAnalysisBudget::default(),
                cancellation: None,
            },
            || {},
        ));
        assert!(
            matches!(
                outcome.status,
                DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Incomplete
            ),
            "{outcome:?}"
        );
        assert!(
            outcome.definitions.is_empty(),
            "lexical binders are not workspace units: {outcome:?}"
        );
        let lexical = outcome
            .lexical_definition
            .expect("exact lexical source declaration");
        assert_eq!(lexical.kind, kind);
        assert_eq!(lexical.identifier, "Item");
        assert_eq!(lexical.source_file.as_ref(), Some(&file));
        assert_eq!(lexical.name_range.start_byte, source.find("Item").unwrap());
        assert_eq!(
            &source[lexical.name_range.start_byte..lexical.name_range.end_byte],
            "Item"
        );
    }
}

#[test]
fn go_native_point_resolves_local_alias_to_receiver_field() {
    let source = "package consumer; type status struct { disabledGroups []string }; type BlockingResolver struct { status *status }; func (r *BlockingResolver) setDisabledGroups(groups []string) { s := r.status; s.disabledGroups = groups }";
    let (fixture, analyzer) = fixture(source);
    let file = fixture.file(CALLER);
    let reference = site_for(source, "disabledGroups");
    let outcome = complete(resolve_go_definition_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &reference,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    ));

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.status.disabledGroups",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_resolves_direct_method_selection() {
    let source = "package consumer; type Service struct {}; func (Service) Run() {}; func caller(service Service) { service.Run() }";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "Run");

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Service.Run",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_resolves_method_expressions_with_exact_method_sets() {
    let caller_source = r#"package consumer

type Widget struct{}
func (Widget) Value() {}
func (*Widget) Pointer() {}

func caller(value Widget) {
	Widget.Value(value)
	(*Widget).Value(&value)
	(*Widget).Pointer(&value)
	Widget.Pointer(value)
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, caller_source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    super::super::persist_live_go_sources_for_test(&analyzer);

    let first_method_expression = "Widget.Value";
    let type_reference_start = caller_source.find(first_method_expression).unwrap();
    let type_outcome = resolve_at(
        &analyzer,
        &fixture,
        CALLER,
        caller_source,
        type_reference_start,
        "Widget",
    );
    assert_eq!(type_outcome.definitions.len(), 1, "{type_outcome:?}");
    assert_eq!(
        type_outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Widget",
        "the method-expression type resolves through its lexical declaration"
    );

    for (selector, expected) in [
        ("Widget.Value", "example.test/native/consumer.Widget.Value"),
        (
            "(*Widget).Value",
            "example.test/native/consumer.Widget.Value",
        ),
        (
            "(*Widget).Pointer",
            "example.test/native/consumer.Widget.Pointer",
        ),
    ] {
        let start_byte = caller_source.find(selector).unwrap() + selector.rfind('.').unwrap() + 1;
        let outcome = resolve_at(
            &analyzer,
            &fixture,
            CALLER,
            caller_source,
            start_byte,
            selector.rsplit('.').next().unwrap(),
        );
        assert_eq!(outcome.definitions.len(), 1, "{selector}: {outcome:?}");
        assert_eq!(
            outcome.definitions[0].fq_name().to_string(),
            expected,
            "{selector}: {outcome:?}"
        );
    }

    let pointer_method_on_value_type = "Widget.Pointer";
    let start_byte = caller_source.rfind(pointer_method_on_value_type).unwrap()
        + pointer_method_on_value_type.rfind('.').unwrap()
        + 1;
    let outcome = resolve_at(
        &analyzer,
        &fixture,
        CALLER,
        caller_source,
        start_byte,
        "Pointer",
    );
    assert!(
        outcome.definitions.is_empty(),
        "T.M must not select a pointer-receiver method: {outcome:?}"
    );
    assert_ne!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "T.M must remain unresolved when M has only a pointer receiver: {outcome:?}"
    );
}

#[test]
fn go_native_point_resolves_field_through_range_clause_binder() {
    let source = r#"package history

type History struct { Revision string }

func visit(history []History) {
	for _, history := range history {
		_ = history.Revision
	}
}
"#;
    let path = "history.go";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(path, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, path, source, "Revision");

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native.History.Revision",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_resolves_type_switch_and_select_case_binders() {
    let source = r#"package consumer

import db "example.test/native/db"

func inspect(value any, input <-chan int) {
    switch db := value.(type) {
    case int:
        _ = db
    default:
        _ = db
    }
    _ = db.Value
    select {
    case db := <-input:
        _ = db
    }
    _ = db.Value
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file("db/db.go", "package db\nvar Value int\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());

    for anchor in [
        "case int:\n        _ = ",
        "default:\n        _ = ",
        "case db := <-input:\n        _ = ",
    ] {
        let start_byte = source.find(anchor).unwrap() + anchor.len();
        let outcome = resolve_at(&analyzer, &fixture, CALLER, source, start_byte, "db");
        assert!(outcome.definitions.is_empty(), "{anchor}: {outcome:?}");
        assert_eq!(
            outcome
                .lexical_definition
                .as_ref()
                .map(|definition| definition.kind),
            Some(brokk_bifrost_core::analyzer::model::DeclarationKind::LocalVariable),
            "{anchor}: {outcome:?}"
        );
    }
}

#[test]
fn go_native_point_resolves_conversion_type_inside_go_1_26_new() {
    let source = "package consumer; type PackageURL struct {}; func FromString(p PackageURL) *PackageURL { return new(PackageURL(p)) }";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.26\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "PackageURL");

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.PackageURL",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_resolves_ordinary_new_type_argument() {
    let source = "package consumer; type Row struct {}; func allocate() { _ = new(Row) }";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.26\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "Row");

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Row",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_does_not_resolve_shadowed_type_conversion_as_type() {
    let source = "package consumer; type PackageURL struct {}; func convert(PackageURL func(int)) { PackageURL(1) }";
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.26\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "PackageURL");

    assert!(outcome.definitions.is_empty(), "{outcome:?}");
    assert_eq!(
        outcome
            .lexical_definition
            .as_ref()
            .map(|definition| definition.kind),
        Some(brokk_bifrost_core::analyzer::model::DeclarationKind::Parameter),
        "{outcome:?}"
    );
    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Resolved,
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_keeps_field_reference_after_go_1_26_new() {
    let source = r#"package consumer

type Row struct {
	limit int
	ents  []int
}

func Build(rows []int, low int, high int) *Row {
	r := &Row{}
	r.limit = *new(max(low, high))
	r.ents = rows
	return r
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.26\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "ents");

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Row.ents",
        "{outcome:?}"
    );
}

#[test]
fn go_native_point_resolves_fields_in_named_elided_container_literals() {
    let source = r#"package consumer

type Item struct { Field string }
type NamedArray [2]*Item
type NestedArray [1][1]*Item
type NamedSlice []Item
type NamedMap map[string]Item
type NamedKeyMap map[Item]string

var array = NamedArray{{Field: "array"}}
var nested = NestedArray{{{Field: "nested"}}}
var slice = NamedSlice{{Field: "slice"}}
var mapped = NamedMap{"item": {Field: "map"}}
var keyed = NamedKeyMap{{Field: "key"}: "value"}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());

    for occurrence in [
        "Field: \"array\"",
        "Field: \"nested\"",
        "Field: \"slice\"",
        "Field: \"map\"",
        "Field: \"key\"",
    ] {
        let start_byte = source.find(occurrence).unwrap();
        let outcome = resolve_at(&analyzer, &fixture, CALLER, source, start_byte, "Field");
        assert_eq!(outcome.definitions.len(), 1, "{occurrence}: {outcome:?}");
        assert_eq!(
            outcome.definitions[0].fq_name().to_string(),
            "example.test/native/consumer.Item.Field",
            "{occurrence}: {outcome:?}"
        );
    }
}

#[test]
fn go_native_point_distinguishes_nested_map_keys_from_struct_field_labels() {
    let source = r#"package consumer

const NestedKey = "nested"

type Item struct { NestedKey string }

var maps = map[string]map[string]string{
	"outer": {NestedKey: "value"},
}
var direct = NestedKey
var items = map[string]Item{
	"outer": {NestedKey: "field"},
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let direct = resolve_at(
        &analyzer,
        &fixture,
        CALLER,
        source,
        source.find("direct = NestedKey").unwrap() + "direct = ".len(),
        "NestedKey",
    );
    assert_eq!(direct.definitions.len(), 1, "{direct:?}");
    let map_key = resolve_at(
        &analyzer,
        &fixture,
        CALLER,
        source,
        source.find("NestedKey: \"value\"").unwrap(),
        "NestedKey",
    );
    assert_eq!(map_key.definitions.len(), 1, "{map_key:?}");
    assert!(
        map_key.definitions[0]
            .fq_name()
            .to_string()
            .ends_with("._module_.NestedKey"),
        "{map_key:?}"
    );

    let field = resolve_at(
        &analyzer,
        &fixture,
        CALLER,
        source,
        source.find("NestedKey: \"field\"").unwrap(),
        "NestedKey",
    );
    assert_eq!(field.definitions.len(), 1, "{field:?}");
    assert_eq!(
        field.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Item.NestedKey",
        "{field:?}"
    );
}

#[test]
fn go_native_points_project_named_container_components_across_package_files() {
    let types = r#"package consumer

type Item struct { Field int }
type Key struct { KeyField int }
type rowStorage []Item
type Rows rowStorage
type lookupStorage map[Key]Item
type Lookup lookupStorage
type streamStorage chan Item
type ItemStream streamStorage
"#;
    let source = r#"package consumer

func use(rows Rows, lookup Lookup, stream ItemStream) {
	for index, row := range rows { _, _ = index, row.Field }
	for key, value := range lookup { _ = key.KeyField; _ = value.Field }
	for item := range stream { _ = item.Field }
	_ = Rows{{Field: 1}}
	_ = Lookup{Key{KeyField: 3}: {Field: 2}}
}
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file("consumer/types.go", types)
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());

    for occurrence in [
        "row.Field",
        "key.KeyField",
        "value.Field",
        "item.Field",
        "{Field: 1}",
        "{Field: 2}",
    ] {
        let identifier = if occurrence.contains("KeyField") {
            "KeyField"
        } else {
            "Field"
        };
        let start_byte = source.find(occurrence).unwrap() + occurrence.find(identifier).unwrap();
        let outcome = resolve_at(&analyzer, &fixture, CALLER, source, start_byte, identifier);
        assert_eq!(outcome.definitions.len(), 1, "{occurrence}: {outcome:?}");
        let expected_owner = if identifier == "KeyField" {
            "Key"
        } else {
            "Item"
        };
        assert_eq!(
            outcome.definitions[0].fq_name().to_string(),
            format!("example.test/native/consumer.{expected_owner}.{identifier}"),
            "{occurrence}: {outcome:?}"
        );
    }
}

#[test]
fn go_native_type_preserves_pointer_depth_and_nominal_identity() {
    use crate::analyzer::usages::get_type::TypeLookupStatus;
    let source = "package consumer; type T struct{}; func f(Item *T) *T { return Item }";
    let (fixture, analyzer) = fixture(source);
    let file = fixture.file(CALLER);
    let site = site(source);
    let result = resolve_go_type_bounded(
        BoundedReceiverQuery {
            analyzer: &analyzer,
            file: &file,
            source,
            tree: None,
            site: &site,
            budget: ReceiverAnalysisBudget::default(),
            cancellation: None,
        },
        || {},
    );
    let BoundedResolution::Complete { value, .. } = result else {
        panic!("{result:?}")
    };
    assert!(
        matches!(
            value.status,
            TypeLookupStatus::Resolved | TypeLookupStatus::Incomplete
        ),
        "{value:?}"
    );
    assert_eq!(value.types.len(), 1, "{value:?}");
    assert_eq!(value.types[0].definitions.len(), 1);
    let unit = &value.types[0].definitions[0];
    assert_eq!(unit.source(), &file);
    assert_eq!(unit.terminal_name(), "T");
    assert_eq!(value.types[0].fqn, format!("*{}", unit.fq_name()));
}

#[test]
fn go_native_point_keeps_generic_call_result_incomplete() {
    let source = r#"package consumer

type Result struct{}
func (Result) Maybe() {}
func Identity[T any](value T) T { return value }
func use() { Identity(Result{}).Maybe() }
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "Maybe");

    assert_eq!(
        outcome.status,
        DefinitionLookupStatus::Incomplete,
        "{outcome:?}"
    );
    assert!(outcome.definitions.is_empty(), "{outcome:?}");
}

#[test]
fn go_native_point_projects_each_multi_result_call_position() {
    let source = r#"package consumer

type First struct{}
func (First) FirstResult() {}
type Second struct{}
func (Second) SecondResult() {}

func Pair() (First, Second) { return First{}, Second{} }
func use() {
    first, second := Pair()
    first.FirstResult()
    second.SecondResult()
}

#[test]
fn go_native_point_projects_results_of_function_typed_values() {
    let source = r#"package consumer

type Result struct{}
func (Result) FromFunctionValue() {}
func use(function func() Result) {
    function().FromFunctionValue()
}

#[test]
fn go_native_point_resolves_call_results_through_intermediate_and_promoted_types() {
    const CALLER_PATH: &str = "consumer/use.go";
    let caller = r#"package consumer

import api "example.test/native/api"

func use() {
    value := api.GetDirect()
    value.FromIntermediate()
    api.GetPromoted().FromPromoted()
}

#[test]
fn go_native_point_resolves_declared_function_and_method_call_results() {
    let source = r#"package consumer

type DirectType struct{}
func (DirectType) FromFunction() {}
func MakeDirect() DirectType { return DirectType{} }

type MethodType struct{}
func (MethodType) FromMethod() {}
type Factory struct{}
func (Factory) Get() MethodType { return MethodType{} }

type AssignedType struct{}
func (AssignedType) FromAssignment() {}
func MakeAssigned() AssignedType { return AssignedType{} }

func use(factory Factory) {
    MakeDirect().FromFunction()
    factory.Get().FromMethod()
    value := MakeAssigned()
    value.FromAssignment()
}

#[test]
fn go_native_point_resolves_fields_on_call_results() {
    let source = r#"package consumer

type Result struct{ Name string }
func Detect() Result { return Result{} }
func use() { _ = Detect().Name }
"#;
    let fixture = InlineTestProject::with_language(Language::Go)
        .file("go.mod", "module example.test/native\n\ngo 1.22\n")
        .file(CALLER, source)
        .build();
    let analyzer = GoAnalyzer::new(fixture.project_dyn());
    let outcome = resolve_last(&analyzer, &fixture, CALLER, source, "Name");

    assert_eq!(outcome.definitions.len(), 1, "{outcome:?}");
    assert_eq!(
        outcome.definitions[0].fq_name().to_string(),
        "example.test/native/consumer.Result.Name",
        "{outcome:?}"
    );
}
