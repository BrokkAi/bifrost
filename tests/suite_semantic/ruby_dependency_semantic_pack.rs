use std::fs;
use std::sync::Arc;
use std::time::Instant;

use brokk_bifrost::analyzer::semantic_model::*;
use brokk_bifrost::searchtools::{
    DefinitionReferenceQuery, GetDefinitionParams, ScanUsagesByReferenceParams, ScanUsagesStatus,
    SearchSymbolsParams, SymbolLookupParams, get_definitions_by_location, get_symbol_locations,
    get_symbol_sources, scan_usages_by_reference, search_symbols,
};
use brokk_bifrost::{
    AnalyzerConfig, CancellationToken, FilesystemProject, Language, Project, RubyAnalyzerConfig,
    RubyDependencyApiEvidence, RubyDependencyPackAdapter, RubyGemApiArtifact, WorkspaceAnalyzer,
    resolve_ruby_semantic_pack_dependencies,
};
use brokk_bifrost_analysis::analyzer::structural::BoundaryStatus;
use brokk_bifrost_analysis::analyzer::{
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome,
};
use flate2::Compression;
use flate2::write::GzEncoder;
use semver::Version;
use sha2::{Digest, Sha256};

use crate::common::InlineTestProject;

const LOCKFILE: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    widget (1.2.3)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  widget\n\nRUBY VERSION\n   ruby 3.4.1p0\n";

#[test]
fn exact_ruby_gem_prepares_activates_and_navigates_without_workspace_files() {
    let fixture = InlineTestProject::with_language(Language::Ruby)
        .file("Gemfile.lock", LOCKFILE)
        // Line 1 carries the navigation assertions below, which are line- and
        // column-addressed. Line 2 is the constant path the diagnostics lane
        // classifies against the same activated pack (#1624).
        .file("main.rb", "Widget.new.call('x')\nWidget::Missing\n")
        .build();
    let archives = tempfile::tempdir().unwrap();
    let archive = gem_archive(&[
        (
            "sig/widget.rbs",
            br#"class Base
end
module Instrumented
end
module Enumerable
end
module Factory
end
class Widget < Base
  prepend Instrumented
  include Enumerable
  extend Factory
  def call: (String value) -> Integer
          | (Integer value) -> String
  def self.build: () -> Widget
  alias invoke call
end
"#,
        ),
        (
            "sorbet/rbi/widget.rbi",
            br#"class Widget
  sig { params(value: String).returns(Integer) }
  def call(value); end
end
"#,
        ),
        (
            "lib/widget.rb",
            b"class Widget; def call(value); end; end\n",
        ),
    ]);
    let archive_path = archives.path().join("widget-1.2.3.gem");
    fs::write(&archive_path, &archive).unwrap();
    let config = AnalyzerConfig {
        ruby: RubyAnalyzerConfig {
            dependency_api_evidence: vec![RubyDependencyApiEvidence {
                lockfile_path: fixture.root().join("Gemfile.lock"),
                lockfile_sha256: digest(LOCKFILE.as_bytes()),
                ruby_version: "3.4.1".to_owned(),
                platform: "ruby".to_owned(),
                approved_archive_roots: vec![archives.path().to_path_buf()],
                gems: vec![RubyGemApiArtifact {
                    name: "widget".to_owned(),
                    version: "1.2.3".to_owned(),
                    source: "https://rubygems.org/".to_owned(),
                    checksum: Some(digest(&archive)),
                    gem_archive_path: archive_path.clone(),
                }],
            }],
        },
        ..AnalyzerConfig::default()
    };
    let project = Arc::new(FilesystemProject::new(fixture.root()).unwrap());
    let files_before = project.all_files().unwrap();
    let analyzer = WorkspaceAnalyzer::build(project.clone(), config.clone());
    let limits = DependencyPackLimits::default();
    let discovery_started = Instant::now();
    let discovery =
        resolve_ruby_semantic_pack_dependencies(&config.ruby, project.as_ref(), &limits, None);
    let discovery_elapsed = discovery_started.elapsed();
    assert!(discovery.complete, "{:#?}", discovery.diagnostics);
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let cold_started = Instant::now();
    let prepared = prepare_discovered_dependency_semantic_packs(
        &catalog,
        &RubyDependencyPackAdapter,
        discovery,
        &limits,
        None,
    );
    let cold_elapsed = cold_started.elapsed();
    assert!(prepared.complete, "{:#?}", prepared.diagnostics);
    let artifact_bytes_read = prepared.profile.artifact_bytes_read;
    let compiled_stored_bytes = catalog.accounting().unwrap().installed_stored_bytes;
    let repeated_discovery =
        resolve_ruby_semantic_pack_dependencies(&config.ruby, project.as_ref(), &limits, None);
    let warm_started = Instant::now();
    let warm = prepare_discovered_dependency_semantic_packs(
        &catalog,
        &RubyDependencyPackAdapter,
        repeated_discovery,
        &limits,
        None,
    );
    let warm_elapsed = warm_started.elapsed();
    assert!(warm.complete, "{:#?}", warm.diagnostics);
    assert_eq!(warm.profile.reused_packs, 1);
    let request = warm
        .compose_activation_request(SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        })
        .unwrap();
    let SemanticModelRuntimeOutcome::Ready { active, .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    ) else {
        panic!("exact Ruby gem pack must activate");
    };
    assert_eq!(project.all_files().unwrap(), files_before);
    assert!(
        files_before
            .iter()
            .all(|file| file.abs_path() != archive_path)
    );

    let overlay = analyzer
        .analyzer()
        .semantic_model_overlay()
        .expect("active Ruby dependency overlay");
    let widget = overlay.symbols_named("Widget");
    assert_eq!(widget.disposition, SemanticModelOverlayDisposition::Unique);
    assert!(
        widget.records[0]
            .location
            .identity()
            .starts_with("bifrost-model://v1/")
    );
    let widget_uri = widget.records[0].location.identity().to_owned();
    assert!(
        !widget.records[0]
            .location
            .identity()
            .contains(archives.path().to_string_lossy().as_ref())
    );
    let members = overlay.members_of(&widget.records[0].id);
    assert_eq!(
        members
            .records
            .iter()
            .filter(|member| member.name == "call")
            .count(),
        2
    );
    assert!(members.records.iter().any(|member| {
        member.name == "call"
            && member.aliases == ["invoke"]
            && member.signature.as_deref() == Some("call(value: String) -> Integer")
    }));
    assert!(
        members
            .records
            .iter()
            .any(|member| member.name == "build" && member.signature.is_some())
    );
    let relation_kinds = overlay
        .relations_from(&widget.records[0].id)
        .records
        .iter()
        .map(|relation| relation.kind.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        relation_kinds,
        ["extends", "mixin_prepend", "mixin_include", "mixin_extend"]
    );
    assert_eq!(
        overlay
            .ancestors_of(widget.records[0])
            .records
            .iter()
            .map(|ancestor| ancestor.qualified_name.as_str())
            .collect::<Vec<_>>(),
        ["Base", "Instrumented", "Enumerable"]
    );

    let search = search_symbols(
        analyzer.analyzer(),
        SearchSymbolsParams {
            patterns: vec!["Widget".to_owned()],
            include_tests: false,
            limit: 10,
        },
    );
    assert!(
        search
            .model_symbols
            .iter()
            .any(|symbol| symbol.qualified_name == "Widget")
    );
    let sources = get_symbol_sources(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec!["Widget".to_owned()],
        },
    );
    assert!(sources.not_found.is_empty(), "{:#?}", sources.not_found);
    assert_eq!(sources.sources.len(), 1);
    assert!(sources.sources[0].semantic_model.is_some());
    let locations = get_symbol_locations(
        analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec!["Widget".to_owned()],
        },
    );
    assert!(locations.not_found.is_empty(), "{:#?}", locations.not_found);
    assert_eq!(locations.model_locations.len(), 1);
    let definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![DefinitionReferenceQuery {
                path: widget_uri,
                line: None,
                column: None,
            }],
        },
    );
    assert_eq!(definitions.results[0].status, "resolved");
    assert!(
        definitions.results[0]
            .definitions
            .iter()
            .any(|definition| definition.path.starts_with("bifrost-model://v1/")),
        "{:#?}",
        definitions.results[0]
    );
    let workspace_definitions = get_definitions_by_location(
        analyzer.analyzer(),
        GetDefinitionParams {
            references: vec![
                DefinitionReferenceQuery {
                    path: "main.rb".to_owned(),
                    line: Some(1),
                    column: Some(1),
                },
                DefinitionReferenceQuery {
                    path: "main.rb".to_owned(),
                    line: Some(1),
                    column: Some(12),
                },
            ],
        },
    );
    for result in &workspace_definitions.results {
        assert_eq!(result.status, "resolved", "{result:#?}");
        assert!(
            result
                .definitions
                .iter()
                .any(|definition| definition.path.starts_with("bifrost-model://v1/")),
            "{result:#?}"
        );
    }
    let usages = scan_usages_by_reference(
        analyzer.analyzer(),
        ScanUsagesByReferenceParams {
            symbols: vec!["Base".to_owned()],
            include_tests: false,
            paths: None,
            include_same_owner: false,
            max_duration_secs: None,
        },
    );
    assert_eq!(usages.results[0].status, ScanUsagesStatus::Found);
    assert!(!usages.results[0].model_relations.is_empty());

    // #1624: the diagnostics lane must find this gem's declarations under the
    // identity the *real* producer minted from the archive's RBS, not merely
    // under one an authored fixture agreed to. A verdict that named a missing
    // dependency would mean the identity lookup missed the pack entirely.
    let main = fixture.file("main.rb");
    let main_source = project.read_source(&main).unwrap();
    let report = analyzer
        .analyzer()
        .semantic_diagnostics(&main, &main_source);
    let reached_the_pack = report.outcomes().iter().any(|outcome| match outcome {
        SemanticDiagnosticOutcome::Absent(proof) => {
            proof.boundary == BoundaryStatus::ExternalIndexed
        }
        SemanticDiagnosticOutcome::Incomplete { reasons, .. } => reasons.iter().any(|reason| {
            matches!(
                reason,
                SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }
                    if detail.contains("Widget")
            )
        }),
        _ => false,
    });
    assert!(
        reached_the_pack,
        "`Widget::Missing` must be classified against the activated gem pack: {report:#?}"
    );

    let (type_count, member_count, relation_count) = active
        .shards()
        .iter()
        .filter_map(|shard| shard.shard.payload().declaration_facts())
        .fold((0, 0, 0), |counts, facts| {
            (
                counts.0 + facts.0.len(),
                counts.1 + facts.1.len(),
                counts.2 + facts.2.len(),
            )
        });
    eprintln!(
        "ruby_dependency_pack_measurement={{\"input_bytes\":{},\"compiled_stored_bytes\":{},\"produced_facts\":{},\"type_facts\":{},\"member_facts\":{},\"relation_facts\":{},\"retained_bytes\":{},\"discovery_us\":{},\"cold_generation_us\":{},\"warm_reuse_us\":{}}}",
        artifact_bytes_read,
        compiled_stored_bytes,
        type_count + member_count + relation_count,
        type_count,
        member_count,
        relation_count,
        active.retained_bytes(),
        discovery_elapsed.as_micros(),
        cold_elapsed.as_micros(),
        warm_elapsed.as_micros(),
    );
}

// #1794: a gem archive is untrusted input. An entry the RBS projection cannot
// model has to leave the producer with a pack it can still publish, and that
// pack has to be `Partial` so the absence prover from #1624 refuses to turn the
// projection's own blind spot into proof that a constant does not exist.
#[test]
fn a_gem_declaration_this_producer_cannot_model_yields_a_partial_pack_that_cannot_prove_absence() {
    let modeled =
        classify_missing_constant(b"class Widget\n  def call: (String value) -> Integer\nend\n");
    assert_eq!(modeled.completeness, Completeness::Complete, "{modeled:#?}");
    assert!(modeled.diagnostic_codes.is_empty(), "{modeled:#?}");
    assert!(
        modeled.proved_absent,
        "a complete gem surface must prove `Widget::Missing` absent: {modeled:#?}"
    );

    // The same class, plus declarations outside every projected arm, plus
    // comments that carry no surface and so must stay trivia.
    let unmodeled = classify_missing_constant(
        br#"# a gem's own copyright header
class Widget
  # a comment between the header and the first member
  def call: (String value) -> Integer
  @hidden: untyped
end
$hostile: untyped
type shadow = Integer
"#,
    );
    assert_eq!(
        unmodeled.completeness,
        Completeness::Partial,
        "{unmodeled:#?}"
    );
    assert!(
        unmodeled
            .diagnostic_codes
            .iter()
            .any(|code| code == "ruby.rbs.unsupported_member"),
        "{unmodeled:#?}"
    );
    assert!(
        unmodeled
            .diagnostic_codes
            .iter()
            .any(|code| code == "ruby.rbs.unsupported_declaration"),
        "{unmodeled:#?}"
    );
    assert!(
        !unmodeled.proved_absent,
        "a partial gem surface must not prove `Widget::Missing` absent: {unmodeled:#?}"
    );
    assert!(
        unmodeled
            .suppressed
            .as_deref()
            .is_some_and(|detail| detail.contains("partial")),
        "{unmodeled:#?}"
    );
}

#[derive(Debug)]
struct GemClassification {
    completeness: Completeness,
    diagnostic_codes: Vec<String>,
    proved_absent: bool,
    suppressed: Option<String>,
}

/// Drives one crafted `.rbs` through the whole offline Ruby pack path and
/// reports how the diagnostics lane then classifies `Widget::Missing`.
fn classify_missing_constant(rbs: &[u8]) -> GemClassification {
    let fixture = InlineTestProject::with_language(Language::Ruby)
        .file("Gemfile.lock", LOCKFILE)
        .file("main.rb", "Widget::Missing\n")
        .build();
    let archives = tempfile::tempdir().unwrap();
    let archive = gem_archive(&[("sig/widget.rbs", rbs)]);
    let archive_path = archives.path().join("widget-1.2.3.gem");
    fs::write(&archive_path, &archive).unwrap();
    let config = AnalyzerConfig {
        ruby: RubyAnalyzerConfig {
            dependency_api_evidence: vec![RubyDependencyApiEvidence {
                lockfile_path: fixture.root().join("Gemfile.lock"),
                lockfile_sha256: digest(LOCKFILE.as_bytes()),
                ruby_version: "3.4.1".to_owned(),
                platform: "ruby".to_owned(),
                approved_archive_roots: vec![archives.path().to_path_buf()],
                gems: vec![RubyGemApiArtifact {
                    name: "widget".to_owned(),
                    version: "1.2.3".to_owned(),
                    source: "https://rubygems.org/".to_owned(),
                    checksum: Some(digest(&archive)),
                    gem_archive_path: archive_path.clone(),
                }],
            }],
        },
        ..AnalyzerConfig::default()
    };
    let project = Arc::new(FilesystemProject::new(fixture.root()).unwrap());
    let analyzer = WorkspaceAnalyzer::build(project.clone(), config.clone());
    let limits = DependencyPackLimits::default();
    let discovery =
        resolve_ruby_semantic_pack_dependencies(&config.ruby, project.as_ref(), &limits, None);
    assert!(discovery.complete, "{:#?}", discovery.diagnostics);
    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
    let prepared = prepare_discovered_dependency_semantic_packs(
        &catalog,
        &RubyDependencyPackAdapter,
        discovery,
        &limits,
        None,
    );
    assert_eq!(prepared.packs.len(), 1, "{:#?}", prepared.diagnostics);
    let completeness = prepared.packs[0].completeness;
    let diagnostic_codes = prepared
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect::<Vec<_>>();
    let request = prepared
        .compose_activation_request(SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        })
        .unwrap();
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models(
        analyzer.analyzer(),
        &catalog,
        None,
        &request,
        &CancellationToken::default(),
    ) else {
        panic!("the crafted Ruby gem pack must still activate");
    };
    let main = fixture.file("main.rb");
    let main_source = project.read_source(&main).unwrap();
    let report = analyzer
        .analyzer()
        .semantic_diagnostics(&main, &main_source);
    let proved_absent = report.outcomes().iter().any(|outcome| {
        matches!(
            outcome,
            SemanticDiagnosticOutcome::Absent(proof)
                if proof.boundary == BoundaryStatus::ExternalIndexed
        )
    });
    let suppressed = report.outcomes().iter().find_map(|outcome| match outcome {
        SemanticDiagnosticOutcome::Incomplete { reasons, .. } => {
            reasons.iter().find_map(|reason| match reason {
                SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail } => {
                    Some(detail.clone())
                }
                _ => None,
            })
        }
        _ => None,
    });
    GemClassification {
        completeness,
        diagnostic_codes,
        proved_absent,
        suppressed,
    }
}

fn gem_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut compressed = Vec::new();
    {
        let encoder = GzEncoder::new(&mut compressed, Compression::default());
        let mut data = tar::Builder::new(encoder);
        for (path, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            data.append_data(&mut header, path, *bytes).unwrap();
        }
        data.into_inner().unwrap().finish().unwrap();
    }
    let mut gem = Vec::new();
    {
        let mut outer = tar::Builder::new(&mut gem);
        let mut header = tar::Header::new_gnu();
        header.set_size(compressed.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        outer
            .append_data(&mut header, "data.tar.gz", compressed.as_slice())
            .unwrap();
        outer.finish().unwrap();
    }
    gem
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
