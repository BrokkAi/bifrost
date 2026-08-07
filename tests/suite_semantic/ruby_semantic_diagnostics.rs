//! Ruby's semantic diagnostics, against the workspace closure and against
//! exact gem API packs (#1624).
//!
//! Every assertion is outcome-level: what a report *claims* matters more than
//! how many diagnostics it printed, because the contract is that a diagnostic
//! exists only where a complete surface proved absence, and that every other
//! candidate leaves a typed reason behind instead of silence.
//!
//! The packs here are authored offline and registered as session packs. No test
//! runs Bundler, reads a `.gem`, or reaches the network.

use crate::common::InlineTestProject;
use brokk_bifrost::analyzer::semantic_model::{
    CatalogCoordinate, CatalogOptions, CompiledSemanticModelPack, CompilerOptions,
    DependencyDiscoveryEvidence, DependencyDiscoveryOutcome, ResolvedDependency,
    SemanticModelActivationControl, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
    SemanticModelPackSelector, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
    SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat, TypeIdentity,
    acquire_active_semantic_models_with_evidence, compile_source, type_declaration_id,
};
use brokk_bifrost::searchtools::{SymbolLookupParams, get_symbol_locations};
use brokk_bifrost::{
    AnalyzerConfig, CancellationToken, IAnalyzer, Language, Project, RubyAnalyzer,
    WorkspaceAnalyzer,
};
use brokk_bifrost_analysis::analyzer::structural::BoundaryStatus;
use brokk_bifrost_analysis::analyzer::{
    SemanticAbsenceProof, SemanticDiagnosticDomain, SemanticDiagnosticIncompleteReason,
    SemanticDiagnosticOutcome, SemanticDiagnosticReport, SemanticDiagnosticReportStatus,
};
use serde_json::{Value, json};

/// The ecosystem the Ruby gem pack producer mints every declaration identity
/// under. Spelled here rather than imported so that a change to
/// `ruby::constant_identity` has to be a deliberate one: this constant and the
/// `::`-joined name shape below are the contract a pack and a diagnostic share.
const RUBY_GEM_ECOSYSTEM: &str = "rubygems";

const GEM: &str = "widget";
/// A second gem that installs the same constant name as [`GEM`]. Two gems can
/// do this, and the overlay must call it a conflict rather than pick a winner.
const FORK_GEM: &str = "widget-fork";

fn ruby_type_id(constant_path: &str) -> String {
    type_declaration_id(TypeIdentity {
        ecosystem: RUBY_GEM_ECOSYSTEM,
        name: constant_path,
    })
}

// ---------------------------------------------------------------------------
// Report helpers
// ---------------------------------------------------------------------------

fn absences(report: &SemanticDiagnosticReport) -> Vec<&SemanticAbsenceProof> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Absent(proof) => Some(proof),
            _ => None,
        })
        .collect()
}

fn resolved_boundaries(report: &SemanticDiagnosticReport) -> Vec<BoundaryStatus> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Resolved { boundary, .. } => Some(*boundary),
            _ => None,
        })
        .collect()
}

fn incomplete_reasons(
    report: &SemanticDiagnosticReport,
) -> Vec<&SemanticDiagnosticIncompleteReason> {
    report
        .outcomes()
        .iter()
        .filter_map(|outcome| match outcome {
            SemanticDiagnosticOutcome::Incomplete { reasons, .. } => Some(reasons),
            _ => None,
        })
        .flatten()
        .collect()
}

/// Every incomplete reason rendered, for substring assertions on the detail a
/// suppression names.
fn incomplete_details(report: &SemanticDiagnosticReport) -> Vec<String> {
    incomplete_reasons(report)
        .into_iter()
        .map(|reason| format!("{reason:?}"))
        .collect()
}

fn assert_states(report: &SemanticDiagnosticReport, expected: &str) {
    assert!(
        report.diagnostics().is_empty(),
        "no diagnostic may be published: {report:#?}"
    );
    assert_eq!(
        SemanticDiagnosticReportStatus::Incomplete,
        report.status(),
        "a suppressed candidate must leave the report incomplete: {report:#?}"
    );
    assert!(
        incomplete_details(report)
            .iter()
            .any(|detail| detail.contains(expected)),
        "expected a suppression naming {expected:?}: {report:#?}"
    );
}

// ---------------------------------------------------------------------------
// Workspace-only fixtures: no host has activated any gem pack.
// ---------------------------------------------------------------------------

fn workspace_report(files: &[(&str, &str)], target: &str) -> SemanticDiagnosticReport {
    let mut project = InlineTestProject::with_language(Language::Ruby);
    for (path, contents) in files {
        project = project.file(*path, *contents);
    }
    let project = project.build();
    let analyzer = RubyAnalyzer::new(project.project_dyn());
    let file = project.file(target);
    let source = project
        .project()
        .read_source(&file)
        .expect("read target source");
    analyzer.semantic_diagnostics(&file, &source)
}

#[test]
fn ruby_semantic_diagnostics_report_unknown_explicit_constants() {
    let report = workspace_report(
        &[("app.rb", "module Billing\nend\nBilling::Missing\n")],
        "app.rb",
    );

    assert_eq!(1, report.diagnostics().len(), "{report:#?}");
    assert!(report.diagnostics()[0].message.contains("Missing"));
    let proofs = absences(&report);
    assert_eq!(1, proofs.len(), "{report:#?}");
    assert_eq!(BoundaryStatus::WorkspaceLocal, proofs[0].boundary);
    assert!(
        matches!(
            proofs[0].domain,
            SemanticDiagnosticDomain::LexicalScope { .. }
        ),
        "a workspace absence names the lexical surface it checked: {report:#?}"
    );
    assert_eq!(
        proofs[0].range,
        report.diagnostics()[0].range,
        "the proof and the diagnostic identify one range"
    );
    assert_eq!(SemanticDiagnosticReportStatus::Complete, report.status());
}

#[test]
fn ruby_semantic_diagnostics_follow_project_local_require_closures() {
    for (name, files) in [
        (
            "require_relative",
            vec![
                ("app.rb", "require_relative \"billing\"\nBilling::Present\n"),
                (
                    "billing.rb",
                    "module Billing\n  class Present\n  end\nend\n",
                ),
            ],
        ),
        (
            "project-root require",
            vec![
                ("app.rb", "require \"lib/billing\"\nBilling::Present\n"),
                (
                    "lib/billing.rb",
                    "module Billing\n  class Present\n  end\nend\n",
                ),
            ],
        ),
        (
            "transitive require",
            vec![
                ("app.rb", "require_relative \"boot\"\nBilling::Present\n"),
                ("boot.rb", "require_relative \"billing\"\n"),
                (
                    "billing.rb",
                    "module Billing\n  class Present\n  end\nend\n",
                ),
            ],
        ),
        (
            "nested lexical namespaces",
            vec![
                (
                    "app.rb",
                    "require_relative \"defs\"\nmodule A\n  module B\n    A::B::Present\n  end\nend\n",
                ),
                (
                    "defs.rb",
                    "module A\n  module B\n    class Present\n    end\n  end\nend\n",
                ),
            ],
        ),
    ] {
        let report = workspace_report(&files, "app.rb");
        assert!(
            report.diagnostics().is_empty(),
            "{name} must resolve: {report:#?}"
        );
        assert!(
            resolved_boundaries(&report).contains(&BoundaryStatus::WorkspaceLocal),
            "{name} must record a workspace-local resolution: {report:#?}"
        );
    }
}

/// Every construct that used to make the pass return an empty `Vec` now names
/// the reason it could not judge the file. The suppression set is unchanged;
/// what changed is that a host can read why.
#[test]
fn ruby_semantic_diagnostics_state_dynamic_and_open_boundaries() {
    for (name, expected, files) in [
        (
            "explicit autoload",
            "autoload",
            vec![
                (
                    "app.rb",
                    "autoload :Billing, \"billing\"\nBilling::Missing\n",
                ),
                ("billing.rb", "module Billing\nend\n"),
            ],
        ),
        (
            "zeitwerk convention",
            "Zeitwerk",
            vec![
                ("Gemfile", "gem \"zeitwerk\"\n"),
                ("app/models/billing.rb", "module Billing\nend\n"),
                ("app.rb", "Billing::Missing\n"),
            ],
        ),
        (
            "dynamic constant lookup",
            "const_get",
            vec![(
                "app.rb",
                "module Billing\nend\nBilling.const_get(:Missing)\n",
            )],
        ),
        (
            "dynamic required file",
            "const_set",
            vec![
                (
                    "app.rb",
                    "require_relative \"generated\"\nmodule Billing\nend\nBilling::Missing\n",
                ),
                (
                    "generated.rb",
                    "module Billing\n  const_set(:Missing, Class.new)\nend\n",
                ),
            ],
        ),
        (
            "dynamic evaluation",
            "eval",
            vec![(
                "app.rb",
                "module Billing\nend\neval(\"Billing::Missing = Class.new\")\nBilling::Missing\n",
            )],
        ),
        (
            "dynamic const_missing definition",
            "const_missing",
            vec![(
                "app.rb",
                "module Billing\nend\nBilling.define_singleton_method(:const_missing) { |name| Class.new }\nBilling::Missing\n",
            )],
        ),
        (
            "transitive dynamic const_missing definition",
            "const_missing",
            vec![
                (
                    "app.rb",
                    "require_relative \"runtime\"\nmodule Billing\nend\nBilling::Missing\n",
                ),
                (
                    "runtime.rb",
                    "Billing.define_method(\"const_missing\") { |name| Class.new }\n",
                ),
            ],
        ),
        (
            "unresolved gem require",
            "MissingDependencyDiscovery",
            vec![
                ("app.rb", "require \"remote_gem\"\nBilling::Missing\n"),
                ("billing.rb", "module Billing\nend\n"),
            ],
        ),
        (
            "transitive unresolved gem require",
            "MissingDependencyDiscovery",
            vec![
                (
                    "app.rb",
                    "require_relative \"boot\"\nmodule Billing\nend\nBilling::Missing\n",
                ),
                ("boot.rb", "require \"billing_runtime\"\n"),
            ],
        ),
        (
            "dynamic loader argument",
            "autoload",
            vec![(
                "app.rb",
                "module Billing\nend\nBilling.autoload :Missing, ENV.fetch(\"AUTOLOAD_PATH\")\nBilling::Missing\n",
            )],
        ),
        (
            "malformed source",
            "parse errors",
            vec![("app.rb", "module Billing\n")],
        ),
    ] {
        let report = workspace_report(&files, "app.rb");
        assert!(
            report.diagnostics().is_empty(),
            "{name} must remain outside the high-confidence slice: {report:#?}"
        );
        assert!(
            incomplete_details(&report)
                .iter()
                .any(|detail| detail.contains(expected)),
            "{name} must state a reason naming {expected:?}: {report:#?}"
        );
    }
}

/// A constant path this pass does not model at all is not a candidate, so it
/// leaves no outcome rather than a false suppression.
#[test]
fn ruby_semantic_diagnostics_do_not_judge_bare_constants_or_methods() {
    let core = workspace_report(&[("app.rb", "module Billing\n  String\nend\n")], "app.rb");
    assert!(core.diagnostics().is_empty(), "{core:#?}");
    assert!(
        absences(&core).is_empty(),
        "a core constant is never proven absent: {core:#?}"
    );

    let call = workspace_report(&[("app.rb", "missing_call\n")], "app.rb");
    assert!(call.diagnostics().is_empty(), "{call:#?}");
    assert!(
        absences(&call).is_empty(),
        "a method is never proven absent: {call:#?}"
    );
}

#[test]
fn ruby_semantic_diagnostics_state_inheritance_and_mixin_owners() {
    let inherited = workspace_report(
        &[("app.rb", "class Billing\nend\nBilling::Missing\n")],
        "app.rb",
    );
    assert_states(&inherited, "inherit constants from ancestors");

    let mixed = workspace_report(
        &[(
            "app.rb",
            "module Extra\nend\nmodule Billing\n  include Extra\nend\nBilling::Missing\n",
        )],
        "app.rb",
    );
    assert_states(&mixed, "supply constants");
}

#[test]
fn ruby_semantic_diagnostics_state_bounded_require_closures() {
    let mut project = InlineTestProject::with_language(Language::Ruby).file(
        "app.rb",
        "require_relative \"dep0\"\nmodule Billing\nend\nBilling::Missing\n",
    );
    for index in 0..64 {
        let next = (index + 1 < 64).then(|| format!("require_relative \"dep{}\"\n", index + 1));
        project = project.file(format!("dep{index}.rb"), next.unwrap_or_default());
    }
    let project = project.build();
    let analyzer = RubyAnalyzer::new(project.project_dyn());
    let file = project.file("app.rb");
    let source = project.project().read_source(&file).expect("read source");

    let report = analyzer.semantic_diagnostics(&file, &source);
    assert!(
        report.diagnostics().is_empty(),
        "an overwide dependency closure must fail closed: {report:#?}"
    );
    assert!(
        incomplete_reasons(&report).contains(&&SemanticDiagnosticIncompleteReason::Truncated),
        "the file-count cap is a truncation: {report:#?}"
    );
}

#[test]
fn ruby_semantic_diagnostics_state_bounded_required_source_bytes() {
    // Keep this source just over the 2 MiB visibility cap without creating
    // hundreds of thousands of syntax nodes during project initialization.
    let oversized_dependency = "#".repeat(2 * 1024 * 1024 + 1);
    let report = workspace_report(
        &[
            (
                "app.rb",
                "require_relative \"generated\"\nmodule Billing\nend\nBilling::Missing\n",
            ),
            ("generated.rb", &oversized_dependency),
        ],
        "app.rb",
    );

    assert!(
        report.diagnostics().is_empty(),
        "an oversized required source must fail closed: {report:#?}"
    );
    assert!(
        incomplete_reasons(&report).contains(&&SemanticDiagnosticIncompleteReason::Truncated),
        "the byte cap is a truncation: {report:#?}"
    );
}

/// Zeitwerk widens what a consumer file can see rather than blinding the pass.
#[test]
fn ruby_semantic_diagnostics_resolve_zeitwerk_visible_constants() {
    let visible = workspace_report(
        &[
            ("Gemfile", "gem \"zeitwerk\"\n"),
            (
                "app/models/billing.rb",
                "module Billing\n  class Present\n  end\nend\n",
            ),
            ("app.rb", "Billing::Present\n"),
        ],
        "app.rb",
    );
    assert!(visible.diagnostics().is_empty(), "{visible:#?}");
    assert!(
        resolved_boundaries(&visible).contains(&BoundaryStatus::WorkspaceLocal),
        "an autoloaded declaration is visible to a consumer: {visible:#?}"
    );

    // The same constant with no Zeitwerk convention in the project is not
    // visible to a file that never required it, and the packs know nothing.
    let invisible = workspace_report(
        &[
            (
                "app/models/billing.rb",
                "module Billing\n  class Present\n  end\nend\n",
            ),
            ("app.rb", "Billing::Present\n"),
        ],
        "app.rb",
    );
    assert!(invisible.diagnostics().is_empty(), "{invisible:#?}");
    assert!(
        resolved_boundaries(&invisible).is_empty(),
        "a file that required nothing sees nothing: {invisible:#?}"
    );
    assert_states(&invisible, "MissingDependencyDiscovery");
}

// ---------------------------------------------------------------------------
// Gem pack fixtures
// ---------------------------------------------------------------------------

/// A Ruby type fact, keyed by the identity the gem pack producer mints.
fn ruby_type(name: &str, type_kind: &str, hierarchy: Value) -> Value {
    ruby_type_from("sig/widget.rbs", name, type_kind, hierarchy)
}

/// The same fact, sourced from a named signature file.
///
/// Two gems that install one constant publish the same declaration *identity*
/// but not the same declaration: the runtime drops a record that is equal to
/// one it already resolved, so a fixture that wants a real cross-pack conflict
/// has to differ somewhere. The signature path is where two gems genuinely
/// differ, and it changes neither the identity nor the symbol name.
fn ruby_type_from(path: &str, name: &str, type_kind: &str, hierarchy: Value) -> Value {
    json!({
        "id": ruby_type_id(name),
        "name": name,
        "type_kind": type_kind,
        "visibility": "public",
        "hierarchy": hierarchy,
        "locator": { "kind": "artifact", "path": path, "symbol": name }
    })
}

fn ruby_member(
    owner: &str,
    name: &str,
    member_kind: &str,
    is_static: bool,
    aliases: Value,
) -> Value {
    json!({
        // Pack identifiers are lowercase; a Ruby constant name is not, so the
        // synthetic record id is spelled separately from the member name.
        "id": format!("member.{}.{name}", owner.replace("::", ".")).to_lowercase(),
        "owner": ruby_type_id(owner),
        "name": name,
        "member_kind": member_kind,
        "visibility": "public",
        "is_static": is_static,
        "aliases": aliases,
        "locator": { "kind": "artifact", "path": "sig/widget.rbs", "symbol": format!("{owner}#{name}") }
    })
}

fn compile(value: &Value) -> CompiledSemanticModelPack {
    compile_source(
        SourceFormat::Json,
        &serde_json::to_vec(value).unwrap(),
        &CompilerOptions::default(),
    )
    .unwrap_or_else(|diagnostics| panic!("fixture pack must compile: {diagnostics:#?}"))
}

fn pack_source(
    pack_id: &str,
    gem: &str,
    completeness: &str,
    types: Value,
    members: Value,
) -> Value {
    json!({
        "schema_version": 1,
        "pack_id": pack_id,
        "version": "1.0.0",
        "producer": { "name": "ruby-fixture", "version": "1.0.0" },
        "language": "ruby",
        "ecosystem": RUBY_GEM_ECOSYSTEM,
        "compatibility": { "bifrost": "*", "toolchains": [] },
        "provenance": { "source": "fixture" },
        "license": "NOASSERTION",
        "completeness": completeness,
        "safety": { "generated_code_only": false, "review_required": false },
        "shards": [{
            "id": format!("declarations.{pack_id}"),
            "activation": [{ "package": { "name": gem } }],
            "payload": {
                "kind": "declaration_facts",
                "types": types,
                "members": members,
                "relations": []
            }
        }]
    })
}

/// The `widget` gem, complete: a class with a nested type, a constant, an
/// aliased instance method and a singleton method; a module whose constants
/// arrive through a mixin; and a class whose superclass no pack publishes.
fn widget_pack() -> CompiledSemanticModelPack {
    compile(&pack_source(
        "fixture.ruby.widget",
        GEM,
        "complete",
        json!([
            ruby_type("Widget", "class", json!([])),
            ruby_type("Widget::Config", "class", json!([])),
            ruby_type("Palette", "module", json!([])),
            ruby_type(
                "Themed",
                "module",
                json!([{
                    "hierarchy_kind": "mixin_include",
                    "target": { "kind": "named", "name": "Palette" }
                }])
            ),
            ruby_type(
                "Legacy",
                "class",
                json!([{
                    "hierarchy_kind": "extends",
                    "target": { "kind": "named", "name": "Unpublished::Base" }
                }])
            ),
        ]),
        json!([
            ruby_member("Widget", "VERSION", "constant", true, json!(["Version"])),
            ruby_member("Widget", "call", "method", false, json!(["invoke"])),
            ruby_member("Widget", "build", "method", true, json!([])),
            ruby_member("Palette", "RED", "constant", true, json!([])),
        ]),
    ))
}

fn activation_request(pack_ids: &[&str]) -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        evidence: [GEM, FORK_GEM]
            .into_iter()
            .map(|gem| SemanticModelActivationEvidence {
                language: "ruby".to_owned(),
                ecosystem: RUBY_GEM_ECOSYSTEM.to_owned(),
                package: Some(CatalogCoordinate {
                    name: gem.to_owned(),
                    version: None,
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            })
            .collect(),
        controls: pack_ids
            .iter()
            .map(|pack_id| SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: (*pack_id).to_owned(),
                    version: None,
                    manifest_digest: None,
                },
            })
            .collect(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}

/// Retained evidence that `Gemfile.lock` declares `gem` and nothing more. This
/// is the residue a discovery run leaves behind; constructing it directly keeps
/// the test offline.
fn declared_gem_evidence(gem: &str) -> DependencyDiscoveryEvidence {
    DependencyDiscoveryEvidence::from_outcome(&DependencyDiscoveryOutcome::complete(vec![
        ResolvedDependency {
            id: format!("rubygems:{gem}"),
            evidence: SemanticModelActivationEvidence {
                language: "ruby".to_owned(),
                ecosystem: RUBY_GEM_ECOSYSTEM.to_owned(),
                package: Some(CatalogCoordinate {
                    name: gem.to_owned(),
                    version: None,
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            },
            provenance: Vec::new(),
            artifacts: Vec::new(),
        },
    ]))
}

struct GemFixture {
    project: crate::common::BuiltInlineTestProject,
    analyzer: WorkspaceAnalyzer,
}

impl GemFixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let mut builder = InlineTestProject::with_language(Language::Ruby);
        for (path, source) in files {
            builder = builder.file(*path, *source);
        }
        let project = builder.build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        Self { project, analyzer }
    }

    /// Activate `packs`, each named by its own `pack_id`, against the fixture's
    /// analyzer. The catalog is ephemeral and every pack is a session pack, so
    /// nothing is installed and nothing is downloaded.
    fn activate(
        &self,
        packs: &[(&str, &CompiledSemanticModelPack)],
        discovery: Option<DependencyDiscoveryEvidence>,
    ) {
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        for (pack_id, pack) in packs {
            catalog
                .register_session_pack(
                    pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: (*pack_id).to_owned(),
                    },
                )
                .unwrap();
        }
        let selectors = packs
            .iter()
            .map(|(pack_id, _)| *pack_id)
            .collect::<Vec<_>>();
        let published = discovery.map(|evidence| [(Box::from([Language::Ruby]), evidence)]);
        let SemanticModelRuntimeOutcome::Ready { .. } =
            acquire_active_semantic_models_with_evidence(
                self.analyzer.analyzer(),
                &catalog,
                None,
                &activation_request(&selectors),
                published.as_ref().map(|published| published.as_slice()),
                &CancellationToken::default(),
            )
        else {
            panic!("Ruby fixture packs must activate");
        };
        assert!(self.analyzer.analyzer().semantic_model_overlay().is_some());
    }

    fn report(&self, rel_path: &str) -> SemanticDiagnosticReport {
        let file = self.project.file(rel_path);
        let source = self
            .project
            .project()
            .read_source(&file)
            .expect("read source");
        self.analyzer
            .analyzer()
            .semantic_diagnostics(&file, &source)
    }
}

/// The headline: a constant an activated gem pack publishes resolves at the
/// indexed boundary, and one its complete surface omits is proven absent.
#[test]
fn ruby_gem_pack_constants_resolve_and_complete_surfaces_prove_absence() {
    let fixture = GemFixture::new(&[(
        "app.rb",
        "Widget::Config\nWidget::VERSION\nWidget::Missing\n",
    )]);
    fixture.activate(&[("fixture.ruby.widget", &widget_pack())], None);

    let report = fixture.report("app.rb");
    assert_eq!(
        2,
        resolved_boundaries(&report)
            .iter()
            .filter(|boundary| **boundary == BoundaryStatus::ExternalIndexed)
            .count(),
        "the nested type and the constant both resolve through the pack: {report:#?}"
    );
    assert_eq!(1, report.diagnostics().len(), "{report:#?}");
    assert!(report.diagnostics()[0].message.contains("Missing"));
    let proofs = absences(&report);
    assert_eq!(1, proofs.len(), "{report:#?}");
    assert_eq!(BoundaryStatus::ExternalIndexed, proofs[0].boundary);
    assert_eq!(
        SemanticDiagnosticDomain::Type {
            name: "Widget".to_owned()
        },
        proofs[0].domain,
        "the proof names the gem type whose surface was checked: {report:#?}"
    );
}

/// A constant a pack publishes under an alias resolves under either spelling.
#[test]
fn ruby_gem_pack_constant_aliases_resolve() {
    let fixture = GemFixture::new(&[("app.rb", "Widget::VERSION\nWidget::Version\n")]);
    fixture.activate(&[("fixture.ruby.widget", &widget_pack())], None);

    let report = fixture.report("app.rb");
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert_eq!(
        2,
        resolved_boundaries(&report)
            .iter()
            .filter(|boundary| **boundary == BoundaryStatus::ExternalIndexed)
            .count(),
        "a published constant and its alias both resolve: {report:#?}"
    );
}

/// A Ruby method is never judged, declared or not.
///
/// Gem packs publish a gem's own declarations and nothing above them: no
/// `Object`, no `Module`, no `Kernel`. Even against a fully RBS-complete gem,
/// `Widget.new` would miss, so no member miss can be proof. This test pins that
/// decision, including for a method the pack does declare (`build`), so a later
/// change that starts judging members has to change this test deliberately.
#[test]
fn ruby_gem_pack_members_are_never_judged() {
    let fixture = GemFixture::new(&[(
        "app.rb",
        "Widget.new\nWidget.build\nWidget.call(1)\nWidget.undeclared_method\n",
    )]);
    fixture.activate(&[("fixture.ruby.widget", &widget_pack())], None);

    let report = fixture.report("app.rb");
    assert!(
        report.diagnostics().is_empty(),
        "no member may be reported: {report:#?}"
    );
    assert!(
        absences(&report).is_empty(),
        "no member may be proven absent: {report:#?}"
    );
}

/// Ruby's `Owner::CONST` lookup walks the ancestor chain, so a mixin's
/// constants are part of the surface.
#[test]
fn ruby_gem_pack_mixins_widen_the_constant_surface() {
    let fixture = GemFixture::new(&[("app.rb", "Themed::RED\n")]);
    fixture.activate(&[("fixture.ruby.widget", &widget_pack())], None);

    let report = fixture.report("app.rb");
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        resolved_boundaries(&report).contains(&BoundaryStatus::ExternalIndexed),
        "an included module supplies the constant: {report:#?}"
    );

    let missing = GemFixture::new(&[("app.rb", "Themed::Absent\n")]);
    missing.activate(&[("fixture.ruby.widget", &widget_pack())], None);
    let report = missing.report("app.rb");
    assert_eq!(
        1,
        report.diagnostics().len(),
        "a complete chain still proves absence: {report:#?}"
    );
    assert_eq!(
        SemanticDiagnosticDomain::Module {
            name: "Themed".to_owned()
        },
        absences(&report)[0].domain
    );
}

/// #1789: an ancestor no pack publishes means the surface is not complete,
/// whatever the pack manifest claims, because what it inherits was never
/// described.
#[test]
fn ruby_gem_pack_unresolvable_ancestor_blocks_absence() {
    let fixture = GemFixture::new(&[("app.rb", "Legacy::Missing\n")]);
    fixture.activate(&[("fixture.ruby.widget", &widget_pack())], None);

    assert_states(&fixture.report("app.rb"), "no activated gem pack publishes");
}

/// A partial pack publishes true facts and omits unknown ones, so a miss
/// against it proves nothing.
#[test]
fn ruby_gem_pack_partial_surface_cannot_prove_absence() {
    let partial = compile(&pack_source(
        "fixture.ruby.draft",
        GEM,
        "partial",
        json!([ruby_type("Draft", "class", json!([]))]),
        json!([]),
    ));
    let fixture = GemFixture::new(&[("app.rb", "Draft::Missing\n")]);
    fixture.activate(&[("fixture.ruby.draft", &partial)], None);

    assert_states(&fixture.report("app.rb"), "partial surface");
}

/// Two gems can install the same constant name. Neither wins, and neither
/// licenses an error.
#[test]
fn ruby_gem_pack_same_name_in_two_gems_is_not_a_proof() {
    let other = compile(&pack_source(
        "fixture.ruby.widget-fork",
        FORK_GEM,
        "complete",
        json!([ruby_type_from(
            "sig/widget_fork.rbs",
            "Widget",
            "class",
            json!([])
        )]),
        json!([]),
    ));
    let fixture = GemFixture::new(&[("app.rb", "Widget::Missing\n")]);
    fixture.activate(
        &[
            ("fixture.ruby.widget", &widget_pack()),
            ("fixture.ruby.widget-fork", &other),
        ],
        None,
    );

    assert_states(
        &fixture.report("app.rb"),
        "more than one activated gem pack declares",
    );
}

/// A diagnostic and a definition must name the same gem declaration.
///
/// The pass resolves `Widget::Config` through the identity
/// `type_declaration_id(rubygems, "Widget::Config")`; navigation must land on
/// the symbol carrying that same id. Two lanes that agreed only by accident
/// would let a definition open a constant that a diagnostic then called absent.
#[test]
fn ruby_gem_pack_shares_one_identity_with_definition_lookup() {
    let fixture = GemFixture::new(&[("app.rb", "Widget::Config\n")]);
    fixture.activate(&[("fixture.ruby.widget", &widget_pack())], None);

    let report = fixture.report("app.rb");
    assert!(
        resolved_boundaries(&report).contains(&BoundaryStatus::ExternalIndexed),
        "the diagnostic lane resolves the constant through the pack: {report:#?}"
    );

    let overlay = fixture
        .analyzer
        .analyzer()
        .semantic_model_overlay()
        .expect("an activated overlay");
    let expected_id = ruby_type_id("Widget::Config");
    let by_identity = overlay.symbols_with_id(&expected_id);
    assert_eq!(
        1,
        by_identity.records.len(),
        "the pack publishes the constant under the minted identity"
    );

    let locations = get_symbol_locations(
        fixture.analyzer.analyzer(),
        SymbolLookupParams {
            symbols: vec!["Widget::Config".to_owned()],
        },
    );
    assert!(
        locations.not_found.is_empty(),
        "navigation must find the same constant: {:#?}",
        locations.not_found
    );
    assert_eq!(
        vec![expected_id],
        locations
            .model_locations
            .iter()
            .map(|symbol| symbol.id.clone())
            .collect::<Vec<_>>(),
        "navigation and the diagnostic lane must land on one declaration identity"
    );
}

/// A workspace file that reopens a gem class adds to the surface the pack
/// described, so the pack's completeness no longer settles the question.
#[test]
fn ruby_gem_pack_workspace_reopen_blocks_absence() {
    let fixture = GemFixture::new(&[(
        "app.rb",
        "class Widget\n  class Extra\n  end\nend\nWidget::Extra\nWidget::Missing\n",
    )]);
    fixture.activate(&[("fixture.ruby.widget", &widget_pack())], None);

    let report = fixture.report("app.rb");
    assert!(
        report.diagnostics().is_empty(),
        "a reopened gem class cannot prove a constant absent: {report:#?}"
    );
    assert!(
        resolved_boundaries(&report).contains(&BoundaryStatus::WorkspaceLocal),
        "the constant the workspace added resolves locally: {report:#?}"
    );
}

/// A `require` of a gem an activated pack covers closes the boundary the pass
/// used to bail on; a gem only the lockfile knows about is declared-unindexed.
#[test]
fn ruby_gem_pack_require_boundary_follows_retained_evidence() {
    let indexed = GemFixture::new(&[("app.rb", "require \"widget\"\nWidget::Config\n")]);
    indexed.activate(
        &[("fixture.ruby.widget", &widget_pack())],
        Some(declared_gem_evidence(GEM)),
    );
    let report = indexed.report("app.rb");
    assert!(
        report.diagnostics().is_empty(),
        "an indexed gem require must not blind the pass: {report:#?}"
    );
    assert!(
        resolved_boundaries(&report).contains(&BoundaryStatus::ExternalIndexed),
        "the required gem's constant resolves: {report:#?}"
    );

    // A gem no lockfile evidence mentions is a boundary nothing can see past.
    let unknown = GemFixture::new(&[("app.rb", "require \"other_gem\"\nWidget::Config\n")]);
    unknown.activate(
        &[("fixture.ruby.widget", &widget_pack())],
        Some(declared_gem_evidence(GEM)),
    );
    let report = unknown.report("app.rb");
    assert!(report.diagnostics().is_empty(), "{report:#?}");
    assert!(
        incomplete_reasons(&report).contains(
            &&SemanticDiagnosticIncompleteReason::MissingDependencyDiscovery {
                boundary: BoundaryStatus::ExternalUnknown
            }
        ),
        "an undeclared gem require is an unknown boundary: {report:#?}"
    );
}

/// A proof is only ever as good as the evidence behind it: activating a pack
/// that publishes the constant must retract the absence the earlier evidence
/// licensed.
#[test]
fn ruby_gem_pack_evidence_change_invalidates_an_earlier_proof() {
    let without_config = compile(&pack_source(
        "fixture.ruby.widget-earlier",
        GEM,
        "complete",
        json!([ruby_type("Widget", "class", json!([]))]),
        json!([]),
    ));
    let fixture = GemFixture::new(&[("app.rb", "Widget::Config\n")]);

    fixture.activate(&[("fixture.ruby.widget-earlier", &without_config)], None);
    let before = fixture.report("app.rb");
    assert_eq!(
        1,
        before.diagnostics().len(),
        "the first surface proved the constant absent: {before:#?}"
    );

    fixture.activate(&[("fixture.ruby.widget", &widget_pack())], None);
    let after = fixture.report("app.rb");
    assert!(
        after.diagnostics().is_empty(),
        "new evidence must retract the earlier proof: {after:#?}"
    );
    assert!(
        resolved_boundaries(&after).contains(&BoundaryStatus::ExternalIndexed),
        "{after:#?}"
    );
}
