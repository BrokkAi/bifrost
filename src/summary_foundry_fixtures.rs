//! The summary-foundry fixture runner (#1871 milestone 3).
//!
//! The generator in `brokk_bifrost_semantic_packs::summary_foundry::fixture`
//! turns one foundry entry into a fixture suite. This module executes that
//! suite through the production policy path: it materializes each case's
//! workspace on disk, compiles the generated pack with the production semantic
//! pack compiler, activates it through a catalog, and evaluates the generated
//! `require-model` taint policy with
//! [`evaluate_policy_inputs_with_analyzer_and_semantic_models`], the same entry
//! point a host uses.
//!
//! It lives in the facade because that is the only package that sees both
//! halves: `brokk-bifrost-semantic-packs` owns the foundry IR and the
//! generator, `brokk-bifrost-policy` owns the evaluator, and the workspace
//! dependency rules deliberately keep the packs crate below policy.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    CatalogCoordinate, CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelRuntimeLimits, SemanticPackCatalog,
    SessionPackSource, SessionPackSourceKind, SourceFormat, compile_source,
};
use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, FilesystemProject, Project};
use brokk_bifrost_policy::{
    PolicyEvaluationDate, PolicyEvaluationInput, PolicyEvaluationOptions, PolicyRunCompletion,
    PolicySemanticModelContext, PolicySourceIdentity,
    evaluate_policy_inputs_with_analyzer_and_semantic_models,
};
use brokk_bifrost_semantic_packs::summary_foundry::fixture::{
    FIXTURE_CONFIGURATION, FIXTURE_PACKAGE_NAME, FIXTURE_PACKAGE_VERSION, FIXTURE_TARGET,
    FixtureCase, FixtureLanguage, FixturePolarity, FixtureSuite,
};
use semver::Version;
use serde::Serialize;

/// The evaluation date every fixture run pins.
///
/// A fixture policy carries no temporal clause, so the date only has to be
/// fixed for two runs of the same suite to be comparable.
const FIXTURE_EVALUATION_DATE: (i32, u32, u32) = (2026, 1, 1);

/// What one executed case reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureCaseResult {
    pub case_id: String,
    pub polarity: FixturePolarity,
    pub expected_findings: usize,
    pub observed_findings: usize,
    /// The policy run's completion, rendered.
    pub completion: String,
    /// Every diagnostic the run or the pack compiler produced, complete.
    pub diagnostics: Vec<String>,
    /// Why the case failed, or `None` when it held.
    pub failure: Option<String>,
}

impl FixtureCaseResult {
    pub fn passed(&self) -> bool {
        self.failure.is_none()
    }
}

/// What one executed suite reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureRunReport {
    pub entry_id: String,
    pub target: String,
    pub cases: Vec<FixtureCaseResult>,
}

impl FixtureRunReport {
    /// Whether every case held. An entry ships only when this is true.
    pub fn passed(&self) -> bool {
        self.cases.iter().all(FixtureCaseResult::passed)
    }

    /// Every failure, complete, for the caller's report.
    pub fn failures(&self) -> Vec<&FixtureCaseResult> {
        self.cases
            .iter()
            .filter(|case| !case.passed())
            .collect::<Vec<_>>()
    }
}

/// A failure of the harness itself, never a verdict about an entry.
#[derive(Debug)]
pub enum FixtureRunError {
    Io { path: PathBuf, error: io::Error },
    Workspace { detail: String },
    Evaluation { detail: String },
}

impl std::fmt::Display for FixtureRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, error } => {
                write!(formatter, "cannot write {}: {error}", path.display())
            }
            Self::Workspace { detail } => {
                write!(formatter, "cannot build a fixture workspace: {detail}")
            }
            Self::Evaluation { detail } => {
                write!(formatter, "policy evaluation failed: {detail}")
            }
        }
    }
}

impl std::error::Error for FixtureRunError {}

/// Execute every case of one suite beneath `root`.
///
/// Each case owns one directory named after it, so a failed run leaves the
/// exact workspace, policy, and pack that produced it on disk.
pub fn run_fixture_suite(
    suite: &FixtureSuite,
    root: &Path,
    language: &dyn FixtureLanguage,
) -> Result<FixtureRunReport, FixtureRunError> {
    let mut cases = Vec::with_capacity(suite.cases.len());
    for case in &suite.cases {
        cases.push(run_case(case, &root.join(&case.id), language)?);
    }
    Ok(FixtureRunReport {
        entry_id: suite.entry_id.clone(),
        target: suite.target.clone(),
        cases,
    })
}

fn run_case(
    case: &FixtureCase,
    root: &Path,
    language: &dyn FixtureLanguage,
) -> Result<FixtureCaseResult, FixtureRunError> {
    materialize(case, root)?;
    let catalog =
        SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).map_err(|error| {
            FixtureRunError::Workspace {
                detail: error.to_string(),
            }
        })?;
    if let Some(source) = &case.pack_source {
        match compile_source(
            SourceFormat::Json,
            source.as_bytes(),
            &CompilerOptions::default(),
        ) {
            Ok(compiled) => {
                catalog
                    .register_session_pack(
                        &compiled,
                        &SessionPackSource {
                            kind: SessionPackSourceKind::Embedded,
                            source_id: format!("bifrost:summary-foundry/{}", case.id),
                        },
                    )
                    .map_err(|error| FixtureRunError::Workspace {
                        detail: error.to_string(),
                    })?;
            }
            // The pack compiler is the first proof gate. An entry it rejects
            // never reaches a workspace, and the rejection is the verdict.
            Err(diagnostics) => {
                return Ok(FixtureCaseResult {
                    case_id: case.id.clone(),
                    polarity: case.polarity,
                    expected_findings: case.expected_findings,
                    observed_findings: 0,
                    completion: "not_run".to_owned(),
                    diagnostics: diagnostics
                        .iter()
                        .map(|diagnostic| {
                            format!(
                                "{:?} {} {}: {}",
                                diagnostic.severity,
                                diagnostic.code,
                                diagnostic.path,
                                diagnostic.message
                            )
                        })
                        .collect(),
                    failure: Some(
                        "the production pack compiler rejected the entry's authored summary"
                            .to_owned(),
                    ),
                });
            }
        }
    }

    let project = FilesystemProject::new(root).map_err(|error| FixtureRunError::Io {
        path: root.to_path_buf(),
        error,
    })?;
    let project: Arc<dyn Project> = Arc::new(project);
    let workspace = brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer::build_ephemeral(
        project,
        AnalyzerConfig::default(),
    )
    .map_err(|error| FixtureRunError::Workspace {
        detail: error.to_string(),
    })?;

    let policy_source = case
        .files
        .iter()
        .find(|file| file.path == case.policy_path)
        .map(|file| file.contents.clone())
        .expect("a generated case carries its own policy file");
    let inputs = [PolicyEvaluationInput::embedded(
        PolicySourceIdentity::new(format!("bifrost:summary-foundry/{}", case.policy_path)),
        &policy_source,
    )];
    let (year, month, day) = FIXTURE_EVALUATION_DATE;
    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(year, month, day).expect("a fixed evaluation date"),
    );
    let request = activation_request(language);
    let outcome = evaluate_policy_inputs_with_analyzer_and_semantic_models(
        root,
        &inputs,
        &workspace,
        &options,
        PolicySemanticModelContext {
            catalog: &catalog,
            request: &request,
            persistence: None,
        },
        None,
    )
    .map_err(|error| FixtureRunError::Evaluation {
        detail: error.to_string(),
    })?;

    let [run] = outcome.report().runs() else {
        return Err(FixtureRunError::Evaluation {
            detail: format!(
                "expected exactly one policy run, got {:?}",
                outcome.report().runs()
            ),
        });
    };
    let diagnostics = run
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.message().to_owned())
        .chain(
            outcome
                .report()
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.message().to_owned()),
        )
        .collect::<Vec<_>>();
    let observed_findings = run.findings().len();
    let completion = format!("{:?}", run.completion());
    let failure = verdict(case, run.completion(), observed_findings, &diagnostics);
    Ok(FixtureCaseResult {
        case_id: case.id.clone(),
        polarity: case.polarity,
        expected_findings: case.expected_findings,
        observed_findings,
        completion,
        diagnostics,
        failure,
    })
}

/// The verdict for one executed case.
///
/// A positive case must produce exactly one finding per claimed transfer: fewer
/// means the claim is not executable, more means the fixture routed something
/// it did not intend. The fail-before control must produce none *and* must not
/// report a clean run: the entry's absence has to surface as incompleteness,
/// because a clean negative without the model would mean the finding never
/// depended on the entry. A negative case must produce none, which is a claim
/// only a `complete` entry is allowed to make.
///
/// One completion invariant holds for every case with the pack active (#1916): a
/// summary-backed run must never report `Complete`, because a summary is an
/// authored assertion about a body Bifrost never analyzed. `Complete` stays
/// reserved for proof from analyzed code; the summary-backed clean conclusion is
/// the distinct `ProvenBySummary` tier. The fail-before control, whose pack is
/// absent, must degrade all the way to `Inconclusive`. The tier itself is proven
/// end to end -- earned by an authored-complete summary, withheld from a partial
/// one -- by `value_flow_client::authored_complete_external_summary_is_proven_by_summary_not_complete`
/// and its partial sibling; these foundry fixtures do not reach it because their
/// native source, sink, and dispatch call sites are open boundaries a target
/// summary does not close, which is orthogonal engine work (#1917 and dispatch
/// resolution), not a completion-semantics question.
fn verdict(
    case: &FixtureCase,
    completion: &PolicyRunCompletion,
    observed: usize,
    diagnostics: &[String],
) -> Option<String> {
    if observed != case.expected_findings {
        return Some(format!(
            "expected {} finding(s), observed {observed}; diagnostics: {diagnostics:?}",
            case.expected_findings
        ));
    }
    if matches!(completion, PolicyRunCompletion::Complete) {
        return Some(
            "a summary-backed run reported Complete, which launders authored trust into the word \
             reserved for proof from analyzed code (#1916)"
                .to_owned(),
        );
    }
    if case.polarity == FixturePolarity::FailBefore
        && !matches!(completion, PolicyRunCompletion::Inconclusive { .. })
    {
        return Some(format!(
            "the fail-before control did not surface the entry's absence as incompleteness; it \
             reported {completion:?} instead of Inconclusive"
        ));
    }
    if matches!(completion, PolicyRunCompletion::Failed { .. }) {
        return Some(format!(
            "the policy run failed: {completion:?}; diagnostics: {diagnostics:?}"
        ));
    }
    None
}

fn materialize(case: &FixtureCase, root: &Path) -> Result<(), FixtureRunError> {
    fs::create_dir_all(root).map_err(|error| FixtureRunError::Io {
        path: root.to_path_buf(),
        error,
    })?;
    for file in &case.files {
        let path = root.join(&file.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| FixtureRunError::Io {
                path: parent.to_path_buf(),
                error,
            })?;
        }
        fs::write(&path, &file.contents).map_err(|error| FixtureRunError::Io {
            path: path.clone(),
            error,
        })?;
    }
    if let Some(source) = &case.pack_source {
        let path = root.join("pack.json");
        fs::write(&path, source).map_err(|error| FixtureRunError::Io {
            path: path.clone(),
            error,
        })?;
    }
    Ok(())
}

/// The activation claim a fixture run makes.
///
/// It mirrors the coordinate the generated pack's selector declares, so the two
/// cannot drift into an activation that silently selects nothing.
fn activation_request(language: &dyn FixtureLanguage) -> SemanticModelActivationRequest {
    SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION"))
            .expect("the package version is semver"),
        evidence: vec![SemanticModelActivationEvidence {
            language: language.language().to_owned(),
            ecosystem: language.ecosystem().to_owned(),
            package: Some(CatalogCoordinate {
                name: FIXTURE_PACKAGE_NAME.to_owned(),
                version: Some(
                    Version::parse(FIXTURE_PACKAGE_VERSION)
                        .expect("the fixture package version is semver"),
                ),
            }),
            module: None,
            toolchain: None,
            target: Some(FIXTURE_TARGET.to_owned()),
            configuration: Some(FIXTURE_CONFIGURATION.to_owned()),
            artifact_sha256: None,
        }],
        controls: Vec::new(),
        limits: SemanticModelRuntimeLimits::default(),
    }
}
