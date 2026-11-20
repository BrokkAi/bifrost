//! OWASP Benchmark taint bakeoff scorer.
//!
//! This module scores Bifrost's taint analysis against the
//! labeled OWASP Benchmark corpora. Each edition (`BenchmarkSuite`) is a
//! table of labels, sources and per-category sinks; BenchmarkJava is the one
//! wired today (`BENCHMARK_JAVA`). It lives in the facade for the same
//! reason `summary_foundry_demand` does: it needs both the semantic-pack /
//! semantic-model machinery from `brokk-bifrost-analysis` and the policy
//! evaluator from `brokk-bifrost-policy`, and the workspace dependency rules
//! keep the packs crate below policy. The facade is the only package that sees
//! both.
//!
//! It is split into two halves. The first is a pure scoring core: given a set
//! of labeled cases and, per case, whether Bifrost produced a finding and what
//! completion it reached, it computes per-category and overall confusion
//! matrices two ways -- a naive way that treats an abstention as a clean
//! negative, and an honest way that pulls abstentions into their own bucket and
//! excludes them from the rates. The gap between the two is the "no false
//! greens" story, quantified. That core is proven by hermetic unit tests over a
//! fabricated label+finding set; it never runs an analyzer.
//!
//! The second half is the live runner: it parses the suite's expected-results
//! file, builds one workspace analyzer over the Benchmark source (with the
//! built classpath fed in so types resolve), activates the Java sanitizer
//! packs plus the pinned ESAPI pack and the `bifrost.jdk` dependency pack,
//! runs one taint policy per scored category, under the chosen unmodeled-call
//! behavior, through the production evaluator, maps each finding and each
//! per-root completion back to its case, and feeds the pure core. Activation
//! is still BenchmarkJava's; a second suite brings its own. The whole run is a
//! measurement performed once; its conclusions go on the governing issue.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use semver::Version;
use serde::Serialize;

use brokk_bifrost_analysis::analyzer::semantic::SemanticLocator;
use brokk_bifrost_analysis::analyzer::semantic_model::csmi;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    CatalogCoordinate, CatalogOpenMode, CatalogOptions, CompiledSemanticModelPack, CompilerOptions,
    DependencyPackLimits, DependencyPackPreparationOutcome, SemanticModelActivationControl,
    SemanticModelActivationEvidence, SemanticModelActivationRequest, SemanticModelControlAction,
    SemanticModelControlScope, SemanticModelPackSelector, SemanticModelRuntimeLimits,
    SemanticModelRuntimeOutcome, SemanticPackCatalog, SessionPackSource, SessionPackSourceKind,
    SourceFormat, compile_source,
};
use brokk_bifrost_analysis::analyzer::{
    PythonDeclaredConfigInput, PythonDeclaredConfigInputRole, PythonDeclaredEditableInstallMode,
    PythonDeclaredEntryMode, PythonDeclaredEntryPoint, PythonDeclaredEnvironmentConfig,
    PythonDeclaredEnvironmentMode, PythonDeclaredFinderMode, PythonDeclaredImportPathMode,
    PythonDeclaredInterpreter, PythonDeclaredIsolationMode, PythonDeclaredLaunchSemantics,
    PythonDeclaredNativeExtensionMode, PythonDeclaredRootRole, PythonDeclaredRootSlot,
    PythonDeclaredSiteStartupMode, PythonRuntimeArtifactConfig, PythonRuntimeEnvironmentConfig,
};
use brokk_bifrost_analysis::retention_budget::RetentionBudget;
use brokk_bifrost_analysis::{
    AnalyzerConfig, CancellationToken, DependencyPackEcosystem, DependencyPackWorkspaceContext,
    FilesystemProject, JvmDependencyDiscoveryMode, JvmExternalArtifact, Project, WorkspaceAnalyzer,
};
use brokk_bifrost_flow::dataflow::{
    SemanticInputStatus, SummaryBoundaryKind, UnmodeledCallBehavior,
};
use brokk_bifrost_policy::{
    PolicyEvaluationDate, PolicyEvaluationInput, PolicyEvaluationOptions, PolicySourceIdentity,
    evaluate_policy_inputs_with_analyzer,
};
use brokk_bifrost_python_analysis::analyzer::python_runtime_artifact::{
    SUPPORTED_PYTHON_DECLARED_ENVIRONMENT_PRODUCER_VERSION,
    SUPPORTED_PYTHON_DECLARED_FILESYSTEM_RESOLVER_VERSION,
    python_declared_environment_project_config,
};
use brokk_bifrost_rql::structural::CodeQueryTaintFinding;

// ===========================================================================
// Pure scoring core
// ===========================================================================

/// The injection categories Bifrost's taint policy addresses, across every
/// edition. These are the OWASP Benchmark categories that are taint-flow
/// problems (a source reaches a sink); each suite scores the subset it has.
/// The Benchmarks' other categories (crypto, hash, weakrand, securecookie,
/// trustbound) are not source-to-sink taint problems and are deliberately out
/// of scope for this bakeoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionCategory {
    Sqli,
    Cmdi,
    Ldapi,
    Pathtraver,
    Xpathi,
    Xss,
    Codeinj,
    Deserialization,
    Redirect,
}

impl InjectionCategory {
    /// The Benchmark's own category token, as it appears in the suite's
    /// expected-results file.
    pub const fn label(self) -> &'static str {
        match self {
            InjectionCategory::Sqli => "sqli",
            InjectionCategory::Cmdi => "cmdi",
            InjectionCategory::Ldapi => "ldapi",
            InjectionCategory::Pathtraver => "pathtraver",
            InjectionCategory::Xpathi => "xpathi",
            InjectionCategory::Xss => "xss",
            InjectionCategory::Codeinj => "codeinj",
            InjectionCategory::Deserialization => "deserialization",
            InjectionCategory::Redirect => "redirect",
        }
    }

    /// The taint label minted by this category's source endpoints and accepted
    /// by its sink endpoints. These labels are the Java sanitizer packs'
    /// sink-context vocabulary, rather than the Benchmark category tokens. No
    /// sanitizer pack covers the Python-only categories yet, so their labels
    /// follow the same naming: the kind of text the sink interprets.
    pub const fn hazard_label(self) -> &'static str {
        match self {
            InjectionCategory::Sqli => "sql",
            InjectionCategory::Cmdi => "shell",
            InjectionCategory::Ldapi => "ldap",
            InjectionCategory::Pathtraver => "path",
            InjectionCategory::Xpathi => "xpath",
            InjectionCategory::Xss => "html",
            InjectionCategory::Codeinj => "code",
            InjectionCategory::Deserialization => "serialized",
            InjectionCategory::Redirect => "url",
        }
    }
}

/// The completion Bifrost reached for one case's flow analysis, projected onto
/// the buckets that matter for honest scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseCompletion {
    /// Proven exhaustively from analyzed code.
    Complete,
    /// Proven precisely, but resting on authored-complete external procedure
    /// summaries rather than analyzed code (#1916).
    ProvenBySummary,
    /// The analysis abstained: an unmodeled boundary on the flow prevented a
    /// reliable verdict.
    Inconclusive,
    /// No taint root formed for the case's file, so no verdict was even
    /// attempted. Treated exactly like `Inconclusive` for scoring (an
    /// abstention), but recorded distinctly because the cause differs.
    NotAnalyzed,
}

impl CaseCompletion {
    /// Whether this completion is reliable enough for a negative (no-finding)
    /// case to count as an affirmative clean pass rather than an abstention.
    const fn is_reliable(self) -> bool {
        matches!(
            self,
            CaseCompletion::Complete | CaseCompletion::ProvenBySummary
        )
    }
}

/// One case's observed outcome: its label plus what Bifrost did with it.
#[derive(Debug, Clone)]
pub struct CaseObservation {
    pub name: String,
    pub category: InjectionCategory,
    /// True when the Benchmark labels this case a real vulnerability.
    pub is_real: bool,
    /// True when Bifrost produced at least one taint finding of this case's
    /// category on this case's file.
    pub flagged: bool,
    /// The completion Bifrost reached for the case's file.
    pub completion: CaseCompletion,
}

/// The three mutually exclusive things Bifrost can do with a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseOutcome {
    /// Bifrost reported a finding (predicted vulnerable).
    Flagged,
    /// No finding, and the analysis reliably concluded (predicted safe).
    Cleared,
    /// No finding, but the analysis abstained (no verdict).
    Abstained,
}

impl CaseObservation {
    fn outcome(&self) -> CaseOutcome {
        if self.flagged {
            CaseOutcome::Flagged
        } else if self.completion.is_reliable() {
            CaseOutcome::Cleared
        } else {
            CaseOutcome::Abstained
        }
    }
}

/// A 2x2 confusion matrix plus the rates derived from it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Confusion {
    pub tp: u32,
    pub fp: u32,
    #[serde(rename = "fn")]
    pub false_negative: u32,
    pub tn: u32,
}

impl Confusion {
    fn positives(&self) -> u32 {
        self.tp + self.false_negative
    }

    fn negatives(&self) -> u32 {
        self.fp + self.tn
    }

    /// True-positive rate (recall / sensitivity). None when there are no reals.
    fn tpr(&self) -> Option<f64> {
        Self::rate(self.tp, self.positives())
    }

    /// False-positive rate (1 - specificity). None when there are no fakes.
    fn fpr(&self) -> Option<f64> {
        Self::rate(self.fp, self.negatives())
    }

    fn rate(numerator: u32, denominator: u32) -> Option<f64> {
        (denominator > 0).then(|| f64::from(numerator) / f64::from(denominator))
    }

    /// Youden's J = TPR - FPR. None when either rate is undefined.
    fn youden(&self) -> Option<f64> {
        Some(self.tpr()? - self.fpr()?)
    }

    fn metrics(&self) -> Metrics {
        Metrics {
            tpr: round4(self.tpr()),
            fpr: round4(self.fpr()),
            youden: round4(self.youden()),
        }
    }

    fn add(&mut self, other: Confusion) {
        self.tp += other.tp;
        self.fp += other.fp;
        self.false_negative += other.false_negative;
        self.tn += other.tn;
    }
}

/// The three rates, rounded to four decimals; `null` when undefined.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Metrics {
    pub tpr: Option<f64>,
    pub fpr: Option<f64>,
    pub youden: Option<f64>,
}

fn round4(value: Option<f64>) -> Option<f64> {
    value.map(|v| (v * 10_000.0).round() / 10_000.0)
}

/// How many cases landed in each completion bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CompletionProfile {
    pub complete: u32,
    pub proven_by_summary: u32,
    pub inconclusive: u32,
    pub not_analyzed: u32,
}

impl CompletionProfile {
    fn record(&mut self, completion: CaseCompletion) {
        match completion {
            CaseCompletion::Complete => self.complete += 1,
            CaseCompletion::ProvenBySummary => self.proven_by_summary += 1,
            CaseCompletion::Inconclusive => self.inconclusive += 1,
            CaseCompletion::NotAnalyzed => self.not_analyzed += 1,
        }
    }

    fn add(&mut self, other: CompletionProfile) {
        self.complete += other.complete;
        self.proven_by_summary += other.proven_by_summary;
        self.inconclusive += other.inconclusive;
        self.not_analyzed += other.not_analyzed;
    }
}

/// The full score for one category (or, aggregated, for the whole subset).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CategoryScore {
    pub category: String,
    pub total: u32,
    pub real: u32,
    pub fake: u32,
    /// Confusion where an abstention counts as a (predicted-safe) negative --
    /// the way a naive bakeoff scores it.
    pub naive: Confusion,
    pub naive_metrics: Metrics,
    /// Confusion over only the cases Bifrost reliably decided (flagged or
    /// cleared); abstentions are excluded.
    pub honest: Confusion,
    pub honest_metrics: Metrics,
    pub completion: CompletionProfile,
    pub real_flagged: u32,
    pub real_cleared: u32,
    pub real_abstained: u32,
    pub fake_flagged: u32,
    pub fake_cleared: u32,
    pub fake_abstained: u32,
    /// Real vulnerabilities Bifrost affirmatively cleared as safe (a false
    /// green). The headline honesty metric: the pitch is that this stays at or
    /// near zero.
    pub false_greens: u32,
}

/// The whole scoreboard: per-category plus the aggregate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Scoreboard {
    pub per_category: Vec<CategoryScore>,
    pub overall: CategoryScore,
}

/// Score a set of observations into per-category matrices, in the suite's
/// category order, plus an aggregate.
pub fn score(suite: &BenchmarkSuite, observations: &[CaseObservation]) -> Scoreboard {
    let per_category: Vec<CategoryScore> = suite
        .categories()
        .map(|category| {
            let cases: Vec<&CaseObservation> = observations
                .iter()
                .filter(|obs| obs.category == category)
                .collect();
            score_category(category.label().to_owned(), &cases)
        })
        .collect();
    let overall = aggregate(&per_category);
    Scoreboard {
        per_category,
        overall,
    }
}

fn score_category(category: String, cases: &[&CaseObservation]) -> CategoryScore {
    let mut naive = Confusion::default();
    let mut honest = Confusion::default();
    let mut completion = CompletionProfile::default();
    let (mut real, mut fake) = (0u32, 0u32);
    let (mut real_flagged, mut real_cleared, mut real_abstained) = (0u32, 0u32, 0u32);
    let (mut fake_flagged, mut fake_cleared, mut fake_abstained) = (0u32, 0u32, 0u32);

    for case in cases {
        completion.record(case.completion);
        let outcome = case.outcome();
        if case.is_real {
            real += 1;
        } else {
            fake += 1;
        }

        // Naive: a flagged case is positive; everything else is negative,
        // abstentions included.
        match (case.is_real, outcome) {
            (true, CaseOutcome::Flagged) => naive.tp += 1,
            (true, _) => naive.false_negative += 1,
            (false, CaseOutcome::Flagged) => naive.fp += 1,
            (false, _) => naive.tn += 1,
        }

        // Honest: only flagged or cleared cases enter the matrix. Abstentions
        // are held out.
        match (case.is_real, outcome) {
            (true, CaseOutcome::Flagged) => honest.tp += 1,
            (true, CaseOutcome::Cleared) => honest.false_negative += 1,
            (false, CaseOutcome::Flagged) => honest.fp += 1,
            (false, CaseOutcome::Cleared) => honest.tn += 1,
            (_, CaseOutcome::Abstained) => {}
        }

        match (case.is_real, outcome) {
            (true, CaseOutcome::Flagged) => real_flagged += 1,
            (true, CaseOutcome::Cleared) => real_cleared += 1,
            (true, CaseOutcome::Abstained) => real_abstained += 1,
            (false, CaseOutcome::Flagged) => fake_flagged += 1,
            (false, CaseOutcome::Cleared) => fake_cleared += 1,
            (false, CaseOutcome::Abstained) => fake_abstained += 1,
        }
    }

    CategoryScore {
        category,
        total: real + fake,
        real,
        fake,
        naive_metrics: naive.metrics(),
        naive,
        honest_metrics: honest.metrics(),
        honest,
        completion,
        real_flagged,
        real_cleared,
        real_abstained,
        fake_flagged,
        fake_cleared,
        fake_abstained,
        false_greens: real_cleared,
    }
}

fn aggregate(per_category: &[CategoryScore]) -> CategoryScore {
    let mut overall = CategoryScore {
        category: "overall".to_owned(),
        total: 0,
        real: 0,
        fake: 0,
        naive: Confusion::default(),
        naive_metrics: Metrics {
            tpr: None,
            fpr: None,
            youden: None,
        },
        honest: Confusion::default(),
        honest_metrics: Metrics {
            tpr: None,
            fpr: None,
            youden: None,
        },
        completion: CompletionProfile::default(),
        real_flagged: 0,
        real_cleared: 0,
        real_abstained: 0,
        fake_flagged: 0,
        fake_cleared: 0,
        fake_abstained: 0,
        false_greens: 0,
    };
    for score in per_category {
        overall.total += score.total;
        overall.real += score.real;
        overall.fake += score.fake;
        overall.naive.add(score.naive);
        overall.honest.add(score.honest);
        overall.completion.add(score.completion);
        overall.real_flagged += score.real_flagged;
        overall.real_cleared += score.real_cleared;
        overall.real_abstained += score.real_abstained;
        overall.fake_flagged += score.fake_flagged;
        overall.fake_cleared += score.fake_cleared;
        overall.fake_abstained += score.fake_abstained;
        overall.false_greens += score.false_greens;
    }
    overall.naive_metrics = overall.naive.metrics();
    overall.honest_metrics = overall.honest.metrics();
    overall
}

// ===========================================================================
// Case labels
// ===========================================================================

/// One row of the suite's expected-results file, narrowed to the categories
/// the suite scores.
#[derive(Debug, Clone)]
pub struct CaseLabel {
    pub name: String,
    pub category: InjectionCategory,
    pub is_real: bool,
}

/// The parse of the whole label file: the taint-subset rows plus a count of the
/// non-taint rows that were deliberately skipped, so the artifact can state the
/// scope honestly.
#[derive(Debug, Clone)]
pub struct LabelSet {
    pub cases: Vec<CaseLabel>,
    pub skipped_non_taint: BTreeMap<String, u32>,
}

/// Parse a suite's expected-results file. Every Benchmark edition uses the
/// same format: one header line beginning with `#`, then rows of
/// `name,category,real,cwe`. A row whose category the suite does not score is
/// counted in `skipped_non_taint`.
pub fn parse_expected_results(suite: &BenchmarkSuite, csv: &str) -> Result<LabelSet, String> {
    let mut cases = Vec::new();
    let mut skipped_non_taint: BTreeMap<String, u32> = BTreeMap::new();
    for (line_no, line) in csv.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 3 {
            return Err(format!(
                "expectedresults line {} has too few fields: {line:?}",
                line_no + 1
            ));
        }
        let name = fields[0].trim().to_owned();
        let category_token = fields[1].trim();
        let is_real = match fields[2].trim() {
            "true" => true,
            "false" => false,
            other => {
                return Err(format!(
                    "expectedresults line {} has an unexpected real flag {other:?}",
                    line_no + 1
                ));
            }
        };
        match suite
            .categories()
            .find(|category| category.label() == category_token)
        {
            Some(category) => cases.push(CaseLabel {
                name,
                category,
                is_real,
            }),
            None => {
                *skipped_non_taint
                    .entry(category_token.to_owned())
                    .or_default() += 1;
            }
        }
    }
    if cases.is_empty() {
        return Err("expectedresults contained no taint-subset cases".to_owned());
    }
    Ok(LabelSet {
        cases,
        skipped_non_taint,
    })
}

/// Extract `BenchmarkTestNNNNN` from a workspace-relative test-case path, using the
/// path's own file stem rather than string scanning. Returns `None` for a path
/// that is not a Benchmark test file.
fn case_name_from_path(path: &str) -> Option<String> {
    let stem = Path::new(path).file_stem()?.to_str()?;
    stem.starts_with("BenchmarkTest").then(|| stem.to_owned())
}

// ===========================================================================
// Benchmark suites and their taint policies
// ===========================================================================

/// One OWASP Benchmark edition, described as data: where its labels live,
/// which RQL language its endpoints select in, its attacker-controlled
/// sources, and the categories it scores with each category's sinks. The
/// shared code (label parsing, policy rendering, evaluation, case
/// attribution, scoring) reads only this description, so a second edition is
/// a second table rather than a second harness.
pub struct BenchmarkSuite {
    /// The edition's name, as the scoreboard prints it.
    pub name: &'static str,
    /// The upstream repository the checkout is cloned from.
    pub repo: &'static str,
    /// The edition's version, as its label file names it.
    pub version: &'static str,
    /// The label file, relative to the checkout root.
    pub expected_results_file: &'static str,
    /// How the rendered policies name themselves: the id prefix, the title
    /// and the classification taxonomy.
    pub(crate) policy_naming: PolicyNaming,
    /// The RQL `language` tokens the policies select endpoints in. Every
    /// source and sink is rendered once per language.
    pub(crate) languages: &'static [&'static str],
    /// The attacker-controlled sources, shared by every category.
    pub(crate) sources: &'static [Source],
    /// What the source table leaves out. These gaps apply to every category.
    pub(crate) source_gaps: &'static [CoverageGap],
    /// The scored categories, in a fixed order so the artifact is byte-stable
    /// across runs.
    pub(crate) categories: &'static [CategorySpec],
}

impl BenchmarkSuite {
    /// The scored categories, in the suite's order.
    pub fn categories(&self) -> impl Iterator<Item = InjectionCategory> + '_ {
        self.categories.iter().map(|spec| spec.category)
    }

    fn spec(&self, category: InjectionCategory) -> &'static CategorySpec {
        self.categories
            .iter()
            .find(|spec| spec.category == category)
            .unwrap_or_else(|| panic!("{} does not score {category:?}", self.name))
    }

    fn sinks(&self, category: InjectionCategory) -> &'static [Sink] {
        self.spec(category).sinks
    }

    /// Every coverage gap a category's policy carries: the source table's,
    /// then the category's own.
    fn coverage_gaps(
        &self,
        category: InjectionCategory,
    ) -> impl Iterator<Item = &'static CoverageGap> + use<> {
        self.source_gaps
            .iter()
            .chain(self.spec(category).coverage_gaps)
    }
}

/// The names a suite's rendered policies carry.
pub(crate) struct PolicyNaming {
    pub(crate) id_prefix: &'static str,
    pub(crate) title: &'static str,
    pub(crate) taxonomy: &'static str,
}

/// The OWASP editions' policy names.
const OWASP_POLICY_NAMING: PolicyNaming = PolicyNaming {
    id_prefix: "bifrost.owasp-benchmark",
    title: "OWASP Benchmark",
    taxonomy: "OWASP",
};

/// One scored category and the sinks its policy selects.
pub(crate) struct CategorySpec {
    pub(crate) category: InjectionCategory,
    pub(crate) sinks: &'static [Sink],
    /// What the sink table leaves out of the category.
    pub(crate) coverage_gaps: &'static [CoverageGap],
}

/// Operations an endpoint table leaves out on purpose. A category whose
/// policy carries any gap declares `:coverage (proven-subset ...)` with the
/// gaps' reasons, and a case of that category without a finding counts as
/// cleared only when every gap selects its operations structurally and
/// none of them occurs in the case's file. A gap without a selector proves
/// nothing about any file, so no case of its categories can be cleared.
pub(crate) struct CoverageGap {
    pub(crate) reason: &'static str,
    /// A CodeQuery `match` object, as JSON, that selects the left-out
    /// operations.
    pub(crate) uncovered: Option<&'static str>,
}

/// One attacker-controlled source.
pub(crate) enum Source {
    /// Matched by callee name. The name selector binds structurally and needs
    /// no type resolution. The servlet API's getters have distinctive names,
    /// so a name is enough for Java.
    Name { callee: &'static str },
    /// A method call whose target resolves exactly to a modeled callable on an
    /// exact receiver type. Flask's request reads are `get` calls on
    /// `request.args` and `request.form`, and a callee name of `get` would
    /// select every dictionary read in the program, so a Python source names
    /// the Werkzeug member and its receiver class instead. Binding needs the
    /// Flask and Werkzeug models active.
    ResolvedMethod {
        callee: &'static str,
        callable: &'static str,
        receiver_type: &'static str,
    },
    /// Every function parameter. A library's attacker input is an argument
    /// of the function it exports, and a server's request object reaches its
    /// handler as a parameter too, so neither needs a modeled call.
    Parameter,
}

/// One sink endpoint: the callee name to match and how to select its operand.
pub(crate) struct Sink {
    callee: &'static str,
    selector: SinkSelector,
}

impl Sink {
    pub(crate) const fn name(callee: &'static str, argument: u32) -> Self {
        Sink {
            callee,
            selector: SinkSelector::Name { argument },
        }
    }

    const fn qualified(callee: &'static str, callable: &'static str, formal: SinkFormal) -> Self {
        Sink {
            callee,
            selector: SinkSelector::QualifiedCallBinding { callable, formal },
        }
    }
}

/// How a sink identifies the call whose operand it observes.
///
/// Most Benchmark endpoints are intentionally broad name selectors. The
/// PrintWriter writer surface is different: `println`, `print`, `write` and
/// `append` share their names with `StringBuilder`, `Writer` and other
/// receivers, and the formatting overloads move their payload formals when a
/// Locale is present. Those endpoints name the qualified callable instead.
/// The policy loader resolves the qualified locator against the activated
/// `bifrost.jdk` bundle to the whole overload family, and the exact
/// call-binding relation maps the selected formal back to each written
/// caller-side actual. The generated bundle names its members by digest, so
/// the qualified name is the only stable way to spell them.
enum SinkSelector {
    Name {
        argument: u32,
    },
    QualifiedCallBinding {
        callable: &'static str,
        formal: SinkFormal,
    },
}

/// The payload formal of a qualified sink. A name selects it in every overload
/// that declares it; the formatting overloads need one, because Locale shifts
/// the payload's position. An index selects the same position in every
/// overload; the print, println and write families need one, because the
/// payload's formal name differs by overload (`s`, `obj`, `buf`, `x`), and a
/// name selector rejecting every overload it witnesses reports the discovery
/// incomplete.
#[derive(Clone, Copy)]
enum SinkFormal {
    Name(&'static str),
    Index(u32),
}

/// OWASP BenchmarkJava 1.2.
pub static BENCHMARK_JAVA: BenchmarkSuite = BenchmarkSuite {
    name: "BenchmarkJava",
    repo: "https://github.com/OWASP-Benchmark/BenchmarkJava",
    version: "1.2",
    expected_results_file: "expectedresults-1.2.csv",
    policy_naming: OWASP_POLICY_NAMING,
    languages: &["java"],
    // The servlet-request and cookie APIs the Benchmark actually reads from.
    sources: &[
        Source::Name {
            callee: "getParameter",
        },
        Source::Name {
            callee: "getParameterValues",
        },
        Source::Name {
            callee: "getParameterMap",
        },
        Source::Name {
            callee: "getParameterNames",
        },
        Source::Name {
            callee: "getHeader",
        },
        Source::Name {
            callee: "getHeaders",
        },
        Source::Name {
            callee: "getHeaderNames",
        },
        Source::Name {
            callee: "getQueryString",
        },
        Source::Name {
            callee: "getRequestURI",
        },
        Source::Name {
            callee: "getRequestURL",
        },
        Source::Name {
            callee: "getPathInfo",
        },
        Source::Name {
            callee: "getServletPath",
        },
        Source::Name {
            callee: "getCookies",
        },
        Source::Name { callee: "getValue" },
        Source::Name { callee: "getenv" },
    ],
    // The Benchmark's other categories (crypto, hash, weakrand, securecookie,
    // trustbound) are not source-to-sink taint problems and are deliberately
    // out of scope.
    source_gaps: &[],
    categories: &[
        // The JDBC lane (`prepareStatement` .. `addBatch`) plus the Spring
        // `JdbcTemplate` lane. The Benchmark routes 156 of its `sqli` cases
        // through `DatabaseHelper.JDBCtemplate`, whose query family takes the
        // SQL text as positional argument 0 in every overload the corpus uses:
        // `queryForObject(sql, Class)` / `queryForObject(sql, Object[], Class)`,
        // `query(sql, RowMapper)`, `queryForList(sql)`, `queryForMap(sql)`,
        // `queryForRowSet(sql)` and `batchUpdate(sql)`. `JdbcTemplate.execute`
        // is already covered by the JDBC `execute` entry above.
        CategorySpec {
            category: InjectionCategory::Sqli,
            coverage_gaps: &[],
            sinks: &[
                Sink::name("prepareStatement", 0),
                Sink::name("prepareCall", 0),
                Sink::name("execute", 0),
                Sink::name("executeQuery", 0),
                Sink::name("executeUpdate", 0),
                Sink::name("executeLargeUpdate", 0),
                Sink::name("addBatch", 0),
                Sink::name("query", 0),
                Sink::name("queryForObject", 0),
                Sink::name("queryForList", 0),
                Sink::name("queryForMap", 0),
                Sink::name("queryForRowSet", 0),
                Sink::name("batchUpdate", 0),
            ],
        },
        // `Runtime.exec(cmd, envp, ...)`: the environment array is a second
        // injection point (`PATH`, `LD_PRELOAD`), and the Benchmark labels
        // flows into it as command injection.
        CategorySpec {
            category: InjectionCategory::Cmdi,
            coverage_gaps: &[],
            sinks: &[
                Sink::name("exec", 0),
                Sink::name("exec", 1),
                Sink::name("command", 0),
                Sink::name("ProcessBuilder", 0),
            ],
        },
        // DirContext.search(name, filter, ...): both the distinguished name and
        // the search filter are injectable, so both operands are sinks.
        CategorySpec {
            category: InjectionCategory::Ldapi,
            coverage_gaps: &[],
            sinks: &[Sink::name("search", 0), Sink::name("search", 1)],
        },
        // `new File(parent, child)` resolves `child` against `parent`, so an
        // attacker-controlled child path traverses as well as a whole path.
        CategorySpec {
            category: InjectionCategory::Pathtraver,
            coverage_gaps: &[],
            sinks: &[
                Sink::name("File", 0),
                Sink::name("File", 1),
                Sink::name("FileInputStream", 0),
                Sink::name("FileOutputStream", 0),
                Sink::name("RandomAccessFile", 0),
                Sink::name("FileReader", 0),
                Sink::name("FileWriter", 0),
                Sink::name("get", 0),
                Sink::name("newInputStream", 0),
                Sink::name("getResourceAsStream", 0),
            ],
        },
        CategorySpec {
            category: InjectionCategory::Xpathi,
            coverage_gaps: &[],
            sinks: &[Sink::name("evaluate", 0), Sink::name("compile", 0)],
        },
        CategorySpec {
            category: InjectionCategory::Xss,
            coverage_gaps: &[],
            sinks: &[
                Sink::qualified(
                    "println",
                    "java.io.PrintWriter.println",
                    SinkFormal::Index(0),
                ),
                Sink::qualified("print", "java.io.PrintWriter.print", SinkFormal::Index(0)),
                Sink::qualified("write", "java.io.PrintWriter.write", SinkFormal::Index(0)),
                Sink::qualified(
                    "format",
                    "java.io.PrintWriter.format",
                    SinkFormal::Name("format"),
                ),
                Sink::qualified(
                    "format",
                    "java.io.PrintWriter.format",
                    SinkFormal::Name("args"),
                ),
                Sink::qualified(
                    "printf",
                    "java.io.PrintWriter.printf",
                    SinkFormal::Name("format"),
                ),
                Sink::qualified(
                    "printf",
                    "java.io.PrintWriter.printf",
                    SinkFormal::Name("args"),
                ),
                Sink::qualified(
                    "append",
                    "java.io.PrintWriter.append",
                    SinkFormal::Name("csq"),
                ),
            ],
        },
    ],
};

/// OWASP BenchmarkPython 0.1.
///
/// The sources are the Flask request reads the premium Werkzeug model covers
/// exactly: `ImmutableMultiDict.get` and `getlist` on `request.form`,
/// `request.args` and `request.cookies`, which the model types as exact
/// `ImmutableMultiDict` results. The suite's other request reads are coverage
/// gaps (see `source_gaps`).
///
/// The sinks are name selectors, as in BenchmarkJava, taken from the calls the
/// suite makes (see the vetting record on #11040). `xss` is not scored: its
/// payload reaches the response as the Flask view's return value, which no
/// call-argument sink selects. `xxe` is not scored: whether a parse is
/// vulnerable depends on a parser feature flag, not on where data flows.
pub static BENCHMARK_PYTHON: BenchmarkSuite = BenchmarkSuite {
    name: "BenchmarkPython",
    repo: "https://github.com/OWASP-Benchmark/BenchmarkPython",
    version: "0.1",
    expected_results_file: "expectedresults-0.1.csv",
    policy_naming: OWASP_POLICY_NAMING,
    languages: &["python"],
    sources: &[
        Source::ResolvedMethod {
            callee: "get",
            callable: "werkzeug.datastructures.structures.ImmutableMultiDict.get",
            receiver_type: "werkzeug.datastructures.structures.ImmutableMultiDict",
        },
        Source::ResolvedMethod {
            callee: "getlist",
            callable: "werkzeug.datastructures.structures.ImmutableMultiDict.getlist",
            receiver_type: "werkzeug.datastructures.structures.ImmutableMultiDict",
        },
    ],
    // Every request read the source table leaves out, so a case that
    // contains one cannot be cleared. One gap per attribute keeps each
    // selector's answer under the CodeQuery row limit. `request.headers`
    // covers its `get`, `getlist`, `get_all` and `keys` reads.
    source_gaps: &[
        CoverageGap {
            reason: "request.headers is not a source",
            uncovered: Some(
                r#"{"kind": "field_access", "name": "headers", "object": {"name": "request"}}"#,
            ),
        },
        CoverageGap {
            reason: "request.path is not a source",
            uncovered: Some(
                r#"{"kind": "field_access", "name": "path", "object": {"name": "request"}}"#,
            ),
        },
        CoverageGap {
            reason: "request.query_string and request.stream are not sources",
            uncovered: Some(
                r#"{"kind": "field_access", "name": {"regex": "^(query_string|stream)$"}, "object": {"name": "request"}}"#,
            ),
        },
        CoverageGap {
            reason: "keys() reads of request.form and request.args are not sources",
            uncovered: Some(r#"{"kind": "call", "callee": {"name": "keys"}}"#),
        },
        CoverageGap {
            reason: "helpers.separate_request.request_wrapper reads are not sources",
            uncovered: Some(r#"{"kind": "call", "callee": {"name": "request_wrapper"}}"#),
        },
    ],
    categories: &[
        // `sqlite3.Cursor.execute(sql)`.
        CategorySpec {
            category: InjectionCategory::Sqli,
            coverage_gaps: &[],
            sinks: &[Sink::name("execute", 0)],
        },
        // `subprocess.run(args, ...)`: the command list or the `shell=True`
        // string.
        CategorySpec {
            category: InjectionCategory::Cmdi,
            coverage_gaps: &[],
            sinks: &[Sink::name("run", 0)],
        },
        // ldap3 `Connection.search(search_base, search_filter, ...)`: both the
        // base and the filter are injectable.
        CategorySpec {
            category: InjectionCategory::Ldapi,
            coverage_gaps: &[],
            sinks: &[Sink::name("search", 0), Sink::name("search", 1)],
        },
        // `open` and `codecs.open`, `pathlib.Path(path)` and
        // `os.path.exists(path)`. Not yet covered: most pathlib cases build
        // the path as `Path(CONSTANT) / value` and then call `p.exists()` or
        // `p.read_text()` with no argument, so the tainted operand is the
        // receiver, which these argument sinks do not select.
        CategorySpec {
            category: InjectionCategory::Pathtraver,
            coverage_gaps: &[CoverageGap {
                reason: "pathlib receiver calls p.exists() and p.read_text() are not sinks",
                uncovered: Some(
                    r#"{"kind": "call", "callee": {"name": {"regex": "^(exists|read_text)$"}}, "arity": 0}"#,
                ),
            }],
            sinks: &[
                Sink::name("open", 0),
                Sink::name("Path", 0),
                Sink::name("exists", 0),
            ],
        },
        // lxml `_Element.xpath(query)` and `etree.XPath(query)`, and
        // `elementpath.select(root, query)`.
        CategorySpec {
            category: InjectionCategory::Xpathi,
            coverage_gaps: &[],
            sinks: &[
                Sink::name("xpath", 0),
                Sink::name("XPath", 0),
                Sink::name("select", 1),
            ],
        },
        CategorySpec {
            category: InjectionCategory::Codeinj,
            coverage_gaps: &[],
            sinks: &[Sink::name("eval", 0), Sink::name("exec", 0)],
        },
        // `pickle.loads(data)` and `yaml.load(data, Loader=...)`. The suite's
        // safe deserialization cases call `yaml.safe_load`, which has a
        // different name and is not a sink.
        CategorySpec {
            category: InjectionCategory::Deserialization,
            coverage_gaps: &[],
            sinks: &[Sink::name("loads", 0), Sink::name("load", 0)],
        },
        // `flask.redirect(location)`.
        CategorySpec {
            category: InjectionCategory::Redirect,
            coverage_gaps: &[],
            sinks: &[Sink::name("redirect", 0)],
        },
    ],
};

/// The policy id for one of a suite's categories, stable and auditable.
pub fn policy_id(
    suite: &BenchmarkSuite,
    category: InjectionCategory,
    call_modeling: UnmodeledCallBehavior,
) -> String {
    format!(
        "{}.{}.{}",
        suite.policy_naming.id_prefix,
        category.label(),
        call_modeling.label()
    )
}

/// Build the taint policy source for one of the suite's categories. Every
/// policy shares the suite's source set and differs only in its sink set, so a
/// finding attributes unambiguously to the category whose policy produced it.
/// `call_modeling` decides what crosses a call that has neither an analyzed
/// body nor a model: `paranoid` propagates every structurally justified
/// transfer, `optimistic` preserves facts only, and `require-model` abstains.
pub fn build_policy(
    suite: &BenchmarkSuite,
    category: InjectionCategory,
    call_modeling: UnmodeledCallBehavior,
) -> String {
    let hazard_label = category.hazard_label();
    let mut sources = String::new();
    // Endpoints are numbered across languages, so a one-language suite's
    // policies read exactly as they did before suites could name several.
    let source_endpoints = suite
        .languages
        .iter()
        .flat_map(|language| suite.sources.iter().map(move |source| (*language, source)));
    for (index, (language, source)) in source_endpoints.enumerate() {
        match *source {
            Source::Name { callee } => sources.push_str(&format!(
                "          (source :id src-{index} :display-name {callee:?}\n\
                 \x20           :categories [input.user-controlled io.external]\n\
                 \x20           :selector (rql :schema-version 1\n\
                 \x20             (language {language} (call :callee (name {callee:?}))))\n\
                 \x20           :bind return-value :labels [{hazard_label}])\n"
            )),
            // Taint endpoint lowering needs an argument identity on the
            // selected call-binding row even when the endpoint binds the
            // return value; a bare `resolved-call` selects a binding without
            // one and the compile refuses it. Formal 0 is the key every
            // modeled `get` takes, so the step keeps exactly the request
            // reads the bare selector matched.
            Source::ResolvedMethod {
                callee,
                callable,
                receiver_type,
            } => sources.push_str(&format!(
                "          (source :id src-{index} :display-name {callable:?}\n\
                 \x20           :categories [input.user-controlled io.external]\n\
                 \x20           :selector (rql :schema-version 1\n\
                 \x20             (call-argument :formal-index 0\n\
                 \x20               (resolved-call :resolves-to {callable:?} :proof exact\n\
                 \x20                 :receiver-type {receiver_type:?}\n\
                 \x20                 (call-bindings (call-shape\n\
                 \x20                   (language {language} (call :callee (name {callee:?}))))))))\n\
                 \x20           :bind return-value :labels [{hazard_label}])\n"
            )),
            Source::Parameter => sources.push_str(&format!(
                "          (source :id src-{index} :display-name \"parameter\"\n\
                 \x20           :categories [input.user-controlled io.external]\n\
                 \x20           :selector (rql :schema-version 1 (language {language} (parameter)))\n\
                 \x20           :bind matched-value :labels [{hazard_label}])\n"
            )),
        }
    }
    let mut sinks = String::new();
    let sink_endpoints = suite.languages.iter().flat_map(|language| {
        suite
            .sinks(category)
            .iter()
            .map(move |sink| (*language, sink))
    });
    for (index, (language, sink)) in sink_endpoints.enumerate() {
        let callee = sink.callee;
        match sink.selector {
            SinkSelector::Name { argument } => {
                // The dangerous operand is positional argument `argument`, so
                // the call must carry at least `argument + 1` positional
                // arguments to be this sink at all. Constraining the selector
                // by minimum arity is a structural correctness bound, not TPR
                // tuning: it excludes arity-overloaded no-operand calls (a
                // no-argument `PreparedStatement.execute()` collides with
                // `Statement.execute(String)` by name) that otherwise abort
                // endpoint binding for the whole compile (#1935 cause 1).
                // A real sink call always has the operand, so the bound never
                // drops a true positive.
                let min_arity = argument + 1;
                sinks.push_str(&format!(
                    "          (sink :id snk-{index} :display-name {callee:?}\n\
                     \x20           :categories [data.sensitive]\n\
                     \x20           :selector (rql :schema-version 1\n\
                     \x20             (language {language} (call :callee (name {callee:?}) (arity :min {min_arity}))))\n\
                     \x20           :dangerous-operand (argument :index {argument}) :accepts [{hazard_label}])\n"
                ));
            }
            SinkSelector::QualifiedCallBinding { callable, formal } => {
                // Keep the call-binding row as the endpoint's output. The
                // `call-argument` query step filters by the exact declared
                // formal, while taint endpoint lowering remaps that formal to
                // the caller-side actual index recorded in the row. This is
                // essential for Locale-first and variadic overloads: Locale is
                // formal 0, format is formal 1, and every written vararg maps
                // to formal 2.
                let (display_name, formal_selector, operand) = match formal {
                    SinkFormal::Name(name) => (
                        format!("{callee} {name}"),
                        format!(":formal-name {name:?}"),
                        format!("(argument :name {name:?})"),
                    ),
                    SinkFormal::Index(position) => (
                        format!("{callee} #{position}"),
                        format!(":formal-index {position}"),
                        format!("(argument :index {position})"),
                    ),
                };
                sinks.push_str(&format!(
                    "          (sink :id snk-{index} :display-name {display_name:?}\n\
                     \x20           :categories [data.sensitive]\n\
                     \x20           :selector (rql :schema-version 1\n\
                     \x20             (language {language}\n\
                     \x20               (call-argument {formal_selector}\n\
                     \x20                 (resolved-call :resolves-to {callable:?} :proof declared\n\
                     \x20                   (call-bindings (call-shape (call :callee (name {callee:?}))))))))\n\
                     \x20           :dangerous-operand {operand} :accepts [{hazard_label}])\n",
                ));
            }
        }
    }
    let reasons = suite
        .coverage_gaps(category)
        .map(|gap| gap.reason)
        .collect::<Vec<_>>();
    let coverage = if reasons.is_empty() {
        String::new()
    } else {
        format!(
            "\x20 :coverage (proven-subset :reason {:?})\n",
            reasons.join("; ")
        )
    };
    let id = policy_id(suite, category, call_modeling);
    let PolicyNaming {
        title, taxonomy, ..
    } = suite.policy_naming;
    let taxonomy_id = format!("BENCHMARK-{}", category.label().to_uppercase());
    format!(
        "(policy\n\
        \x20 :schema-version 1\n\
        \x20 :id {id:?}\n\
        \x20 :name \"{title} {label} ({call_modeling})\"\n\
        \x20 :message \"data carrying {hazard_label} reached a {label} sink\"\n\
        \x20 :severity warning\n\
        {coverage}\
        \x20 :analysis (analysis\n\
        \x20   :type taint\n\
        \x20   :mode may\n\
        \x20   :call-modeling (call-modeling :unmodeled {call_modeling})\n\
        \x20   :sources (endpoint-set :entries [\n{sources}          ])\n\
        \x20   :sinks (endpoint-set :entries [\n{sinks}          ]))\n\
        \x20 :classification (classification\n\
        \x20   :fallback (classification-id :taxonomy {taxonomy:?} :id {taxonomy_id:?})))\n",
        label = category.label(),
        hazard_label = hazard_label,
        call_modeling = call_modeling.label(),
    )
}

// ===========================================================================
// ESAPI sanitizer pack promotion
// ===========================================================================

/// Promote a staged sanitizer pack to a pinned one by writing the resolved
/// artifact's SHA-256 into every shard activation. This is the deterministic
/// promotion the sanitizer README describes: the staged pack carries a package
/// coordinate but no byte-level pin, and this step supplies the pin from the jar
/// the Maven build resolved.
///
/// Returns the pinned pack JSON (pretty, newline-terminated). The caller writes
/// it and validates it through `compile_source`.
pub fn promote_staged_sanitizer_pack(
    staged_json: &str,
    artifact_sha256: &str,
) -> Result<String, String> {
    let mut value: serde_json::Value =
        serde_json::from_str(staged_json).map_err(|error| format!("staged pack parse: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "staged pack is not a JSON object".to_owned())?;

    // Record the pin in provenance so the promoted pack is self-describing.
    if let Some(provenance) = object.get_mut("provenance").and_then(|p| p.as_object_mut()) {
        provenance.insert(
            "source".to_owned(),
            serde_json::Value::String(format!(
                "audited k3 sanitizer content, pinned to the resolved artifact (sha256 {artifact_sha256})"
            )),
        );
    }
    object.insert(
        "completeness".to_owned(),
        serde_json::Value::String("complete".to_owned()),
    );

    let shards = object
        .get_mut("shards")
        .and_then(|s| s.as_array_mut())
        .ok_or_else(|| "staged pack has no shards array".to_owned())?;
    let mut activations_pinned = 0u32;
    for shard in shards.iter_mut() {
        let activations = shard
            .get_mut("activation")
            .and_then(|a| a.as_array_mut())
            .ok_or_else(|| "shard has no activation array".to_owned())?;
        for activation in activations.iter_mut() {
            let entry = activation
                .as_object_mut()
                .ok_or_else(|| "activation entry is not an object".to_owned())?;
            entry.insert(
                "artifact_sha256".to_owned(),
                serde_json::Value::String(artifact_sha256.to_owned()),
            );
            activations_pinned += 1;
        }
    }
    if activations_pinned == 0 {
        return Err("staged pack had no activations to pin".to_owned());
    }
    let mut rendered =
        serde_json::to_string_pretty(&value).map_err(|error| format!("render: {error}"))?;
    rendered.push('\n');
    Ok(rendered)
}

// ===========================================================================
// Live runner
// ===========================================================================

/// One pack to activate: its on-disk JSON and the activation evidence that lets
/// the analyzer bind it. The set spans sanitizer packs, external declaration
/// packs (servlet/JDBC/java.lang framework decls), and the golden JDK
/// procedure-summary pack -- every pack the run needs to close a
/// boundary the Benchmark routes flows through.
struct LoadedPack {
    pack_id: String,
    compiled: CompiledSemanticModelPack,
    evidence: SemanticModelActivationEvidence,
}

/// A JDK toolchain coordinate the sanitizer evidence advertises. The JDK the
/// analyzer sees is at least 17; 21 is what this run used.
fn jdk_toolchain() -> CatalogCoordinate {
    CatalogCoordinate {
        name: "jdk".to_owned(),
        version: Some(Version::new(21, 0, 0)),
    }
}

// ===========================================================================
// #2558: JDK dependency pack, routed through the product activation path
// ===========================================================================
//
// Every other pack this module loads is authored bakeoff content (sanitizer
// knowledge, servlet/JDK behavioral summaries) with no real generation-time
// extraction behind it, so `SemanticPackCatalog::register_session_pack` --
// which only validates a pack's own shape and never consults `Completeness`
// or gap accounting -- is the right mechanism for it (#2401's central
// finding). The JDK declaration pack is different: it is a real, generated
// extraction of the JDK's own `src.zip` (44 shards, 52,996 records, 3,791
// named warning-grade gaps for `bifrost.jdk@21.0.8`), and it exists
// specifically so `prepare_dependency_semantic_packs`'s declaration-scoped
// completeness gate (`crates/bifrost-analysis/src/analyzer/semantic_model/dependency.rs`,
// landed for #2401) has something real to activate. Loading it through
// `register_session_pack` would skip that gate entirely -- exactly the
// bakeoff-vs-product divergence issue #2558 exists to close.

/// The exact JDK release the pinned `bifrost.jdk` pack was extracted from
/// (pinned in `BrokkAi/bifrost-packs`). The pack's activation
/// selector accepts the whole `>=21.0.0, <22.0.0` API surface that build
/// serves (#3465), so the harness names the extraction build itself rather
/// than an arbitrary member of the range: the measurement is about the pack
/// whose declarations came from exactly this release. A caller who wants a
/// different JDK feature release needs a differently pinned pack, not a flag
/// here.
const JDK_PACK_VERSION: &str = "21.0.8";

/// The dependency id JVM discovery gives the JDK of `version`.
fn jdk_dependency_id(version: &str) -> String {
    format!("jdk:{version}")
}

/// Write an evidence-only JDK home: a `release` file naming the exact
/// version and no `lib/src.zip`. JVM dependency discovery
/// (`discover_jdk_semantic_pack_dependencies` in
/// `crates/bifrost-analysis/src/analyzer/jvm/external.rs`) then resolves a
/// zero-artifact JDK dependency, which is what forces
/// `prepare_dependency_semantic_packs` through its installed-pack lookup
/// (`compatible_installed_pack`) instead of local production. A real
/// `JAVA_HOME` with an actual `src.zip` would instead have Bifrost
/// regenerate a fresh JDK pack in-process on every run, which is not how a
/// customer runs the shipped, pre-installed `bifrost.jdk` release bundle.
/// This is the same evidence-only-home shape #2401's own Butterknife
/// acceptance smoke used, and the one
/// `tests/suite_semantic/dependency_pack_version_selection.rs`'s
/// `write_jdk_home` helper exercises.
fn write_evidence_only_jdk_home(root: &Path, version: &str) -> Result<PathBuf, String> {
    let home = root.join(format!("jdk-{version}"));
    fs::create_dir_all(&home).map_err(|error| format!("mkdir {}: {error}", home.display()))?;
    let release = home.join("release");
    fs::write(&release, format!("JAVA_VERSION=\"{version}\"\n"))
        .map_err(|error| format!("write {}: {error}", release.display()))?;
    Ok(home)
}

/// Activate the JDK declaration pack through the PRODUCT path:
/// `WorkspaceAnalyzer::activate_dependency_packs` ->
/// `prepare_dependency_semantic_packs`. This is the same function
/// `crates/bifrost-analysis/src/analyzer/packs_document.rs::activate_workspace_packs`
/// calls when a host activates packs from a checked-in `.bifrost/packs.json`
/// (`activate_workspace_packs` is a thin wrapper around exactly this call
/// with `workspace_model_root: None`, verified by reading its source); the
/// harness calls it directly because it builds its activation evidence in
/// Rust rather than from a JSON document, the same way it already does for
/// its own session packs, and a document layer here would only add an
/// artificial workspace-relative catalog path with no behavioral difference.
///
/// `catalog` must already have the real `bifrost.jdk` release bundle
/// installed (`bifrost-semantic-pack install <bundle> <catalog>`) for
/// `jdk_version`, the version of the JDK home in `analyzer_config`, and be
/// open read-write: preparation produces packs for the workspace's dependency
/// jars into it, as the product path does. `analyzer_config` must be the
/// config `workspace` was built with (see `java_analyzer_config`). The
/// activation publishes the active models on `workspace`, where the category
/// runs read them; on success this returns the preparation outcome, for gap
/// reporting. On any refusal -- discovery incomplete, or the completeness gate declining the installed pack -- returns `Err`
/// naming the reason; this function never silently drops the JDK from the
/// active set.
pub fn activate_jdk_dependency_pack(
    workspace: &WorkspaceAnalyzer,
    analyzer_config: &AnalyzerConfig,
    jdk_version: &str,
    catalog: &SemanticPackCatalog,
    request: SemanticModelActivationRequest,
    cancellation: &CancellationToken,
) -> Result<DependencyPackPreparationOutcome, String> {
    let outcome = workspace.activate_dependency_packs(
        analyzer_config,
        &[DependencyPackEcosystem::Jvm],
        DependencyPackWorkspaceContext {
            catalog,
            persistence: None,
            activation: &request,
            limits: DependencyPackLimits::default(),
            cancellation,
        },
    );
    let ecosystem =
        outcome.ecosystems.into_iter().next().ok_or_else(|| {
            "JVM dependency-pack activation produced no ecosystem outcome".to_owned()
        })?;
    if !ecosystem.discovery.complete {
        return Err(format!(
            "JDK dependency discovery was incomplete: {:?}",
            ecosystem.discovery.diagnostics
        ));
    }
    let preparation = ecosystem
        .preparation
        .ok_or_else(|| "JDK dependency-pack preparation did not run".to_owned())?;
    if preparation.cancelled {
        return Err(format!(
            "JDK dependency-pack preparation was cancelled: {:?}",
            preparation.diagnostics
        ));
    }
    // The category runs read the snapshot this activation published; a
    // runtime that is not ready published none, or a partial one.
    if !matches!(
        outcome.runtime,
        Some(SemanticModelRuntimeOutcome::Ready { .. })
    ) {
        return Err(format!(
            "JVM dependency-pack activation is not ready: {:#?}",
            outcome.runtime
        ));
    }
    // The JDK pack is mandatory. A dependency jar whose pack could not be
    // produced is not: preparation records it as a failure, and the reader
    // treats that jar as unknown instead of refusing every JVM lookup, as it
    // does on the product path.
    let jdk_dependency_id = jdk_dependency_id(jdk_version);
    if !preparation
        .installed_packs
        .iter()
        .any(|pack| pack.dependency_id == jdk_dependency_id)
    {
        return Err(format!(
            "the JDK pack for {jdk_dependency_id} was not installed: installed={:?} \
             diagnostics={:?}",
            preparation
                .installed_packs
                .iter()
                .map(|pack| &pack.dependency_id)
                .collect::<Vec<_>>(),
            preparation.diagnostics
        ));
    }
    if preparation
        .installed_packs
        .iter()
        .any(|pack| !pack.activation_ready)
    {
        return Err(format!(
            "JDK dependency-pack preparation was refused by the declaration-scoped \
             completeness gate: {:?}",
            preparation.diagnostics
        ));
    }
    if !preparation.failures.is_empty() {
        eprintln!(
            "dependency packs not prepared, left as gaps: {:?}",
            preparation.failures
        );
    }
    Ok(preparation)
}

// ===========================================================================
// BenchmarkPython: staged workspace, installed wheels, pinned premium models
// ===========================================================================
//
// A Python third-party model activates only from exact evidence: a declared
// Python environment whose installed-distribution roots hold the files of a
// wheel whose SHA-256 matches the model's artifact selector. The runtime
// paths in that declaration must be relative to the analyzed workspace, so
// the run stages one: the checkout under `src/`, and the downloaded wheels,
// their installed files and the declaration's evidence files under an
// ignored `.runtime-evidence/` beside it. The checkout itself is never
// written to.
//
// The premium models ship with a placeholder digest. The run pins each to its
// downloaded wheel, as `promote_staged_sanitizer_pack` pins the ESAPI pack
// for Java, and registers it as a session pack. The CPython packs come from
// the `bifrost.public.packs` bundle installed in the operator catalog and
// activate on the declared interpreter's toolchain.

/// The CPython release the declared interpreter names. The public CPython
/// packs activate on exactly `>=3.13.5, <3.13.6`, and BenchmarkPython needs
/// 3.12 or later for its nested same-quote f-strings (PEP 701).
const PYTHON_TOOLCHAIN_VERSION: Version = Version::new(3, 13, 5);

/// The catalog pack that models the CPython standard library. A Python run
/// refuses to score without it.
const PYTHON_STDLIB_PACK_ID: &str = "bifrost.python-stdlib";

/// The workspace-relative directory holding the runtime evidence, ignored by
/// source analysis.
const PYTHON_RUNTIME_EVIDENCE: &str = ".runtime-evidence";

/// One third-party distribution the run installs, with the premium model that
/// describes it.
struct PythonDistribution {
    name: &'static str,
    version: &'static str,
    wheel: &'static str,
    /// The wheel's SHA-256 as published on PyPI. The model is pinned to the
    /// wheel the harness was vetted against, never to whatever file the
    /// operator supplies under that name.
    sha256: &'static str,
    /// The model's CSMI document, relative to the premium-packs checkout.
    model: &'static str,
}

/// The distributions with a premium model the suite's endpoints need. The
/// versions are the models' own, not the suite's `requirements.txt` pins:
/// the Werkzeug model describes 3.1.0 and the suite pins 3.1.3, and a model
/// only activates for the exact artifact it was reviewed against. The request
/// reads the suite makes behave the same in both releases.
const PYTHON_DISTRIBUTIONS: &[PythonDistribution] = &[
    PythonDistribution {
        name: "flask",
        version: "3.1.0",
        wheel: "flask-3.1.0-py3-none-any.whl",
        sha256: "d667207822eb83f1c4b50949b1623c8fc8d51f2341d65f72e1a1815397551136",
        model: "semantic-packs/python-codeql-parity/bifrost.python-flask.json",
    },
    PythonDistribution {
        name: "werkzeug",
        version: "3.1.0",
        wheel: "werkzeug-3.1.0-py3-none-any.whl",
        sha256: "208a2e31a4a54c8b3d2244f2079ca1d3851629a7a7d546646059c64fb746023a",
        model: "semantic-packs/python-codeql-parity/bifrost.python-werkzeug.json",
    },
    PythonDistribution {
        name: "ldap3",
        version: "2.9.1",
        wheel: "ldap3-2.9.1-py2.py3-none-any.whl",
        sha256: "5869596fc4948797020d3f03b7939da938778a0f9e2009f7a072ccf92b8e8d70",
        model: "semantic-packs/python-codeql-parity/bifrost.python-ldap3.csmi.json",
    },
];

/// Stage the BenchmarkPython workspace, pin and register the premium models,
/// build the workspace and activate the Python dependency packs through the
/// product path.
fn prepare_python(
    benchmark_root: &Path,
    inputs: &PythonInputs,
    budget: &RetentionBudget,
    timeout: Duration,
) -> Result<PreparedSuite, String> {
    let work = &inputs.work_dir;
    if work.exists()
        && fs::read_dir(work)
            .map_err(|error| format!("read {}: {error}", work.display()))?
            .next()
            .is_some()
    {
        return Err(format!(
            "the Python work directory must be absent or empty: {}",
            work.display()
        ));
    }
    // A work directory inside the checkout would be walked by its own copy.
    fs::create_dir_all(work).map_err(|error| format!("mkdir {}: {error}", work.display()))?;
    let canonical = |path: &Path| {
        path.canonicalize()
            .map_err(|error| format!("canonicalize {}: {error}", path.display()))
    };
    if canonical(work)?.starts_with(canonical(benchmark_root)?) {
        return Err(format!(
            "the Python work directory {} must not be inside the benchmark checkout {}",
            work.display(),
            benchmark_root.display()
        ));
    }
    copy_tree(benchmark_root, &work.join("src"))?;
    write_file(
        &work.join(".bifrostignore"),
        format!("{PYTHON_RUNTIME_EVIDENCE}/\n").as_bytes(),
    )?;

    let mut runtime_artifacts = Vec::with_capacity(PYTHON_DISTRIBUTIONS.len());
    let mut artifacts = Vec::with_capacity(PYTHON_DISTRIBUTIONS.len());
    for distribution in PYTHON_DISTRIBUTIONS {
        let wheel_source = inputs.wheels_dir.join(distribution.wheel);
        let bytes = fs::read(&wheel_source)
            .map_err(|error| format!("read wheel {}: {error}", wheel_source.display()))?;
        let archive_sha256 = csmi::sha256_hex(&bytes);
        if archive_sha256 != distribution.sha256 {
            return Err(format!(
                "wheel {} has SHA-256 {archive_sha256}, not the vetted {}",
                wheel_source.display(),
                distribution.sha256
            ));
        }
        let archive_path = Path::new(PYTHON_RUNTIME_EVIDENCE)
            .join("wheels")
            .join(distribution.wheel);
        write_file(&work.join(&archive_path), &bytes)?;
        let installed_root = Path::new(PYTHON_RUNTIME_EVIDENCE)
            .join("site")
            .join(distribution.name);
        install_wheel(&bytes, &work.join(&installed_root), distribution.wheel)?;
        runtime_artifacts.push(PythonRuntimeArtifactConfig {
            archive_path,
            installed_root,
        });
        artifacts.push(PythonArtifact {
            distribution: distribution.name,
            purl: format!("pkg:pypi/{}@{}", distribution.name, distribution.version),
            archive_sha256,
        });
    }
    let environment = declared_python_environment(work, runtime_artifacts)?;
    let limits = DependencyPackLimits::default();
    let project_config =
        python_declared_environment_project_config(work, &environment, &limits, None)
            .map_err(|error| format!("derive the Python projectConfig: {error:?}"))?;

    let catalog = SemanticPackCatalog::open(
        &inputs.catalog_root,
        CatalogOpenMode::ReadOnly,
        CatalogOptions::default(),
    )
    .map_err(|error| {
        format!(
            "open operator catalog {}: {error}",
            inputs.catalog_root.display()
        )
    })?;
    let mut premium_pack_ids = Vec::new();
    let mut controls = Vec::new();
    for (distribution, artifact) in PYTHON_DISTRIBUTIONS.iter().zip(&artifacts) {
        let model_path = inputs.premium_packs_dir.join(distribution.model);
        let document = fs::read(&model_path)
            .map_err(|error| format!("read model {}: {error}", model_path.display()))?;
        let compiled = pin_python_model(&document, artifact, &project_config)
            .map_err(|error| format!("{}: {error}", model_path.display()))?;
        let pack_id = compiled.manifest.pack_id.clone();
        catalog
            .register_session_pack(
                &compiled,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: format!("owasp-benchmark:{pack_id}"),
                },
            )
            .map_err(|error| format!("register pack {pack_id}: {error}"))?;
        controls.push(enable_pack(&pack_id));
        premium_pack_ids.push(pack_id);
    }

    let mut analyzer_config = AnalyzerConfig::default();
    analyzer_config.python.runtime_environments = vec![environment];
    let project = FilesystemProject::new(work)
        .map_err(|error| format!("open staged Python project: {error}"))?;
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun_with_budget(
        Arc::new(project),
        analyzer_config.clone(),
        budget,
    )
    .map_err(|error| format!("build staged Python workspace: {error}"))?;

    let request = SemanticModelActivationRequest {
        host_activation:
            brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
        approximate_standard_libraries: Vec::new(),
        bifrost_version: bifrost_version()?,
        evidence: vec![SemanticModelActivationEvidence {
            language: "python".to_owned(),
            ecosystem: "python".to_owned(),
            package: None,
            module: None,
            toolchain: Some(CatalogCoordinate {
                name: "cpython".to_owned(),
                version: Some(PYTHON_TOOLCHAIN_VERSION),
            }),
            target: None,
            configuration: None,
            production_input_digest: None,
            verified_raw_artifacts: Vec::new(),
        }],
        controls,
        limits: SemanticModelRuntimeLimits::default(),
    };
    let cancellation = CancellationToken::new().with_timeout(timeout);
    let outcome = workspace.activate_dependency_packs(
        &analyzer_config,
        &[DependencyPackEcosystem::Python],
        DependencyPackWorkspaceContext {
            catalog: &catalog,
            persistence: None,
            activation: &request,
            limits,
            cancellation: &cancellation,
        },
    );
    let [ecosystem] = outcome.ecosystems.as_slice() else {
        return Err(format!(
            "Python dependency-pack activation produced {} ecosystem outcomes",
            outcome.ecosystems.len()
        ));
    };
    if !ecosystem.discovery.complete {
        return Err(format!(
            "Python dependency discovery was incomplete: {:?}",
            ecosystem.discovery.diagnostics
        ));
    }
    // A premium model that its wheel evidence does not select leaves its
    // identities out of the overlay, and every selector naming them fails as
    // `qualified-call-locator-zero`, indistinguishable from a wrong name.
    // Refuse the run instead.
    let Some(SemanticModelRuntimeOutcome::Ready { active, .. }) = &outcome.runtime else {
        return Err(format!(
            "Python dependency-pack activation is not ready: {:#?}",
            outcome.runtime
        ));
    };
    let inactive = premium_pack_ids
        .iter()
        .map(|pack_id| format!("owasp-benchmark:{pack_id}"))
        .filter(|source_id| {
            !active
                .shards()
                .iter()
                .any(|shard| &shard.source_id == source_id)
        })
        .collect::<Vec<_>>();
    if !inactive.is_empty() {
        return Err(format!(
            "premium Python models {inactive:?} were not selected by their wheel evidence: {:#?}",
            active.activation_report()
        ));
    }
    // The catalog's CPython packs shape the result as much as the premium
    // models do, and which ones the catalog holds is an operator input, so
    // the artifact records every selected pack with its version. Without the
    // standard-library pack the run would score a configuration it does not
    // claim to measure.
    let mut selected_packs = active
        .shards()
        .iter()
        .map(|shard| {
            (
                shard.manifest.pack_id.clone(),
                shard.manifest.version.clone(),
            )
        })
        .collect::<Vec<_>>();
    selected_packs.sort();
    selected_packs.dedup();
    if !selected_packs
        .iter()
        .any(|(pack_id, _)| pack_id == PYTHON_STDLIB_PACK_ID)
    {
        return Err(format!(
            "the catalog's {PYTHON_STDLIB_PACK_ID} pack was not selected; selected packs: {selected_packs:?}"
        ));
    }
    let activated_pack_ids = selected_packs
        .into_iter()
        .map(|(pack_id, version)| format!("{pack_id}@{version}"))
        .collect();
    Ok(PreparedSuite {
        analysis_root: work.clone(),
        workspace,
        activated_pack_ids,
        skipped_packs: Vec::new(),
        activation: SuiteActivation::Python {
            python_artifacts: artifacts,
        },
        _jdk_home: None,
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().expect("a staged file has a parent directory");
    fs::create_dir_all(parent).map_err(|error| format!("mkdir {}: {error}", parent.display()))?;
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

/// Copy the checkout's regular files into `to`, leaving out `.git`. Symbolic
/// links are not followed: the checkout is untrusted data, and a link could
/// name a file outside it.
fn copy_tree(from: &Path, to: &Path) -> Result<(), String> {
    for entry in walkdir::WalkDir::new(from)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| entry.file_name() != ".git")
    {
        let entry = entry.map_err(|error| format!("walk {}: {error}", from.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(from)
            .expect("a walked path is under its root");
        let bytes = fs::read(entry.path())
            .map_err(|error| format!("read {}: {error}", entry.path().display()))?;
        write_file(&to.join(relative), &bytes)?;
    }
    Ok(())
}

/// Install a wheel the way an installer lays it out: every member at its
/// archive path under `root`. A member whose path would leave `root` is an
/// error, not something to skip.
fn install_wheel(bytes: &[u8], root: &Path, wheel: &str) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .map_err(|error| format!("open wheel {wheel}: {error}"))?;
    for index in 0..archive.len() {
        let mut member = archive
            .by_index(index)
            .map_err(|error| format!("read wheel {wheel} member {index}: {error}"))?;
        if member.is_dir() {
            continue;
        }
        let relative = member
            .enclosed_name()
            .ok_or_else(|| format!("wheel {wheel} member {:?} escapes its root", member.name()))?;
        let mut contents = Vec::new();
        std::io::Read::read_to_end(&mut member, &mut contents).map_err(|error| {
            format!("read wheel {wheel} member {}: {error}", relative.display())
        })?;
        write_file(&root.join(relative), &contents)?;
    }
    Ok(())
}

/// Write one runtime evidence file under the work directory and return its
/// SHA-256.
fn write_runtime_evidence(work: &Path, relative: &Path, bytes: &[u8]) -> Result<String, String> {
    write_file(&work.join(relative), bytes)?;
    Ok(csmi::sha256_hex(bytes))
}

/// The declared Python environment for the staged workspace: an isolated
/// CPython whose import path is exactly the source root, an empty standard
/// library root (the standard library comes from the CPython packs) and one
/// installed-distribution root per wheel. The interpreter is an opaque
/// evidence file and is never executed.
fn declared_python_environment(
    work: &Path,
    artifacts: Vec<PythonRuntimeArtifactConfig>,
) -> Result<PythonRuntimeEnvironmentConfig, String> {
    let evidence = Path::new(PYTHON_RUNTIME_EVIDENCE);
    let interpreter_path = evidence.join("python/interpreter.bin");
    let interpreter_sha256 = write_runtime_evidence(
        work,
        &interpreter_path,
        b"opaque interpreter evidence; never execute\n",
    )?;
    let config_files = [
        (
            "resolver",
            PythonDeclaredConfigInputRole::ResolverConfiguration,
            b"import_path = declared_roots_only\nfinder = standard_filesystem\n".as_slice(),
        ),
        (
            "entry",
            PythonDeclaredConfigInputRole::EntryConfiguration,
            b"mode = script\nroot = source\npath = app.py\n".as_slice(),
        ),
        (
            "startup",
            PythonDeclaredConfigInputRole::StartupConfiguration,
            b"site_startup = disabled\n".as_slice(),
        ),
        (
            "environment",
            PythonDeclaredConfigInputRole::EnvironmentConfiguration,
            b"environment = cleared\n".as_slice(),
        ),
        (
            "extras",
            PythonDeclaredConfigInputRole::ExtrasConfiguration,
            b"enabled_extras = []\n".as_slice(),
        ),
    ];
    let mut config_inputs = Vec::with_capacity(config_files.len());
    for (ordinal, (input_id, role, bytes)) in (0u32..).zip(config_files) {
        let path = evidence.join("config").join(format!("{input_id}.toml"));
        config_inputs.push(PythonDeclaredConfigInput {
            ordinal,
            input_id: input_id.to_owned(),
            role,
            sha256: write_runtime_evidence(work, &path, bytes)?,
            path,
        });
    }
    write_runtime_evidence(work, &evidence.join("stdlib/.keep"), b"")?;
    let mut root_slots = vec![
        PythonDeclaredRootSlot {
            ordinal: 0,
            slot_id: "source".to_owned(),
            role: PythonDeclaredRootRole::Source,
            path: PathBuf::from("src"),
            artifact_index: None,
        },
        PythonDeclaredRootSlot {
            ordinal: 1,
            slot_id: "stdlib".to_owned(),
            role: PythonDeclaredRootRole::StandardLibrary,
            path: evidence.join("stdlib"),
            artifact_index: None,
        },
    ];
    for ((artifact_index, distribution), artifact) in
        (0u32..).zip(PYTHON_DISTRIBUTIONS).zip(&artifacts)
    {
        root_slots.push(PythonDeclaredRootSlot {
            ordinal: artifact_index + 2,
            slot_id: format!("installed-{}", distribution.name),
            role: PythonDeclaredRootRole::InstalledDistribution,
            path: artifact.installed_root.clone(),
            artifact_index: Some(artifact_index),
        });
    }
    let platform = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    };
    Ok(PythonRuntimeEnvironmentConfig {
        source_root: PathBuf::from("src"),
        artifacts,
        declared_environment: Some(PythonDeclaredEnvironmentConfig {
            producer_version: SUPPORTED_PYTHON_DECLARED_ENVIRONMENT_PRODUCER_VERSION.to_owned(),
            resolver_version: SUPPORTED_PYTHON_DECLARED_FILESYSTEM_RESOLVER_VERSION.to_owned(),
            interpreter: PythonDeclaredInterpreter {
                path: interpreter_path,
                sha256: interpreter_sha256,
                implementation: "cpython".to_owned(),
                python_version: PYTHON_TOOLCHAIN_VERSION.to_string(),
                abi: format!(
                    "cp{}{}",
                    PYTHON_TOOLCHAIN_VERSION.major, PYTHON_TOOLCHAIN_VERSION.minor
                ),
                platform: platform.to_owned(),
            },
            launch: PythonDeclaredLaunchSemantics {
                isolation: PythonDeclaredIsolationMode::Isolated,
                site_startup: PythonDeclaredSiteStartupMode::Disabled,
                environment: PythonDeclaredEnvironmentMode::Cleared,
                import_path: PythonDeclaredImportPathMode::DeclaredRootsOnly,
                finder: PythonDeclaredFinderMode::StandardFilesystem,
                editable_installs: PythonDeclaredEditableInstallMode::Disabled,
                native_extensions: PythonDeclaredNativeExtensionMode::Disabled,
            },
            entry_point: PythonDeclaredEntryPoint {
                mode: PythonDeclaredEntryMode::Script,
                root_slot_id: "source".to_owned(),
                relative_path: PathBuf::from("app.py"),
                working_directory_root_slot_id: "source".to_owned(),
                working_directory: PathBuf::new(),
            },
            extras: Vec::new(),
            config_inputs,
            root_slots,
        }),
    })
}

/// Pin one premium Python CSMI model to the installed wheel and the staged
/// environment, then compile it. The shipped document carries a placeholder
/// archive digest and no `projectConfig`; a model activates only when both
/// name the exact artifact and environment the analyzer verified, so this
/// writes the wheel's digest into the artifact selector and the
/// target-artifact provenance input, and the environment's digest into the
/// Python compatibility constraint.
fn pin_python_model(
    document: &[u8],
    artifact: &PythonArtifact,
    project_config: &csmi::CsmiArtifactDigest,
) -> Result<CompiledSemanticModelPack, String> {
    let mut document: serde_json::Value = serde_json::from_slice(document)
        .map_err(|error| format!("the model is not JSON: {error}"))?;
    document["schema"] = serde_json::json!(csmi::CSMI_SCHEMA_URI);
    let digest = serde_json::json!({
        "algorithm": "sha-256",
        "coverage": "artifact",
        "value": artifact.archive_sha256,
    });
    let [model] = document["semanticModels"]
        .as_array_mut()
        .map(Vec::as_mut_slice)
        .ok_or("the document has no semanticModels")?
    else {
        return Err("the document has more than one semantic model".to_owned());
    };
    let selectors = model["artifactSelectors"]
        .as_array()
        .ok_or("the model has no artifactSelectors")?;
    if selectors.len() != 1 || selectors[0]["purl"] != artifact.purl.as_str() {
        return Err(format!(
            "the model does not select exactly {}: {selectors:?}",
            artifact.purl
        ));
    }
    model["artifactSelectors"] = serde_json::json!([{
        "purl": artifact.purl,
        "digests": [digest],
    }]);
    let python_use = model["vocabularyUses"]
        .as_array_mut()
        .ok_or("the model has no vocabularyUses")?
        .iter_mut()
        .find(|use_| {
            use_["identifier"] == csmi::CSMI_PYTHON_PROFILE_ID
                && use_["version"] == csmi::CSMI_PYTHON_PROFILE_VERSION
        })
        .ok_or("the model does not use the Python profile")?;
    let affects = python_use["affects"]
        .as_array_mut()
        .ok_or("the Python profile use names no affected units")?;
    let compatibility_scope = serde_json::json!({
        "kind": "core-slot",
        "slot": "artifact-compatibility",
        "target": {"semanticModel": "current"},
    });
    if !affects.contains(&compatibility_scope) {
        affects.push(compatibility_scope);
    }
    let project_config = serde_json::to_value(project_config)
        .map_err(|error| format!("serialize projectConfig: {error}"))?;
    let constraints = model
        .as_object_mut()
        .ok_or("the semantic model is not an object")?
        .entry("compatibilityConstraints")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or("compatibilityConstraints is not an array")?;
    match constraints.iter_mut().find(|constraint| {
        constraint["vocabulary"] == csmi::CSMI_PYTHON_PROFILE_ID
            && constraint["value"]["kind"] == "compatibility"
    }) {
        Some(constraint) => constraint["value"]["projectConfig"] = project_config,
        None => constraints.push(serde_json::json!({
            "vocabulary": csmi::CSMI_PYTHON_PROFILE_ID,
            "version": csmi::CSMI_PYTHON_PROFILE_VERSION,
            "value": {"kind": "compatibility", "projectConfig": project_config},
        })),
    }
    let input = document["provenanceRecords"]
        .as_array_mut()
        .ok_or("the document has no provenanceRecords")?
        .iter_mut()
        .flat_map(|record| record["inputs"].as_array_mut().into_iter().flatten())
        .find(|input| input["role"] == "target-artifact")
        .ok_or("the document names no target artifact")?;
    input["purl"] = serde_json::json!(artifact.purl);
    input["digest"] = digest;
    compile_csmi_document(&document, artifact.distribution)
}

/// Compile one CSMI semantic document as a single-resource logical pack.
fn compile_csmi_document(
    document: &serde_json::Value,
    distribution: &str,
) -> Result<CompiledSemanticModelPack, String> {
    let source =
        serde_json::to_vec(document).map_err(|error| format!("serialize the model: {error}"))?;
    let bytes = csmi::canonical_json_bytes(&source)
        .map_err(|error| format!("canonicalize the model: {error:?}"))?;
    let path = format!("models/{distribution}.csmi.json");
    let resources = csmi::InMemoryCsmiResourceResolver::new([(path.clone(), bytes.clone())])
        .map_err(|error| format!("resource path {path}: {error:?}"))?;
    let logical = csmi::CsmiLogicalPack::new(
        csmi::CsmiPackManifest {
            document_type: "pack-manifest".to_owned(),
            schema: csmi::CSMI_SCHEMA_URI.to_owned(),
            pack_format_version: csmi::CSMI_PACK_FORMAT_VERSION.to_owned(),
            assembler: csmi::CsmiProducerIdentity {
                identifier: "https://bifrost.brokk.ai/owasp-benchmark".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            license: "NOASSERTION".to_owned(),
            created_at: None,
            resources: vec![csmi::CsmiResourceDescriptor {
                path,
                role: csmi::CsmiResourceRole::SemanticDocument,
                media_type: csmi::CSMI_SEMANTIC_DOCUMENT_MEDIA_TYPE.to_owned(),
                size: u64::try_from(bytes.len()).expect("a model's length fits u64"),
                digest: csmi::CsmiContentDigest {
                    algorithm: csmi::CsmiContentDigestAlgorithm::Sha256,
                    value: csmi::sha256_hex(&bytes),
                },
                license: None,
                schema_identifier: None,
                license_reference: None,
            }],
            derived_from: Vec::new(),
        },
        resources,
    );
    let support = csmi::CsmiVocabularySupport::support(
        csmi::CSMI_PYTHON_PROFILE_ID,
        csmi::CSMI_PYTHON_PROFILE_VERSION,
        csmi::CSMI_PYTHON_PROFILE_SCHEMA,
    );
    csmi::import_logical_csmi_pack(&logical, &support, &Default::default())
        .map_err(|error| format!("import the model: {error:?}"))?
        .compile(&Default::default())
        .map_err(|error| format!("compile the model: {error:?}"))
}

/// Configuration for one live run.
pub struct RunConfig {
    /// The edition's own inputs; they also say which edition this is.
    pub inputs: SuiteInputs,
    /// The Benchmark checkout root, holding the label file and the sources.
    pub benchmark_root: PathBuf,
    /// What each category's taint policy does at a call with neither an
    /// analyzed body nor a model.
    pub call_modeling: UnmodeledCallBehavior,
    /// Wall-clock budget for each category's taint run.
    pub timeout: Duration,
    /// Optional cap on the number of cases scored, for a smoke run. `None`
    /// scores the whole subset.
    pub case_limit: Option<usize>,
    /// Optional append-only JSON Lines progress stream. The binary initializes
    /// this with run provenance; the live runner then syncs category start and
    /// completion records as they occur.
    pub progress_path: Option<PathBuf>,
}

impl RunConfig {
    /// The edition this run scores.
    pub fn suite(&self) -> &'static BenchmarkSuite {
        match self.inputs {
            SuiteInputs::Java(_) => &BENCHMARK_JAVA,
            SuiteInputs::Python(_) => &BENCHMARK_PYTHON,
        }
    }
}

/// The inputs one edition's pack activation needs. Each edition activates its
/// packs its own way (`prepare_java`, `prepare_python`); everything after
/// activation is shared.
pub enum SuiteInputs {
    Java(JavaInputs),
    Python(PythonInputs),
}

/// BenchmarkJava's activation inputs.
pub struct JavaInputs {
    /// The directory of resolved dependency jars (Maven `target/dependency`),
    /// fed to the analyzer so Benchmark types resolve. Empty to skip.
    pub dependency_jars: Vec<PathBuf>,
    /// The packs to activate. Each is registered as a session pack, given
    /// matching activation evidence, and enabled with an explicit `Enable`
    /// control (every shipped pack declares `safety.review_required`, so an
    /// enable control is what lets it resolve as active).
    pub packs: Vec<PackSpec>,
    /// #2558: an operator catalog directory with the real `bifrost.jdk`
    /// release bundle already installed
    /// (`bifrost-semantic-pack install <bundle> <this dir>`). The JDK
    /// declaration pack activates from here through the product dependency
    /// path (`activate_jdk_dependency_pack`), not as a curated session pack.
    /// Opened read-write: a run produces packs for the dependency jars into
    /// it, as the product path does, and later runs reuse them.
    pub jdk_catalog_root: PathBuf,
}

/// BenchmarkPython's activation inputs.
pub struct PythonInputs {
    /// An operator catalog directory with the `bifrost.public.packs` native
    /// release bundle installed, for the CPython standard-library packs.
    /// Opened read-only.
    pub catalog_root: PathBuf,
    /// A `BrokkAi/bifrost-premium-packs` checkout, for the Flask, Werkzeug
    /// and ldap3 models.
    pub premium_packs_dir: PathBuf,
    /// A directory holding the wheels `PYTHON_DISTRIBUTIONS` names, as
    /// `pip download --no-deps --only-binary :all:` saves them.
    pub wheels_dir: PathBuf,
    /// An absent or empty directory the run stages its workspace in: a copy
    /// of the checkout plus the installed wheels as ignored runtime evidence.
    pub work_dir: PathBuf,
}

/// A pack to load: its id, its JSON on disk, and the coordinate evidence to
/// activate it with.
pub struct PackSpec {
    pub pack_id: String,
    pub json_path: PathBuf,
    pub ecosystem: String,
    pub package: Option<CatalogCoordinate>,
    pub artifact_sha256: Option<String>,
    /// A mandatory pack that fails to load aborts the run; an optional one is
    /// recorded and skipped.
    pub mandatory: bool,
}

/// The result of one live run: the scoreboard plus everything needed to make
/// the committed artifact reproducible and auditable.
pub struct RunResult {
    pub scoreboard: Scoreboard,
    pub label_set: LabelSet,
    pub activated_pack_ids: Vec<String>,
    /// Packs that could not be compiled or registered, with the reason. A
    /// mandatory pack failing aborts the run; an optional one is recorded here
    /// and the run continues without it.
    pub skipped_packs: Vec<(String, String)>,
    /// Distinct Benchmark cases for which at least one taint root formed (a
    /// verdict was attempted).
    pub cases_with_roots: usize,
    pub taint_roots: usize,
    pub findings_total: usize,
    /// Per-category run-level completion plus a few representative diagnostics,
    /// so the artifact records why a category concluded as it did (for example,
    /// a run-level `capability_incomplete` abstention with its binding reason).
    pub category_runs: Vec<CategoryRunStatus>,
    /// The analyzed source volume the policy coordinator measures to scale its
    /// workspace budget lanes, computed the same way it does. Every density
    /// constant derived from a bakeoff run is per one of these bytes, so the
    /// artifact has to carry the denominator (#1936).
    pub analyzed_files: usize,
    pub analyzed_source_bytes: u64,
    /// What the edition's activation recorded beyond the pack ids.
    pub activation: SuiteActivation,
}

/// What an edition's pack activation records for the artifact.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum SuiteActivation {
    /// #2558: the named warning-grade extraction gaps the activated
    /// `bifrost.jdk` release bundle carries (3,791 for `bifrost.jdk@21.0.8`,
    /// per the #2401 verification). A reference to a gapped declaration
    /// degrades to a typed `PackExtractionGap` incomplete reason rather than
    /// a false absence proof; this count is the honesty budget the product
    /// activation path enforces, restated here so it is visible in the
    /// artifact rather than only in a log line.
    ///
    /// `unprepared_dependencies` names each dependency jar whose pack
    /// preparation failed, with its cause. The run treats those jars as
    /// unknown, so a score is comparable only with runs that left the same
    /// jars unprepared.
    Java {
        jdk_pack_gaps: usize,
        unprepared_dependencies: Vec<String>,
    },
    /// The wheels installed as archive-verified runtime evidence, which the
    /// premium models were pinned to.
    Python {
        python_artifacts: Vec<PythonArtifact>,
    },
}

/// One installed wheel: its package coordinate and archive digest.
#[derive(Debug, Clone, Serialize)]
pub struct PythonArtifact {
    pub distribution: &'static str,
    pub purl: String,
    pub archive_sha256: String,
}

/// The run-level taint completion for one category, with sample diagnostics.
#[derive(Debug, Clone, Serialize)]
pub struct CategoryRunStatus {
    pub category: String,
    pub completion: String,
    /// How the policy execution terminated, when it terminated abnormally --
    /// `DeadlineExceeded` above all. A category whose evaluation is cancelled
    /// before it registers a run produces a report with no runs, which reads
    /// as `no_taint_run`; without this field that is indistinguishable from a
    /// category that ran and found nothing.
    pub termination: Option<String>,
    pub findings: usize,
    pub retained_analyses: usize,
    pub sample_diagnostics: Vec<String>,
    /// The policy run's work report, flattened to `name -> value`.  The scan
    /// and semantic lane charges here are the only measured input available for
    /// calibrating the workspace-scaled budget lanes against a real corpus,
    /// which is what the lane model was missing (#1936).
    pub work: BTreeMap<String, u64>,
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum CategoryProgressRecord<'a> {
    PacksActivated {
        activated: &'a [String],
        skipped: &'a [(String, String)],
        #[serde(flatten)]
        activation: &'a SuiteActivation,
    },
    CategoryStarted {
        category: &'a str,
        ordinal: usize,
        total: usize,
        timeout_secs: u64,
    },
    CategoryCompleted {
        ordinal: usize,
        total: usize,
        #[serde(flatten)]
        status: &'a CategoryRunStatus,
    },
}

fn append_progress(path: Option<&Path>, record: &CategoryProgressRecord<'_>) -> Result<(), String> {
    let Some(path) = path else {
        return Ok(());
    };
    let mut rendered = serde_json::to_vec(record)
        .map_err(|error| format!("serialize OWASP progress record: {error}"))?;
    rendered.push(b'\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("open OWASP progress {}: {error}", path.display()))?;
    file.write_all(&rendered)
        .map_err(|error| format!("append OWASP progress {}: {error}", path.display()))?;
    file.sync_data()
        .map_err(|error| format!("sync OWASP progress {}: {error}", path.display()))
}

/// One diagnostic as the artifact records it, with the number of diagnostics it
/// stands for when the per-policy cap folded its reason family (#2356).
///
/// Without the count a folded entry reads like a single site, which is exactly
/// the corpus-scale reading the cap used to make impossible.
fn census_line(message: &str, family_count: u64) -> String {
    if family_count > 1 {
        format!("{message} [x{family_count}]")
    } else {
        message.to_owned()
    }
}

fn load_pack(spec: &PackSpec) -> Result<LoadedPack, String> {
    let source = fs::read(&spec.json_path)
        .map_err(|error| format!("read {}: {error}", spec.json_path.display()))?;
    let compiled = compile_source(SourceFormat::Json, &source, &CompilerOptions::default())
        .map_err(|diagnostics| format!("compile pack {}: {diagnostics:#?}", spec.pack_id))?;
    let evidence = SemanticModelActivationEvidence {
        language: "java".to_owned(),
        ecosystem: spec.ecosystem.clone(),
        package: spec.package.clone(),
        module: None,
        toolchain: Some(jdk_toolchain()),
        target: Some("jvm".to_owned()),
        configuration: None,
        production_input_digest: None,
verified_raw_artifacts: (spec.artifact_sha256.clone()).into_iter().map(|sha256: String| brokk_bifrost_analysis::analyzer::semantic_model::runtime::VerifiedRawArtifact::from_sha256(brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyArtifactRole::Reference, brokk_bifrost_analysis::analyzer::semantic_model::ExternalArtifactKind::JavaClassJar, &sha256)).collect(),
    };
    Ok(LoadedPack {
        pack_id: spec.pack_id.clone(),
        compiled,
        evidence,
    })
}

/// Build the analyzer config: feed the resolved dependency jars as explicit
/// external artifacts so Benchmark types resolve, and keep dependency discovery
/// on metadata mode (read the pom coordinates, never run a build tool).
///
/// The workspace and its dependency-pack activation must share this config.
/// The request-owned JVM reader expects a catalog entry for every dependency
/// and JDK the workspace selects, so an activation that saw fewer jars, or
/// another JDK home, leaves the rest unaccounted and every JVM lookup open
/// (#13851). The JDK is the evidence-only home at `jdk_home`, never the
/// host's `JAVA_HOME`.
fn java_analyzer_config(dependency_jars: &[PathBuf], jdk_home: PathBuf) -> AnalyzerConfig {
    let mut config = AnalyzerConfig::default();
    config.jvm.standard_library_discovery.discover_java_home = false;
    config.jvm.standard_library_discovery.jdk_homes = vec![jdk_home];
    config.jvm.dependency_discovery.mode = JvmDependencyDiscoveryMode::Metadata;
    config.jvm.external_dependencies.artifact_paths = dependency_jars
        .iter()
        .map(|path| JvmExternalArtifact {
            artifact_path: path.clone(),
            ..JvmExternalArtifact::default()
        })
        .collect();
    config
}

/// One edition's workspace and activated packs, ready for the category runs.
struct PreparedSuite {
    /// The root the workspace was built over and the policies evaluate
    /// against: the checkout itself for Java, the staged copy for Python.
    analysis_root: PathBuf,
    workspace: WorkspaceAnalyzer,
    activated_pack_ids: Vec<String>,
    skipped_packs: Vec<(String, String)>,
    activation: SuiteActivation,
    /// Java's evidence-only JDK home, kept until the category runs finish
    /// because the workspace's JDK discovery reads it.
    _jdk_home: Option<tempfile::TempDir>,
}

/// Build the BenchmarkJava workspace over the checkout and activate its
/// curated session packs plus, through the product dependency path, the
/// `bifrost.jdk` release bundle.
fn prepare_java(
    benchmark_root: &Path,
    inputs: &JavaInputs,
    budget: &RetentionBudget,
    timeout: Duration,
) -> Result<PreparedSuite, String> {
    let project = FilesystemProject::new(benchmark_root)
        .map_err(|error| format!("open benchmark project: {error}"))?;
    let project: Arc<dyn Project> = Arc::new(project);
    let jdk_home_root = tempfile::tempdir()
        .map_err(|error| format!("create scratch dir for JDK evidence home: {error}"))?;
    let jdk_home = write_evidence_only_jdk_home(jdk_home_root.path(), JDK_PACK_VERSION)?;
    let analyzer_config = java_analyzer_config(&inputs.dependency_jars, jdk_home);
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun_with_budget(
        project,
        analyzer_config.clone(),
        budget,
    )
    .map_err(|error| format!("build benchmark workspace: {error}"))?;

    // #2558: the catalog is opened at the operator catalog directory
    // carrying the real, pre-installed `bifrost.jdk` release bundle, not an
    // ephemeral in-memory catalog. Session packs (authored
    // sanitizer/summary content) register into this same handle below, so
    // one catalog and one activation request serve both the curated content
    // and the product-path JDK dependency pack. It is read-write because
    // dependency preparation produces packs for the workspace's jars into it;
    // a read-only catalog refuses that production and leaves those jars
    // unaccounted (#13851).
    let catalog = SemanticPackCatalog::open(
        &inputs.jdk_catalog_root,
        CatalogOpenMode::ReadWrite,
        CatalogOptions::default(),
    )
    .map_err(|error| {
        format!(
            "open JDK operator catalog {}: {error}",
            inputs.jdk_catalog_root.display()
        )
    })?;
    let mut evidence = Vec::new();
    let mut controls = Vec::new();
    let mut activated_pack_ids = Vec::new();
    let mut skipped_packs = Vec::new();
    for spec in &inputs.packs {
        let pack = match load_pack(spec) {
            Ok(pack) => pack,
            Err(error) if !spec.mandatory => {
                skipped_packs.push((spec.pack_id.clone(), error));
                continue;
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = catalog.register_session_pack(
            &pack.compiled,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: format!("owasp-benchmark:{}", pack.pack_id),
            },
        ) {
            if spec.mandatory {
                return Err(format!("register pack {}: {error}", pack.pack_id));
            }
            skipped_packs.push((spec.pack_id.clone(), error.to_string()));
            continue;
        }
        // Every shipped pack declares `safety.review_required`, so activation
        // needs an explicit compatible `Enable` control keyed by pack id --
        // matching evidence alone leaves it in `ReviewRequired` (inactive). We
        // both supply the evidence and enable the pack, so the run resolves the
        // full set active.
        controls.push(enable_pack(&pack.pack_id));
        evidence.push(pack.evidence);
        activated_pack_ids.push(pack.pack_id);
    }
    let request = SemanticModelActivationRequest {
        host_activation:
            brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
        approximate_standard_libraries: Vec::new(),
        bifrost_version: bifrost_version()?,
        evidence,
        controls,
        limits: SemanticModelRuntimeLimits::default(),
    };

    // #2558: activate `request` together with the dependency packs through
    // the product activation path. The JDK pack is mandatory, like the curated
    // packs above: a refusal here (discovery incomplete, or the
    // declaration-scoped completeness gate declining the installed pack)
    // aborts the run rather than silently scoring without the JDK pack.
    let jdk_activation_cancellation = CancellationToken::new().with_timeout(timeout);
    let jdk_preparation = activate_jdk_dependency_pack(
        &workspace,
        &analyzer_config,
        JDK_PACK_VERSION,
        &catalog,
        request,
        &jdk_activation_cancellation,
    )?;
    let jdk_dependency_id = jdk_dependency_id(JDK_PACK_VERSION);
    let jdk_pack = jdk_preparation
        .installed_packs
        .iter()
        .find(|pack| pack.dependency_id == jdk_dependency_id)
        .expect("activate_jdk_dependency_pack refuses a run without the JDK pack");
    activated_pack_ids.push("bifrost.jdk".to_owned());
    let jdk_pack_gaps = jdk_pack.gaps;
    let unprepared_dependencies = jdk_preparation
        .failures
        .iter()
        .map(|failure| format!("{}: {:?}", failure.dependency_id, failure.cause))
        .collect();
    Ok(PreparedSuite {
        analysis_root: benchmark_root.to_path_buf(),
        workspace,
        activated_pack_ids,
        skipped_packs,
        activation: SuiteActivation::Java {
            jdk_pack_gaps,
            unprepared_dependencies,
        },
        _jdk_home: Some(jdk_home_root),
    })
}

/// An explicit workspace `Enable` control for one pack.
fn enable_pack(pack_id: &str) -> SemanticModelActivationControl {
    SemanticModelActivationControl {
        scope: SemanticModelControlScope::Workspace,
        action: SemanticModelControlAction::Enable,
        selector: SemanticModelPackSelector {
            pack_id: pack_id.to_owned(),
            version: None,
            manifest_digest: None,
        },
    }
}

fn bifrost_version() -> Result<Version, String> {
    Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|error| format!("parse bifrost version: {error}"))
}

/// Run the whole bakeoff: build the workspace, activate the packs, run one
/// taint policy per category, map findings and completions back to
/// cases, and score.
pub fn run(config: &RunConfig) -> Result<RunResult, String> {
    let suite = config.suite();
    let csv_path = config.benchmark_root.join(suite.expected_results_file);
    let csv = fs::read_to_string(&csv_path)
        .map_err(|error| format!("read {}: {error}", csv_path.display()))?;
    let mut label_set = parse_expected_results(suite, &csv)?;
    if let Some(limit) = config.case_limit {
        label_set.cases.truncate(limit);
    }
    let labels: BTreeMap<String, CaseLabel> = label_set
        .cases
        .iter()
        .map(|case| (case.name.clone(), case.clone()))
        .collect();

    // One benchmark run owns its retention budget.
    let budget = RetentionBudget::new(AnalyzerConfig::default().retention_budget_bytes());
    let PreparedSuite {
        analysis_root,
        workspace,
        activated_pack_ids,
        skipped_packs,
        activation,
        _jdk_home,
    } = match &config.inputs {
        SuiteInputs::Java(inputs) => {
            prepare_java(&config.benchmark_root, inputs, &budget, config.timeout)?
        }
        SuiteInputs::Python(inputs) => {
            prepare_python(&config.benchmark_root, inputs, &budget, config.timeout)?
        }
    };

    // The same measurement `PolicyCoordinator` takes to scale its budget lanes:
    // the on-disk size of every analyzed file. Recording it makes the run's
    // budget lanes reproducible from the artifact alone.
    let analyzed = workspace.analyzer().analyzed_files();
    let analyzed_files = analyzed.len();
    let analyzed_source_bytes: u64 = analyzed
        .iter()
        .map(|file| {
            fs::metadata(file.abs_path())
                .map(|metadata| metadata.len())
                .unwrap_or(0)
        })
        .sum();

    append_progress(
        config.progress_path.as_deref(),
        &CategoryProgressRecord::PacksActivated {
            activated: &activated_pack_ids,
            skipped: &skipped_packs,
            activation: &activation,
        },
    )?;
    eprintln!(
        "[owasp-progress] activated packs: {activated_pack_ids:?}; skipped packs: \
         {skipped_packs:?}; activation: {activation:?}"
    );

    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 1, 1).expect("a fixed evaluation date"),
    );

    // Accumulate per-case state across the category runs.
    let mut flagged: BTreeMap<String, InjectionCategory> = BTreeMap::new();
    let mut case_completion: BTreeMap<String, CaseCompletion> = BTreeMap::new();
    // Per case, the distinct reasons its retained analyses gave for not
    // concluding. Written to the per-case dump so the abstention families can
    // be counted exactly rather than sampled from capped diagnostics.
    let mut case_reasons: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut findings_total = 0usize;
    let mut taint_roots = 0usize;
    let mut category_runs = Vec::new();
    let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
    let mut uncovered_cases = BTreeMap::new();
    for category in suite.categories() {
        for selector in suite
            .coverage_gaps(category)
            .filter_map(|gap| gap.uncovered)
        {
            if !uncovered_cases.contains_key(selector) {
                let located = locate_uncovered_cases(&workspace, &flow_state, selector);
                eprintln!("[owasp-progress] coverage gap {selector}: {located:?}");
                uncovered_cases.insert(selector, located);
            }
        }
    }
    let workspace_run = WorkspaceRun {
        analysis_root: &analysis_root,
        workspace: &workspace,
        flow_state: &flow_state,
        options: &options,
        budget: &budget,
    };

    let category_count = suite.categories().count();
    for (category_index, category) in suite.categories().enumerate() {
        let ordinal = category_index + 1;
        append_progress(
            config.progress_path.as_deref(),
            &CategoryProgressRecord::CategoryStarted {
                category: category.label(),
                ordinal,
                total: category_count,
                timeout_secs: config.timeout.as_secs(),
            },
        )?;
        eprintln!(
            "[owasp-progress] category {ordinal}/{} started: {}",
            category_count,
            category.label()
        );
        let policy = build_policy(suite, category, config.call_modeling);
        let evaluation = evaluate_policy(
            &workspace_run,
            policy_id(suite, category, config.call_modeling),
            &policy,
            category.label(),
            config.timeout,
        )?;
        let category_status = evaluation.status;
        // A finding on a case's file, in this category's run, flags that case
        // for this category.
        for finding in &evaluation.findings {
            findings_total += 1;
            if let Some(name) = case_name_from_path(&finding.path)
                && labels
                    .get(&name)
                    .is_some_and(|label| label.category == category)
            {
                flagged.insert(name, category);
            }
        }

        // Per-root completion: attribute each retained analysis to the case
        // whose file holds its root, taking the worst completion per case.
        for root in evaluation.roots {
            taint_roots += 1;
            let Some(name) = case_name_from_path(&root.path) else {
                continue;
            };
            if labels
                .get(&name)
                .is_none_or(|label| label.category != category)
            {
                continue;
            }
            case_reasons
                .entry(name.clone())
                .or_default()
                .extend(root.reasons);
            merge_completion(&mut case_completion, name, root.completion);
        }

        append_progress(
            config.progress_path.as_deref(),
            &CategoryProgressRecord::CategoryCompleted {
                ordinal,
                total: category_count,
                status: &category_status,
            },
        )?;
        eprintln!(
            "[owasp-progress] category {ordinal}/{} completed: {} completion={} termination={:?} findings={} retained={}",
            category_count,
            category_status.category,
            category_status.completion,
            category_status.termination,
            category_status.findings,
            category_status.retained_analyses
        );
        category_runs.push(category_status);
    }

    let observations: Vec<CaseObservation> = label_set
        .cases
        .iter()
        .map(|case| {
            let flagged = flagged.contains_key(&case.name);
            let mut completion = case_completion
                .get(&case.name)
                .copied()
                .unwrap_or(CaseCompletion::NotAnalyzed);
            // A verdict of clean must also rule out the operations the
            // tables leave out; a gap that might hold the case's flow turns
            // the clearance into an abstention.
            if !flagged
                && completion.is_reliable()
                && let Some(gap) = suite.coverage_gaps(case.category).find(|gap| {
                    !gap.uncovered.is_some_and(|selector| {
                        matches!(
                            &uncovered_cases[selector],
                            UncoveredCases::Located(cases) if !cases.contains(&case.name)
                        )
                    })
                })
            {
                completion = CaseCompletion::Inconclusive;
                let reason = match gap.uncovered.map(|selector| &uncovered_cases[selector]) {
                    Some(UncoveredCases::Unknown(detail)) => format!(
                        "coverage_gap: {} (selector incomplete: {detail})",
                        gap.reason
                    ),
                    _ => format!("coverage_gap: {}", gap.reason),
                };
                case_reasons
                    .entry(case.name.clone())
                    .or_default()
                    .insert(reason);
            }
            CaseObservation {
                name: case.name.clone(),
                category: case.category,
                is_real: case.is_real,
                flagged,
                completion,
            }
        })
        .collect();

    // Optional per-case dump for diagnosing corpus-scale abstention: one line
    // per case in benchmark order, so a `not_analyzed` cluster at the tail of the
    // run points at an accumulation budget while a scattered one points at a
    // per-case cause. Gated on an env var so it never affects normal runs.
    if let Ok(path) = std::env::var("BIFROST_OWASP_PER_CASE") {
        use std::fmt::Write as _;
        let mut out = String::new();
        for (index, observation) in observations.iter().enumerate() {
            let reasons = case_reasons
                .get(&observation.name)
                .map(|reasons| reasons.iter().cloned().collect::<Vec<_>>().join(","))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "{index}\t{}\t{}\treal={}\tflagged={}\t{:?}\t{reasons}",
                observation.name,
                observation.category.label(),
                observation.is_real,
                observation.flagged,
                observation.completion,
            );
        }
        if let Err(error) = std::fs::write(&path, out) {
            eprintln!("[per-case] failed to write {path}: {error}");
        }
    }

    let scoreboard = score(suite, &observations);

    Ok(RunResult {
        scoreboard,
        label_set,
        activated_pack_ids,
        skipped_packs,
        cases_with_roots: case_completion.len(),
        taint_roots,
        findings_total,
        category_runs,
        analyzed_files,
        analyzed_source_bytes,
        activation,
    })
}

/// One built workspace and everything a policy evaluation against it needs.
/// Every suite's runner builds one per analyzed tree and evaluates its
/// category policies through `evaluate_policy`.
pub(crate) struct WorkspaceRun<'a> {
    pub(crate) analysis_root: &'a Path,
    pub(crate) workspace: &'a WorkspaceAnalyzer,
    pub(crate) flow_state: &'a brokk_bifrost_flow::FlowWorkspaceState,
    pub(crate) options: &'a PolicyEvaluationOptions,
    pub(crate) budget: &'a RetentionBudget,
}

/// What one taint policy's evaluation on one workspace produced, before a
/// suite attributes it to its cases.
pub(crate) struct PolicyEvaluation {
    pub(crate) status: CategoryRunStatus,
    /// Every finding the run reported. A leak reached from several roots is
    /// reported once per root.
    pub(crate) findings: Vec<CodeQueryTaintFinding>,
    /// Every retained analysis root.
    pub(crate) roots: Vec<RootOutcome>,
}

/// One retained taint root: the file that holds it, the completion its
/// propagation reached, and, when it did not complete, why.
pub(crate) struct RootOutcome {
    pub(crate) path: String,
    pub(crate) completion: CaseCompletion,
    /// `status:`, `cause:`, `boundary:`, `edges:` and `termination:` rows; see
    /// the comment where they are built.
    pub(crate) reasons: BTreeSet<String>,
}

/// Evaluate one taint policy against a built workspace, with its own
/// deadline, and collect the run status, the findings and every root's
/// completion.
///
/// Each call gets its own deadline rather than one shared across a suite's
/// categories. A single token minted before a loop is an absolute wall-clock
/// deadline, so whichever categories the earlier ones did not leave time for
/// are cancelled before evaluation and come back as a report with no runs at
/// all, which silently scores every one of their cases `NotAnalyzed`. That is
/// a measurement artifact, not a Bifrost verdict, so the run status records
/// when a deadline is hit.
pub(crate) fn evaluate_policy(
    run: &WorkspaceRun<'_>,
    policy_id: String,
    policy: &str,
    label: &str,
    timeout: Duration,
) -> Result<PolicyEvaluation, String> {
    let cancellation = CancellationToken::new().with_timeout(timeout);
    let inputs = [PolicyEvaluationInput::embedded(
        PolicySourceIdentity::new(policy_id),
        policy,
    )];
    // The models are the snapshot the suite's dependency-pack activation
    // published on the workspace. Acquiring them again from the activation
    // request alone loses what only that publication carries: the dependency
    // packs whose preparation failed, which the JVM reader must see recorded
    // to treat those jars as unknown, and Python's runtime-artifact evidence.
    let outcome = evaluate_policy_inputs_with_analyzer(
        run.analysis_root,
        &inputs,
        run.workspace,
        run.flow_state,
        run.options,
        Some(&cancellation),
        run.budget,
    )
    .map_err(|error| format!("evaluate {label} policy: {error}"))?;
    if std::env::var_os("BIFROST_OWASP_DEBUG").is_some() {
        eprintln!(
            "[debug] {} run: {} taint findings, {} retained analyses",
            label,
            outcome.taint_findings().len(),
            outcome.taint_analysis_results().len(),
        );
        for policy_run in outcome.report().runs() {
            eprintln!(
                "[debug]   run policy={} type={:?} completion={:?} findings={}",
                policy_run.policy_id().as_str(),
                policy_run.analysis_type(),
                policy_run.completion(),
                policy_run.findings().len(),
            );
            for diagnostic in policy_run.diagnostics() {
                eprintln!(
                    "[debug]     run-diagnostic: {}",
                    census_line(diagnostic.message(), diagnostic.family_count()),
                );
            }
        }
        for diagnostic in outcome.report().diagnostics() {
            eprintln!("[debug]   diagnostic: {}", diagnostic.message());
        }
        eprintln!(
            "[debug]   termination={:?} stage={:?}",
            outcome.report().execution().termination(),
            outcome.report().execution().terminal_stage(),
        );
    }

    // Record the run-level taint completion and a few diagnostics so the
    // artifact explains the category's outcome. Report-level diagnostics
    // come first: when the evaluation never reached a run, they are the
    // only account of why, and leaving them out is what made a
    // deadline-dropped category indistinguishable from a clean empty one.
    let termination = outcome
        .report()
        .execution()
        .termination()
        .map(|termination| format!("{termination:?}"));
    let mut sample_diagnostics: Vec<String> = outcome
        .report()
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.message().to_owned())
        .collect();
    let mut completion_label = "no_taint_run".to_owned();
    let mut work = BTreeMap::new();
    for policy_run in outcome.report().runs() {
        completion_label = format!("{:?}", policy_run.completion());
        for diagnostic in policy_run.diagnostics() {
            let message = census_line(diagnostic.message(), diagnostic.family_count());
            if !sample_diagnostics.contains(&message) {
                sample_diagnostics.push(message);
            }
        }
        let report = policy_run.work();
        for (name, value) in [
            ("scanned_files", report.scanned_files()),
            ("scanned_source_bytes", report.scanned_source_bytes()),
            ("fact_nodes", report.fact_nodes()),
            ("pipeline_rows", report.pipeline_rows()),
            ("examined_references", report.examined_references()),
        ] {
            let slot = work.entry(name.to_owned()).or_insert(0);
            *slot = (*slot).max(value);
        }
        for metric in report.metrics() {
            let slot = work.entry(metric.name().to_owned()).or_insert(0);
            *slot = (*slot).max(metric.value());
        }
    }
    let sample_cap = std::env::var("BIFROST_OWASP_SAMPLE_DIAGS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(6);
    sample_diagnostics.truncate(sample_cap);
    let category_status = CategoryRunStatus {
        category: label.to_owned(),
        completion: completion_label,
        termination,
        findings: outcome.taint_findings().len(),
        retained_analyses: outcome.taint_analysis_results().len(),
        sample_diagnostics,
        work,
    };
    let findings = outcome.taint_findings().to_vec();
    let mut roots = Vec::new();
    for result in outcome.taint_analysis_results() {
        let path = result
            .expected_root()
            .artifact()
            .key()
            .path()
            .as_str()
            .to_owned();
        let report = result.report();
        let completion = if report.is_complete() {
            CaseCompletion::Complete
        } else if report.is_proven_by_authored_summaries() {
            CaseCompletion::ProvenBySummary
        } else {
            CaseCompletion::Inconclusive
        };
        // Why this root did not conclude, taken from the plan's own
        // retained cause rather than from the run's diagnostic list. This
        // is the same cause the policy renders into
        // "taint discovery is incomplete: ..."
        // (crates/bifrost-policy/src/taint_policy.rs), but recorded per
        // root: the run's diagnostic list is capped at `MAX_DIAGNOSTICS`
        // (256) per policy, so counting families from it under-counts at
        // corpus scale, while this is uncapped and exact.
        //
        // `cause:` is the one blocking input. `boundary:` rows are the
        // solve's whole incomplete-boundary set, which is a superset: an
        // authored summary can close a boundary that still appears here.
        // Only `cause:` supports an exact family count.
        let mut reasons = BTreeSet::new();
        if !matches!(completion, CaseCompletion::Complete) {
            let coverage = report.result().coverage();
            reasons.insert(format!("status:{}", coverage.semantic_status().label()));
            match result.plan().value_flow().first_incomplete_cause() {
                Some(cause) => {
                    let locator = cause.procedure().semantics().locator();
                    let status = match cause.status() {
                        Some(SemanticInputStatus::Unsupported { capability }) => {
                            format!("unsupported({})", capability.label())
                        }
                        Some(status) => status.label().to_owned(),
                        None => "incomplete-coverage".to_owned(),
                    };
                    reasons.insert(format!(
                        "cause:{}:{status}:{}:{}",
                        cause.label().replace(' ', "-"),
                        locator.path().as_str(),
                        declaration_name(locator),
                    ));
                }
                None => {
                    reasons.insert("cause:none".to_owned());
                }
            }
            for boundary in coverage.boundaries() {
                reasons.insert(format!(
                    "boundary:{}",
                    summary_boundary_label(boundary.kind())
                ));
            }
            if !coverage.unproven_edges().is_empty() {
                reasons.insert("edges:unproven".to_owned());
            }
            if !coverage.partial_edges().is_empty() {
                reasons.insert("edges:partial".to_owned());
            }
            if !report.result().termination().is_fixed_point() {
                reasons.insert(format!("termination:{:?}", report.result().termination()));
            }
        }
        roots.push(RootOutcome {
            path,
            completion,
            reasons,
        });
    }
    Ok(PolicyEvaluation {
        status: category_status,
        findings,
        roots,
    })
}

/// A short, stable label for one incomplete summary boundary, so the per-case
/// dump can be grouped into abstention families by exact string match.
fn summary_boundary_label(kind: &SummaryBoundaryKind) -> String {
    match kind {
        SummaryBoundaryKind::Semantic(status) => match status.unsupported_capability() {
            Some(capability) => format!("semantic:unsupported:{}", capability.label()),
            None => format!("semantic:{}", status.label()),
        },
        SummaryBoundaryKind::Dispatch(kind) => match kind.target_locator() {
            // Name the unreached callee, because for a dispatch boundary the
            // callee is the whole question: which procedure the run would have
            // needed a body or an authored model for.
            Some(locator) => format!("dispatch:{}:{}", kind.label(), declaration_name(locator)),
            None => format!("dispatch:{}", kind.label()),
        },
        SummaryBoundaryKind::Limit(kind) => format!("limit:{kind:?}"),
        SummaryBoundaryKind::Continuation { kind, state } => {
            format!("continuation:{kind:?}:{state:?}")
        }
    }
}

/// The dotted names of a locator's declaration segments, which for a Java
/// callee reads as `Type.method`. Debug-printing the locator instead would put
/// a whole mount digest and every source anchor into every census row.
fn declaration_name(locator: &SemanticLocator) -> String {
    locator
        .declaration()
        .segments()
        .iter()
        .filter_map(|segment| segment.name())
        .collect::<Vec<_>>()
        .join(".")
}

/// The cases whose files contain an operation a coverage gap selects.
#[derive(Debug)]
enum UncoveredCases {
    Located(BTreeSet<String>),
    /// The selector's query did not complete, so no file is known to be free
    /// of the operations.
    Unknown(String),
}

fn locate_uncovered_cases(
    workspace: &WorkspaceAnalyzer,
    flow_state: &brokk_bifrost_flow::FlowWorkspaceState,
    selector: &str,
) -> UncoveredCases {
    let matcher: serde_json::Value =
        serde_json::from_str(selector).expect("a coverage-gap selector is JSON");
    // Only the files matter, but the answer is rows; a selector whose rows
    // exceed the largest limit comes back incomplete and fails closed.
    let query = crate::rql::CodeQuery::from_json(&serde_json::json!({
        "match": matcher,
        "limit": crate::rql::query::MAX_LIMIT,
    }))
    .expect("a coverage-gap selector is a valid CodeQuery match");
    let result = crate::rql::execute_workspace(workspace, flow_state, &query);
    match result.completion() {
        crate::rql::CodeQueryCompletion::Complete => UncoveredCases::Located(
            result
                .results
                .iter()
                .filter_map(|item| match &item.value {
                    crate::rql::CodeQueryResultValue::StructuralMatch { value } => {
                        case_name_from_path(&value.path)
                    }
                    other => panic!("a match query returned a non-match row: {other:?}"),
                })
                .collect(),
        ),
        completion => UncoveredCases::Unknown(format!("{completion:?}: {:?}", result.diagnostics)),
    }
}

/// Take the worst (least reliable) completion seen for a case across roots, so a
/// case counts as reliably cleared only when every root that touched it
/// concluded reliably.
fn merge_completion(
    map: &mut BTreeMap<String, CaseCompletion>,
    name: String,
    completion: CaseCompletion,
) {
    let rank = |c: CaseCompletion| match c {
        CaseCompletion::Complete => 0,
        CaseCompletion::ProvenBySummary => 1,
        CaseCompletion::NotAnalyzed => 2,
        CaseCompletion::Inconclusive => 3,
    };
    map.entry(name)
        .and_modify(|existing| {
            if rank(completion) > rank(*existing) {
                *existing = completion;
            }
        })
        .or_insert(completion);
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn obs(
        name: &str,
        category: InjectionCategory,
        is_real: bool,
        flagged: bool,
        completion: CaseCompletion,
    ) -> CaseObservation {
        CaseObservation {
            name: name.to_owned(),
            category,
            is_real,
            flagged,
            completion,
        }
    }

    #[test]
    fn scoring_separates_naive_and_honest_over_a_fabricated_set() {
        use CaseCompletion::*;
        use InjectionCategory::Sqli;
        // Six sqli cases exercising every outcome x label combination.
        let cases = vec![
            // real, flagged -> TP both ways
            obs("A", Sqli, true, true, Complete),
            // real, cleared (no finding, reliable) -> honest FN; a FALSE GREEN
            obs("B", Sqli, true, false, Complete),
            // real, abstained -> naive FN, honest excluded
            obs("C", Sqli, true, false, Inconclusive),
            // fake, flagged -> FP both ways
            obs("D", Sqli, false, true, Complete),
            // fake, cleared -> TN both ways
            obs("E", Sqli, false, false, ProvenBySummary),
            // fake, abstained -> naive TN, honest excluded
            obs("F", Sqli, false, false, NotAnalyzed),
        ];
        let board = score(&BENCHMARK_JAVA, &cases);
        let sqli = board
            .per_category
            .iter()
            .find(|c| c.category == "sqli")
            .unwrap();

        // Naive: abstentions fold into the negatives.
        assert_eq!(
            sqli.naive,
            Confusion {
                tp: 1,
                fp: 1,
                false_negative: 2, // B (cleared) + C (abstained)
                tn: 2,             // E (cleared) + F (abstained)
            }
        );
        // Honest: abstentions excluded.
        assert_eq!(
            sqli.honest,
            Confusion {
                tp: 1,
                fp: 1,
                false_negative: 1, // only B
                tn: 1,             // only E
            }
        );
        // Rates.
        assert_eq!(sqli.naive_metrics.tpr, Some(0.3333));
        assert_eq!(sqli.honest_metrics.tpr, Some(0.5));
        assert_eq!(sqli.honest_metrics.fpr, Some(0.5));
        assert_eq!(sqli.honest_metrics.youden, Some(0.0));
        // Buckets and the headline false-green count.
        assert_eq!(sqli.real_flagged, 1);
        assert_eq!(sqli.real_cleared, 1);
        assert_eq!(sqli.real_abstained, 1);
        assert_eq!(sqli.fake_abstained, 1);
        assert_eq!(sqli.false_greens, 1);
        assert_eq!(
            sqli.completion,
            CompletionProfile {
                complete: 3,
                proven_by_summary: 1,
                inconclusive: 1,
                not_analyzed: 1,
            }
        );
    }
    #[test]
    fn parse_expected_results_narrows_to_taint_subset() {
        let csv = "# header line\n\
                   BenchmarkTest00001,pathtraver,true,22\n\
                   BenchmarkTest00003,hash,true,328\n\
                   BenchmarkTest00010,sqli,false,89\n\
                   BenchmarkTest00020,crypto,false,327\n";
        let set = parse_expected_results(&BENCHMARK_JAVA, csv).unwrap();
        assert_eq!(set.cases.len(), 2);
        assert_eq!(set.skipped_non_taint.get("hash"), Some(&1));
        assert_eq!(set.skipped_non_taint.get("crypto"), Some(&1));
    }
    #[test]
    #[hardwon("bc1cbe8ea882: OWASP sanitizer policy labels must match sink context")]
    fn benchmark_categories_use_exact_sink_context_hazard_labels() {
        let expected = [
            (InjectionCategory::Sqli, "sql"),
            (InjectionCategory::Cmdi, "shell"),
            (InjectionCategory::Ldapi, "ldap"),
            (InjectionCategory::Pathtraver, "path"),
            (InjectionCategory::Xpathi, "xpath"),
            (InjectionCategory::Xss, "html"),
        ];

        for (category, hazard_label) in expected {
            assert_eq!(category.hazard_label(), hazard_label);
            let policy = build_policy(&BENCHMARK_JAVA, category, UnmodeledCallBehavior::Paranoid);

            assert!(!policy.contains("attacker-controlled"));
            assert_eq!(
                policy.matches(&format!(":labels [{hazard_label}]")).count(),
                BENCHMARK_JAVA.sources.len(),
                "every source must mint the category's hazard label"
            );
            assert_eq!(
                policy
                    .matches(&format!(":accepts [{hazard_label}]"))
                    .count(),
                BENCHMARK_JAVA.sinks(category).len(),
                "every sink must accept only the category's hazard label"
            );
            assert!(policy.contains(&format!(
                ":message \"data carrying {hazard_label} reached a {} sink\"",
                category.label()
            )));
        }
    }
    /// #2558 fail-before: a Partial JDK pack installed with no gap
    /// accounting (the pre-#2401 shape) is exactly the kind of pack
    /// `register_session_pack` accepts without complaint -- it only
    /// validates a pack's own shape and never consults `Completeness`. The
    /// product-path route this module now uses for the JDK pack,
    /// `activate_jdk_dependency_pack`, must refuse the same pack instead of
    /// silently activating it. This proves the harness actually exercises
    /// `prepare_dependency_semantic_packs`'s declaration-scoped completeness
    /// gate for the JDK pack, not just a second copy of the old
    /// no-gate-at-all path.
    #[test]
    #[hardwon("#2558: incomplete JDK packs without gap accounting must fail product activation")]
    fn jdk_pack_activation_refuses_a_gap_unaccounted_partial_pack_where_register_session_pack_would_accept_it()
     {
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            DurablePackSource, DurablePackSourceKind,
        };

        const GAP_UNACCOUNTED_PARTIAL_JDK_PACK: &str = r#"{
          "schema_version": 2,
          "pack_id": "test.fail-before.jdk",
          "version": "21.0.2",
          "producer": { "name": "bifrost-fixture", "version": "1.0.0" },
          "language": "java",
          "ecosystem": "jdk",
          "compatibility": {
            "bifrost": ">=0.8.0, <1.0.0",
            "toolchains": [{ "name": "jdk", "requirement": "=21.0.2" }]
          },
          "provenance": { "source": "test fixture", "revision": "fail-before" },
          "license": "GPL-2.0-only WITH Classpath-exception-2.0",
          "completeness": "partial",
          "safety": { "generated_code_only": false, "review_required": false },
          "shards": [{
            "id": "jdk.core",
            "activation": [{
              "toolchain": { "name": "jdk", "version": "=21.0.2" },
              "targets": ["jvm"]
            }],
            "payload": {
              "kind": "declaration_facts",
              "types": [{
                "id": "jdk.java-util-arraylist",
                "name": "java.util.ArrayList",
                "type_kind": "class",
                "visibility": "public",
                "type_parameters": [],
                "hierarchy": [],
                "aliases": [],
                "extension_surfaces": [],
                "locator": {
                  "kind": "artifact",
                  "path": "java.base/java/util/ArrayList.java",
                  "symbol": "java.util.ArrayList"
                }
              }],
              "members": [],
              "relations": []
            }
          }]
        }"#;

        let pack = compile_source(
            SourceFormat::Json,
            GAP_UNACCOUNTED_PARTIAL_JDK_PACK.as_bytes(),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| panic!("fixture compilation failed: {diagnostics:#?}"));

        // `register_session_pack` -- the mechanism this module used for the
        // JDK pack before #2558, and still uses for authored sanitizer and
        // summary content -- has no completeness gate at all and accepts
        // this Partial, gap-unaccounted pack with no complaint.
        let session_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("open ephemeral catalog");
        session_catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:register-session-pack".to_owned(),
                },
            )
            .expect(
                "register_session_pack must accept a gap-unaccounted Partial pack: it has no \
                 completeness gate to refuse it with (#2401's central finding)",
            );

        // The installed-pack catalog the product path reads from, carrying
        // the same pack installed with NO gap accounting (`catalog.install`,
        // not `catalog.install_release`), matching
        // `partial_jdk_pack_without_gap_accounting_stays_blocked` in
        // `tests/suite_semantic/dependency_pack_version_selection.rs`.
        let installed_catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("open ephemeral catalog");
        installed_catalog
            .install(
                &pack,
                &DurablePackSource {
                    kind: DurablePackSourceKind::PreShipped,
                    source_id: "test:fail-before.jdk@21.0.2".to_owned(),
                },
            )
            .expect("install the fixture pack with no gap accounting");

        let scratch = tempfile::tempdir().expect("scratch dir");
        std::fs::write(scratch.path().join("Main.java"), "final class Main {}")
            .expect("write fixture source");
        let project: Arc<dyn Project> =
            Arc::new(FilesystemProject::new(scratch.path()).expect("open fixture project"));
        let jdk_home_root = tempfile::tempdir().expect("scratch dir for the JDK home");
        let jdk_home = write_evidence_only_jdk_home(jdk_home_root.path(), "21.0.2")
            .expect("write the evidence-only JDK home");
        let analyzer_config = java_analyzer_config(&[], jdk_home);
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, analyzer_config.clone())
                .expect("build ephemeral workspace");
        let cancellation = CancellationToken::new();
        let request = SemanticModelActivationRequest {
            host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
            approximate_standard_libraries: Vec::new(),
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };

        let error = activate_jdk_dependency_pack(
            &workspace,
            &analyzer_config,
            "21.0.2",
            &installed_catalog,
            request,
            &cancellation,
        )
        .expect_err(
            "the product path must refuse a Partial pack with no gap accounting, not silently \
             activate it the way register_session_pack did above",
        );
        assert!(
            error.contains("completeness gate"),
            "the refusal must name the completeness gate: {error}"
        );
    }

    #[test]
    fn progress_records_append_as_independent_json_lines() {
        let scratch = tempfile::tempdir().expect("scratch dir");
        let path = scratch.path().join("progress.jsonl");
        let status = CategoryRunStatus {
            category: "sqli".to_owned(),
            completion: "no_taint_run".to_owned(),
            termination: Some("DeadlineExceeded".to_owned()),
            findings: 0,
            retained_analyses: 0,
            sample_diagnostics: Vec::new(),
            work: BTreeMap::new(),
        };

        append_progress(
            Some(&path),
            &CategoryProgressRecord::CategoryStarted {
                category: "sqli",
                ordinal: 1,
                total: BENCHMARK_JAVA.categories().count(),
                timeout_secs: 3_600,
            },
        )
        .expect("append category start");
        append_progress(
            Some(&path),
            &CategoryProgressRecord::CategoryCompleted {
                ordinal: 1,
                total: BENCHMARK_JAVA.categories().count(),
                status: &status,
            },
        )
        .expect("append category completion");

        let lines = fs::read_to_string(path).expect("read progress stream");
        let records = lines
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid JSON line"))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["event"], "category_started");
        assert_eq!(records[0]["timeout_secs"], 3_600);
        assert_eq!(records[1]["event"], "category_completed");
        assert_eq!(records[1]["termination"], "DeadlineExceeded");
    }

    #[test]
    fn built_policy_carries_sources_sinks_and_call_modeling() {
        let policy = build_policy(
            &BENCHMARK_JAVA,
            InjectionCategory::Sqli,
            UnmodeledCallBehavior::Optimistic,
        );
        assert!(policy.contains(":unmodeled optimistic"));
        assert!(policy.contains("getParameter"));
        assert!(policy.contains("executeQuery"));
        assert!(policy.contains("bifrost.owasp-benchmark.sqli.optimistic"));
        // Every sink selector constrains minimum arity so a no-operand
        // arity-overloaded call (e.g. `PreparedStatement.execute()`) does not
        // collide by name and abort binding (#1935 cause 1). An operand at
        // argument index 0 requires at least one positional argument.
        assert!(policy.contains("(call :callee (name \"executeQuery\") (arity :min 1))"));
        // The sqli policy also models the Spring `JdbcTemplate` lane, which 156
        // benchmark cases sink through; its SQL operand is argument 0 too.
        assert!(policy.contains("(call :callee (name \"queryForObject\") (arity :min 1))"));
        // A pathtraver policy names the file sinks, not the sql ones.
        let pathtraver = build_policy(
            &BENCHMARK_JAVA,
            InjectionCategory::Pathtraver,
            UnmodeledCallBehavior::Paranoid,
        );
        assert!(pathtraver.contains("FileInputStream"));
        assert!(!pathtraver.contains("executeQuery"));
        // The ldapi filter operand sits at argument index 1, so its sink
        // requires at least two positional arguments.
        let ldapi = build_policy(
            &BENCHMARK_JAVA,
            InjectionCategory::Ldapi,
            UnmodeledCallBehavior::Paranoid,
        );
        assert!(ldapi.contains("(call :callee (name \"search\") (arity :min 1))"));
        assert!(ldapi.contains("(call :callee (name \"search\") (arity :min 2))"));
    }

    #[test]
    fn promotion_pins_every_activation() {
        let staged = r#"{
            "schema_version": 2,
            "pack_id": "bifrost.esapi-sanitizers",
            "provenance": { "source": "staged", "revision": "k3" },
            "shards": [
                { "activation": [ { "package": { "name": "org.owasp.esapi:esapi" }, "targets": ["jvm"], "configurations": [] } ], "payload": {} }
            ]
        }"#;
        let digest = "2288e84a6c93a457c5215eb8028c87ebd4326a515e21545d2e02db8356d6ccff";
        let pinned = promote_staged_sanitizer_pack(staged, digest).unwrap();
        let value: serde_json::Value = serde_json::from_str(&pinned).unwrap();
        let activation = &value["shards"][0]["activation"][0];
        assert_eq!(activation["artifact_sha256"], serde_json::json!(digest));
        assert!(
            value["provenance"]["source"]
                .as_str()
                .unwrap()
                .contains(digest)
        );
    }
}
