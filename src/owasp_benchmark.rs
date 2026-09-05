//! OWASP Benchmark (Java) taint bakeoff scorer.
//!
//! This module scores Bifrost's `require-model` taint analysis against the
//! labeled OWASP BenchmarkJava corpus. It lives in the facade for the same
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
//! The second half is the live runner: it parses the Benchmark's
//! `expectedresults-1.2.csv`, builds one workspace analyzer over the Benchmark
//! source (with the built classpath fed in so types resolve), activates the
//! shipped Java sanitizer packs plus the pinned ESAPI pack, runs one
//! `require-model` taint policy per injection category through the production
//! evaluator, maps each finding and each per-root completion back to its case,
//! and feeds the pure core. The whole run is a measurement performed once; the
//! artifact it writes is committed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use semver::Version;
use serde::Serialize;

use brokk_bifrost_analysis::analyzer::semantic::SemanticLocator;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    CatalogCoordinate, CatalogOpenMode, CatalogOptions, CompiledSemanticModelPack, CompilerOptions,
    DependencyPackLimits, DependencyPackPreparationOutcome, SemanticModelActivationControl,
    SemanticModelActivationEvidence, SemanticModelActivationRequest, SemanticModelControlAction,
    SemanticModelControlScope, SemanticModelPackSelector, SemanticModelRuntimeLimits,
    SemanticPackCatalog, SessionPackSource, SessionPackSourceKind, SourceFormat, compile_source,
};
use brokk_bifrost_analysis::{
    AnalyzerConfig, CancellationToken, DependencyPackEcosystem, DependencyPackWorkspaceContext,
    FilesystemProject, JvmDependencyDiscoveryMode, JvmExternalArtifact, Project, WorkspaceAnalyzer,
};
use brokk_bifrost_flow::dataflow::{SemanticInputStatus, SummaryBoundaryKind};
use brokk_bifrost_policy::{
    PolicyEvaluationDate, PolicyEvaluationInput, PolicyEvaluationOptions,
    PolicySemanticModelContext, PolicySourceIdentity,
    evaluate_policy_inputs_with_analyzer_and_semantic_models,
};

// ===========================================================================
// Pure scoring core
// ===========================================================================

/// The injection categories Bifrost's taint policy addresses. These are exactly
/// the OWASP Benchmark categories that are taint-flow problems (a source reaches
/// a sink). The Benchmark's other categories (crypto, hash, weakrand,
/// securecookie, trustbound) are not source-to-sink taint problems and are
/// deliberately out of scope for this bakeoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionCategory {
    Sqli,
    Cmdi,
    Ldapi,
    Pathtraver,
    Xpathi,
    Xss,
}

impl InjectionCategory {
    /// The scored categories, in a fixed canonical order so the artifact is
    /// byte-stable across runs.
    pub const ALL: [InjectionCategory; 6] = [
        InjectionCategory::Sqli,
        InjectionCategory::Cmdi,
        InjectionCategory::Ldapi,
        InjectionCategory::Pathtraver,
        InjectionCategory::Xpathi,
        InjectionCategory::Xss,
    ];

    /// The Benchmark's own category token, as it appears in
    /// `expectedresults-1.2.csv`.
    pub const fn label(self) -> &'static str {
        match self {
            InjectionCategory::Sqli => "sqli",
            InjectionCategory::Cmdi => "cmdi",
            InjectionCategory::Ldapi => "ldapi",
            InjectionCategory::Pathtraver => "pathtraver",
            InjectionCategory::Xpathi => "xpathi",
            InjectionCategory::Xss => "xss",
        }
    }

    /// The taint label minted by this category's source endpoints and accepted
    /// by its sink endpoints. These labels are the sanitizer pack's
    /// sink-context vocabulary, rather than the Benchmark category tokens.
    pub const fn hazard_label(self) -> &'static str {
        match self {
            InjectionCategory::Sqli => "sql",
            InjectionCategory::Cmdi => "shell",
            InjectionCategory::Ldapi => "ldap",
            InjectionCategory::Pathtraver => "path",
            InjectionCategory::Xpathi => "xpath",
            InjectionCategory::Xss => "html",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.label() == label)
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
    /// The `require-model` analysis abstained: an unmodeled boundary on the flow
    /// prevented a reliable verdict.
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
        let denom = self.positives();
        (denom > 0).then(|| f64::from(self.tp) / f64::from(denom))
    }

    /// False-positive rate (1 - specificity). None when there are no fakes.
    fn fpr(&self) -> Option<f64> {
        let denom = self.negatives();
        (denom > 0).then(|| f64::from(self.fp) / f64::from(denom))
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

/// Score a set of observations into per-category matrices plus an aggregate.
pub fn score(observations: &[CaseObservation]) -> Scoreboard {
    let per_category: Vec<CategoryScore> = InjectionCategory::ALL
        .into_iter()
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

/// One row of `expectedresults-1.2.csv`, narrowed to the taint subset.
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

/// Parse `expectedresults-1.2.csv`. The format is one header line beginning
/// with `#`, then rows of `name,category,real,cwe`.
pub fn parse_expected_results(csv: &str) -> Result<LabelSet, String> {
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
        match InjectionCategory::from_label(category_token) {
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

/// Extract `BenchmarkTestNNNNN` from a workspace-relative Java path, using the
/// path's own file stem rather than string scanning. Returns `None` for a path
/// that is not a Benchmark test file.
fn case_name_from_path(path: &str) -> Option<String> {
    let stem = Path::new(path).file_stem()?.to_str()?;
    stem.starts_with("BenchmarkTest").then(|| stem.to_owned())
}

// ===========================================================================
// Per-category require-model policies
// ===========================================================================

/// One sink endpoint: the callee name to match and how to select its operand.
struct Sink {
    callee: &'static str,
    selector: SinkSelector,
}

/// How a sink identifies the call whose operand it observes.
///
/// Most Benchmark endpoints are intentionally broad name selectors. The
/// PrintWriter formatting overloads are different: their payload formals move
/// when Locale is present, so those endpoints use the exact call-binding
/// relation and let the compiler map the selected formal back to each written
/// caller-side actual.
enum SinkSelector {
    Name {
        argument: u32,
    },
    ExactCallBinding {
        model_id: &'static str,
        formal_name: &'static str,
    },
}

/// The attacker-controlled sources, shared by every category. These are the
/// servlet-request and cookie APIs the Benchmark actually reads from, matched by
/// callee name; the name selector binds structurally and needs no type
/// resolution.
const SOURCE_CALLEES: &[&str] = &[
    "getParameter",
    "getParameterValues",
    "getParameterMap",
    "getParameterNames",
    "getHeader",
    "getHeaders",
    "getHeaderNames",
    "getQueryString",
    "getRequestURI",
    "getRequestURL",
    "getPathInfo",
    "getServletPath",
    "getCookies",
    "getValue",
    "getenv",
];

fn category_sinks(category: InjectionCategory) -> Vec<Sink> {
    let s = |callee, argument| Sink {
        callee,
        selector: SinkSelector::Name { argument },
    };
    let exact = |callee, model_id, formal_name| Sink {
        callee,
        selector: SinkSelector::ExactCallBinding {
            model_id,
            formal_name,
        },
    };
    match category {
        // The JDBC lane (`prepareStatement` .. `addBatch`) plus the Spring
        // `JdbcTemplate` lane. The Benchmark routes 156 of its `sqli` cases
        // through `DatabaseHelper.JDBCtemplate`, whose query family takes the
        // SQL text as positional argument 0 in every overload the corpus uses:
        // `queryForObject(sql, Class)` / `queryForObject(sql, Object[], Class)`,
        // `query(sql, RowMapper)`, `queryForList(sql)`, `queryForMap(sql)`,
        // `queryForRowSet(sql)` and `batchUpdate(sql)`. `JdbcTemplate.execute`
        // is already covered by the JDBC `execute` entry above.
        InjectionCategory::Sqli => vec![
            s("prepareStatement", 0),
            s("prepareCall", 0),
            s("execute", 0),
            s("executeQuery", 0),
            s("executeUpdate", 0),
            s("executeLargeUpdate", 0),
            s("addBatch", 0),
            s("query", 0),
            s("queryForObject", 0),
            s("queryForList", 0),
            s("queryForMap", 0),
            s("queryForRowSet", 0),
            s("batchUpdate", 0),
        ],
        InjectionCategory::Cmdi => vec![s("exec", 0), s("command", 0), s("ProcessBuilder", 0)],
        // DirContext.search(name, filter, ...): both the distinguished name and
        // the search filter are injectable, so both operands are sinks.
        InjectionCategory::Ldapi => vec![s("search", 0), s("search", 1)],
        InjectionCategory::Pathtraver => vec![
            s("File", 0),
            s("FileInputStream", 0),
            s("FileOutputStream", 0),
            s("RandomAccessFile", 0),
            s("FileReader", 0),
            s("FileWriter", 0),
            s("get", 0),
            s("newInputStream", 0),
            s("getResourceAsStream", 0),
        ],
        InjectionCategory::Xpathi => vec![s("evaluate", 0), s("compile", 0)],
        InjectionCategory::Xss => vec![
            exact("println", "member.printwriter.println-string", "x"),
            exact("print", "member.printwriter.print-string", "s"),
            exact("write", "member.printwriter.write-string", "s"),
            exact("format", "member.printwriter.format-format", "format"),
            exact("format", "member.printwriter.format-format", "args"),
            exact(
                "format",
                "member.printwriter.format-locale-format",
                "format",
            ),
            exact("format", "member.printwriter.format-locale-format", "args"),
            exact("printf", "member.printwriter.printf-format", "format"),
            exact("printf", "member.printwriter.printf-format", "args"),
            exact(
                "printf",
                "member.printwriter.printf-locale-format",
                "format",
            ),
            exact("printf", "member.printwriter.printf-locale-format", "args"),
            s("append", 0),
        ],
    }
}

/// The policy id for one category, stable and auditable.
pub fn policy_id(category: InjectionCategory) -> String {
    format!("bifrost.owasp-benchmark.{}.require-model", category.label())
}

/// Build the `require-model` taint policy source for one category. Every policy
/// shares the source set and differs only in its sink set, so a finding
/// attributes unambiguously to the category whose policy produced it.
pub fn build_policy(category: InjectionCategory) -> String {
    let hazard_label = category.hazard_label();
    let mut sources = String::new();
    for (index, callee) in SOURCE_CALLEES.iter().enumerate() {
        sources.push_str(&format!(
            "          (source :id src-{index} :display-name {callee:?}\n\
             \x20           :categories [input.user-controlled io.external]\n\
             \x20           :selector (rql :schema-version 1\n\
             \x20             (language java (call :callee (name {callee:?}))))\n\
             \x20           :bind return-value :labels [{hazard_label}])\n"
        ));
    }
    let mut sinks = String::new();
    for (index, sink) in category_sinks(category).into_iter().enumerate() {
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
                     \x20             (language java (call :callee (name {callee:?}) (arity :min {min_arity}))))\n\
                     \x20           :dangerous-operand (argument :index {argument}) :accepts [{hazard_label}])\n"
                ));
            }
            SinkSelector::ExactCallBinding {
                model_id,
                formal_name,
            } => {
                // Keep the call-binding row as the endpoint's output. The
                // `call-argument` derivation filters by the exact declared
                // formal, while taint endpoint lowering remaps that formal to
                // the caller-side actual index recorded in the row. This is
                // essential for Locale-first and variadic overloads: Locale is
                // formal 0, format is formal 1, and every written vararg maps
                // to formal 2.
                let display_name = format!("{callee} {formal_name}");
                sinks.push_str(&format!(
                    "          (sink :id snk-{index} :display-name {display_name:?}\n\
                     \x20           :categories [data.sensitive]\n\
                     \x20           :selector (row-selector :output calls\n\
                     \x20             (bind :name calls :query\n\
                     \x20               (rql :schema-version 1\n\
                     \x20                 (language java\n\
                     \x20                   (call-bindings (call-shape (call :callee (name {callee:?})))))))\n\
                     \x20             (call :over calls :resolves-to {model_id} :proof declared)\n\
                     \x20             (call-argument :over calls :formal-name {formal_name:?}))\n\
                     \x20           :dangerous-operand (argument :name {formal_name:?}) :accepts [{hazard_label}])\n",
                ));
            }
        }
    }
    let id = policy_id(category);
    let taxonomy_id = format!("BENCHMARK-{}", category.label().to_uppercase());
    format!(
        "(policy\n\
        \x20 :schema-version 1\n\
        \x20 :id {id:?}\n\
        \x20 :name \"OWASP Benchmark {label} (require-model)\"\n\
        \x20 :message \"data carrying {hazard_label} reached a {label} sink\"\n\
        \x20 :severity warning\n\
        \x20 :analysis (analysis\n\
        \x20   :type taint\n\
        \x20   :mode may\n\
        \x20   :call-modeling (call-modeling :unmodeled require-model)\n\
        \x20   :sources (endpoint-set :entries [\n{sources}          ])\n\
        \x20   :sinks (endpoint-set :entries [\n{sinks}          ]))\n\
        \x20 :classification (classification\n\
        \x20   :fallback (classification-id :taxonomy \"OWASP\" :id {taxonomy_id:?})))\n",
        label = category.label(),
        hazard_label = hazard_label,
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
/// procedure-summary pack -- every pack the require-model run needs to close a
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

/// The exact JDK release the pinned `bifrost.jdk` pack targets
/// (`semantic-packs/jvm/temurin-jdk-21.0.8+9.json`). The installed pack's own
/// activation selector requires this exact version, so a caller who wants a
/// different JDK release needs a differently pinned pack, not a flag here.
const JDK_PACK_VERSION: &str = "21.0.8";

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
/// installed (`bifrost-semantic-pack install <bundle> <catalog>`); this
/// function never installs or mutates it. On success, returns `request` with
/// the JDK's own dependency evidence folded in (so the caller's later
/// per-category resolution sees it) and the preparation outcome (for
/// completeness/gap reporting). On any refusal -- discovery incomplete, or
/// the completeness gate declining the installed pack -- returns `Err`
/// naming the reason; this function never silently drops the JDK from the
/// active set.
pub fn activate_jdk_dependency_pack(
    workspace: &WorkspaceAnalyzer,
    catalog: &SemanticPackCatalog,
    request: SemanticModelActivationRequest,
    jdk_version: &str,
    cancellation: &CancellationToken,
) -> Result<
    (
        SemanticModelActivationRequest,
        DependencyPackPreparationOutcome,
    ),
    String,
> {
    let scratch = tempfile::tempdir()
        .map_err(|error| format!("create scratch dir for JDK evidence home: {error}"))?;
    let jdk_home = write_evidence_only_jdk_home(scratch.path(), jdk_version)?;

    let mut jdk_config = AnalyzerConfig::default();
    jdk_config.jvm.dependency_discovery.mode = JvmDependencyDiscoveryMode::Disabled;
    jdk_config.jvm.standard_library_discovery.discover_java_home = false;
    jdk_config.jvm.standard_library_discovery.jdk_homes = vec![jdk_home];

    let outcome = workspace.activate_dependency_packs(
        &jdk_config,
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
    if !preparation.complete {
        return Err(format!(
            "JDK dependency-pack preparation was refused by the declaration-scoped \
             completeness gate: {:?}",
            preparation.diagnostics
        ));
    }
    let merged = preparation
        .compose_activation_request(request)
        .ok_or_else(|| {
            "JDK dependency-pack preparation produced no activation evidence".to_owned()
        })?;
    Ok((merged, preparation))
}

/// Configuration for one live run.
pub struct RunConfig {
    /// The built Benchmark checkout root.
    pub benchmark_root: PathBuf,
    /// The directory of resolved dependency jars (Maven `target/dependency`),
    /// fed to the analyzer so Benchmark types resolve. Empty to skip.
    pub dependency_jars: Vec<PathBuf>,
    /// The packs to activate. Each is registered as a session pack, given
    /// matching activation evidence, and enabled with an explicit `Enable`
    /// control (every shipped pack declares `safety.review_required`, so an
    /// enable control is what lets it resolve as active).
    pub packs: Vec<PackSpec>,
    /// Wall-clock budget for each category's taint run.
    pub timeout: Duration,
    /// Optional cap on the number of cases scored, for a smoke run. `None`
    /// scores the whole subset.
    pub case_limit: Option<usize>,
    /// #2558: an operator catalog directory with the real `bifrost.jdk`
    /// release bundle already installed
    /// (`bifrost-semantic-pack install <bundle> <this dir>`). The JDK
    /// declaration pack activates from here through the product dependency
    /// path (`activate_jdk_dependency_pack`), not as a curated session pack.
    /// Opened read-only: a run never installs into or otherwise mutates it.
    pub jdk_catalog_root: PathBuf,
    /// Optional append-only JSON Lines progress stream. The binary initializes
    /// this with run provenance; the live runner then syncs category start and
    /// completion records as they occur.
    pub progress_path: Option<PathBuf>,
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
    /// #2558: the named warning-grade extraction gaps the activated
    /// `bifrost.jdk` release bundle carries (3,791 for `bifrost.jdk@21.0.8`,
    /// per the #2401 verification). A reference to a gapped declaration
    /// degrades to a typed `PackExtractionGap` incomplete reason rather than
    /// a false absence proof; this count is the honesty budget the product
    /// activation path enforces, restated here so it is visible in the
    /// artifact rather than only in a log line.
    pub jdk_pack_gaps: usize,
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
        jdk_pack_gaps: usize,
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
        artifact_sha256: spec.artifact_sha256.clone(),
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
fn run_analyzer_config(dependency_jars: &[PathBuf]) -> AnalyzerConfig {
    let mut config = AnalyzerConfig::default();
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

/// Run the whole bakeoff: build the workspace, activate the packs, run one
/// require-model policy per category, map findings and completions back to
/// cases, and score.
pub fn run(config: &RunConfig) -> Result<RunResult, String> {
    let csv_path = config.benchmark_root.join("expectedresults-1.2.csv");
    let csv = fs::read_to_string(&csv_path)
        .map_err(|error| format!("read {}: {error}", csv_path.display()))?;
    let mut label_set = parse_expected_results(&csv)?;
    if let Some(limit) = config.case_limit {
        label_set.cases.truncate(limit);
    }
    let labels: BTreeMap<String, CaseLabel> = label_set
        .cases
        .iter()
        .map(|case| (case.name.clone(), case.clone()))
        .collect();

    let project = FilesystemProject::new(&config.benchmark_root)
        .map_err(|error| format!("open benchmark project: {error}"))?;
    let project: Arc<dyn Project> = Arc::new(project);
    let analyzer_config = run_analyzer_config(&config.dependency_jars);
    let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(project, analyzer_config)
        .map_err(|error| format!("build benchmark workspace: {error}"))?;

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

    // #2558: the catalog is opened read-only at the operator catalog
    // directory carrying the real, pre-installed `bifrost.jdk` release
    // bundle, not an ephemeral in-memory catalog. Session packs (authored
    // sanitizer/summary content) register into this same handle below, so
    // one catalog and one activation request serve both the curated content
    // and the product-path JDK dependency pack.
    let catalog = SemanticPackCatalog::open(
        &config.jdk_catalog_root,
        CatalogOpenMode::ReadOnly,
        CatalogOptions::default(),
    )
    .map_err(|error| {
        format!(
            "open JDK operator catalog {}: {error}",
            config.jdk_catalog_root.display()
        )
    })?;
    let mut evidence = Vec::new();
    let mut controls = Vec::new();
    let mut activated_pack_ids = Vec::new();
    let mut skipped_packs = Vec::new();
    for spec in &config.packs {
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
        controls.push(SemanticModelActivationControl {
            scope: SemanticModelControlScope::Workspace,
            action: SemanticModelControlAction::Enable,
            selector: SemanticModelPackSelector {
                pack_id: pack.pack_id.clone(),
                version: None,
                manifest_digest: None,
            },
        });
        evidence.push(pack.evidence);
        activated_pack_ids.push(pack.pack_id);
    }
    let request = SemanticModelActivationRequest {
        bifrost_version: Version::parse(env!("CARGO_PKG_VERSION"))
            .map_err(|error| format!("parse bifrost version: {error}"))?,
        evidence,
        controls,
        limits: SemanticModelRuntimeLimits::default(),
    };

    // #2558: fold the JDK dependency pack's own evidence into `request`
    // through the product activation path. Mandatory, like the curated
    // packs above: a refusal here (discovery incomplete, or the
    // declaration-scoped completeness gate declining the installed pack)
    // aborts the run rather than silently scoring without the JDK pack.
    let jdk_activation_cancellation = CancellationToken::new().with_timeout(config.timeout);
    let (request, jdk_preparation) = activate_jdk_dependency_pack(
        &workspace,
        &catalog,
        request,
        JDK_PACK_VERSION,
        &jdk_activation_cancellation,
    )?;
    activated_pack_ids.extend(
        jdk_preparation
            .installed_packs
            .iter()
            .map(|_| "bifrost.jdk".to_owned()),
    );
    let jdk_pack_gaps: usize = jdk_preparation
        .installed_packs
        .iter()
        .map(|pack| pack.gaps)
        .sum();
    append_progress(
        config.progress_path.as_deref(),
        &CategoryProgressRecord::PacksActivated {
            activated: &activated_pack_ids,
            skipped: &skipped_packs,
            jdk_pack_gaps,
        },
    )?;
    eprintln!(
        "[owasp-progress] activated packs: {:?}; skipped packs: {:?}; JDK gaps: {jdk_pack_gaps}",
        activated_pack_ids, skipped_packs
    );

    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 1, 1).expect("a fixed evaluation date"),
    );

    // Accumulate per-case state across the six category runs.
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

    for (category_index, category) in InjectionCategory::ALL.into_iter().enumerate() {
        // One deadline per category, not one shared across all six. A single
        // token minted before the loop is an absolute wall-clock deadline, so
        // whichever categories the earlier ones did not leave time for are
        // cancelled before evaluation and come back as a report with no runs
        // at all -- silently scoring every one of their cases `NotAnalyzed`.
        // That is a measurement artifact, not a Bifrost verdict, so each
        // category gets its own budget and the artifact records when one is
        // hit.
        let ordinal = category_index + 1;
        append_progress(
            config.progress_path.as_deref(),
            &CategoryProgressRecord::CategoryStarted {
                category: category.label(),
                ordinal,
                total: InjectionCategory::ALL.len(),
                timeout_secs: config.timeout.as_secs(),
            },
        )?;
        eprintln!(
            "[owasp-progress] category {ordinal}/{} started: {}",
            InjectionCategory::ALL.len(),
            category.label()
        );
        let cancellation = CancellationToken::new().with_timeout(config.timeout);
        let policy = build_policy(category);
        let inputs = [PolicyEvaluationInput::embedded(
            PolicySourceIdentity::new(policy_id(category)),
            &policy,
        )];
        let outcome = evaluate_policy_inputs_with_analyzer_and_semantic_models(
            &config.benchmark_root,
            &inputs,
            &workspace,
            &flow_state,
            &options,
            PolicySemanticModelContext {
                catalog: &catalog,
                request: &request,
                persistence: None,
            },
            Some(&cancellation),
        )
        .map_err(|error| format!("evaluate {} policy: {error}", category.label()))?;

        if std::env::var_os("BIFROST_OWASP_DEBUG").is_some() {
            eprintln!(
                "[debug] {} run: {} taint findings, {} retained analyses",
                category.label(),
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
            category: category.label().to_owned(),
            completion: completion_label,
            termination,
            findings: outcome.taint_findings().len(),
            retained_analyses: outcome.taint_analysis_results().len(),
            sample_diagnostics,
            work,
        };
        // A finding on a case's file, in this category's run, flags that case
        // for this category.
        for finding in outcome.taint_findings() {
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
        for result in outcome.taint_analysis_results() {
            taint_roots += 1;
            let root_path = result.expected_root().artifact().key().path();
            let Some(name) = case_name_from_path(root_path.as_str()) else {
                continue;
            };
            if labels
                .get(&name)
                .is_none_or(|label| label.category != category)
            {
                continue;
            }
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
            let reasons = case_reasons.entry(name.clone()).or_default();
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
            merge_completion(&mut case_completion, name, completion);
        }

        append_progress(
            config.progress_path.as_deref(),
            &CategoryProgressRecord::CategoryCompleted {
                ordinal,
                total: InjectionCategory::ALL.len(),
                status: &category_status,
            },
        )?;
        eprintln!(
            "[owasp-progress] category {ordinal}/{} completed: {} completion={} termination={:?} findings={} retained={}",
            InjectionCategory::ALL.len(),
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
        .map(|case| CaseObservation {
            name: case.name.clone(),
            category: case.category,
            is_real: case.is_real,
            flagged: flagged.contains_key(&case.name),
            completion: case_completion
                .get(&case.name)
                .copied()
                .unwrap_or(CaseCompletion::NotAnalyzed),
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

    let scoreboard = score(&observations);

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
        jdk_pack_gaps,
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
        let board = score(&cases);
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
    fn overall_aggregates_across_categories() {
        use CaseCompletion::*;
        use InjectionCategory::{Cmdi, Sqli};
        let cases = vec![
            obs("A", Sqli, true, true, Complete),
            obs("B", Cmdi, false, false, Complete),
        ];
        let board = score(&cases);
        assert_eq!(board.overall.total, 2);
        assert_eq!(board.overall.naive.tp, 1);
        assert_eq!(board.overall.naive.tn, 1);
        assert_eq!(board.overall.honest.tp, 1);
        assert_eq!(board.overall.honest.tn, 1);
        // A category with no cases contributes an all-zero matrix.
        let ldapi = board
            .per_category
            .iter()
            .find(|c| c.category == "ldapi")
            .unwrap();
        assert_eq!(ldapi.total, 0);
        assert_eq!(ldapi.naive_metrics.tpr, None);
    }

    #[test]
    fn rates_are_none_when_a_class_is_empty() {
        use CaseCompletion::Complete;
        use InjectionCategory::Sqli;
        // Only reals: FPR is undefined.
        let cases = vec![obs("A", Sqli, true, true, Complete)];
        let board = score(&cases);
        let sqli = board
            .per_category
            .iter()
            .find(|c| c.category == "sqli")
            .unwrap();
        assert_eq!(sqli.naive_metrics.tpr, Some(1.0));
        assert_eq!(sqli.naive_metrics.fpr, None);
        assert_eq!(sqli.naive_metrics.youden, None);
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
                total: InjectionCategory::ALL.len(),
                timeout_secs: 3_600,
            },
        )
        .expect("append category start");
        append_progress(
            Some(&path),
            &CategoryProgressRecord::CategoryCompleted {
                ordinal: 1,
                total: InjectionCategory::ALL.len(),
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
    fn parse_expected_results_narrows_to_taint_subset() {
        let csv = "# header line\n\
                   BenchmarkTest00001,pathtraver,true,22\n\
                   BenchmarkTest00003,hash,true,328\n\
                   BenchmarkTest00010,sqli,false,89\n\
                   BenchmarkTest00020,crypto,false,327\n";
        let set = parse_expected_results(csv).unwrap();
        assert_eq!(set.cases.len(), 2);
        assert_eq!(set.skipped_non_taint.get("hash"), Some(&1));
        assert_eq!(set.skipped_non_taint.get("crypto"), Some(&1));
    }

    #[test]
    fn case_name_comes_from_the_path_stem() {
        assert_eq!(
            case_name_from_path(
                "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest01234.java"
            )
            .as_deref(),
            Some("BenchmarkTest01234")
        );
        assert_eq!(
            case_name_from_path("src/main/java/org/owasp/Helper.java"),
            None
        );
    }

    #[test]
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
            let policy = build_policy(category);

            assert!(!policy.contains("attacker-controlled"));
            assert_eq!(
                policy.matches(&format!(":labels [{hazard_label}]")).count(),
                SOURCE_CALLEES.len(),
                "every source must mint the category's hazard label"
            );
            assert_eq!(
                policy
                    .matches(&format!(":accepts [{hazard_label}]"))
                    .count(),
                category_sinks(category).len(),
                "every sink must accept only the category's hazard label"
            );
            assert!(policy.contains(&format!(
                ":message \"data carrying {hazard_label} reached a {} sink\"",
                category.label()
            )));
        }
    }

    #[test]
    fn built_policy_carries_sources_sinks_and_require_model() {
        let policy = build_policy(InjectionCategory::Sqli);
        assert!(policy.contains(":unmodeled require-model"));
        assert!(policy.contains("getParameter"));
        assert!(policy.contains("executeQuery"));
        assert!(policy.contains("bifrost.owasp-benchmark.sqli.require-model"));
        // Every sink selector constrains minimum arity so a no-operand
        // arity-overloaded call (e.g. `PreparedStatement.execute()`) does not
        // collide by name and abort binding (#1935 cause 1). An operand at
        // argument index 0 requires at least one positional argument.
        assert!(policy.contains("(call :callee (name \"executeQuery\") (arity :min 1))"));
        // The sqli policy also models the Spring `JdbcTemplate` lane, which 156
        // benchmark cases sink through; its SQL operand is argument 0 too.
        assert!(policy.contains("(call :callee (name \"queryForObject\") (arity :min 1))"));
        // A pathtraver policy names the file sinks, not the sql ones.
        let pathtraver = build_policy(InjectionCategory::Pathtraver);
        assert!(pathtraver.contains("FileInputStream"));
        assert!(!pathtraver.contains("executeQuery"));
        // The ldapi filter operand sits at argument index 1, so its sink
        // requires at least two positional arguments.
        let ldapi = build_policy(InjectionCategory::Ldapi);
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
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("build ephemeral workspace");
        let cancellation = CancellationToken::new();
        let request = SemanticModelActivationRequest {
            bifrost_version: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };

        let error = activate_jdk_dependency_pack(
            &workspace,
            &installed_catalog,
            request,
            "21.0.2",
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
}
