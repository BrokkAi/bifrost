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

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use semver::Version;
use serde::Serialize;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    CatalogCoordinate, CatalogOptions, CompiledSemanticModelPack, CompilerOptions,
    SemanticModelActivationControl, SemanticModelActivationEvidence,
    SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
    SemanticModelPackSelector, SemanticModelRuntimeLimits, SemanticPackCatalog, SessionPackSource,
    SessionPackSourceKind, SourceFormat, compile_source,
};
use brokk_bifrost_analysis::{
    AnalyzerConfig, CancellationToken, FilesystemProject, JvmDependencyDiscoveryMode,
    JvmExternalArtifact, Project, WorkspaceAnalyzer,
};
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

/// One sink endpoint: the callee name to match and which argument carries the
/// dangerous operand.
struct Sink {
    callee: &'static str,
    argument: u32,
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
    let s = |callee, argument| Sink { callee, argument };
    match category {
        InjectionCategory::Sqli => vec![
            s("prepareStatement", 0),
            s("prepareCall", 0),
            s("execute", 0),
            s("executeQuery", 0),
            s("executeUpdate", 0),
            s("executeLargeUpdate", 0),
            s("addBatch", 0),
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
            s("println", 0),
            s("print", 0),
            s("write", 0),
            s("format", 0),
            s("printf", 0),
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
    let mut sources = String::new();
    for (index, callee) in SOURCE_CALLEES.iter().enumerate() {
        sources.push_str(&format!(
            "          (source :id src-{index} :display-name {callee:?}\n\
             \x20           :categories [input.user-controlled io.external]\n\
             \x20           :selector (rql :schema-version 1\n\
             \x20             (language java (call :callee (name {callee:?}))))\n\
             \x20           :bind return-value :labels [attacker-controlled])\n"
        ));
    }
    let mut sinks = String::new();
    for (index, sink) in category_sinks(category).into_iter().enumerate() {
        let callee = sink.callee;
        let argument = sink.argument;
        // The dangerous operand is positional argument `argument`, so the call
        // must carry at least `argument + 1` positional arguments to be this
        // sink at all. Constraining the selector by minimum arity is a
        // structural correctness bound, not TPR tuning: it excludes the
        // arity-overloaded no-operand calls (a no-argument
        // `PreparedStatement.execute()` collides with `Statement.execute(String)`
        // by name) that otherwise abort endpoint binding for the whole compile
        // (#1935 cause 1). A real sink call always has the operand, so the bound
        // never drops a true positive.
        let min_arity = argument + 1;
        sinks.push_str(&format!(
            "          (sink :id snk-{index} :display-name {callee:?}\n\
             \x20           :categories [data.sensitive]\n\
             \x20           :selector (rql :schema-version 1\n\
             \x20             (language java (call :callee (name {callee:?}) (arity :min {min_arity}))))\n\
             \x20           :dangerous-operand (argument :index {argument}) :accepts [attacker-controlled])\n"
        ));
    }
    let id = policy_id(category);
    let taxonomy_id = format!("BENCHMARK-{}", category.label().to_uppercase());
    format!(
        "(policy\n\
        \x20 :schema-version 1\n\
        \x20 :id {id:?}\n\
        \x20 :name \"OWASP Benchmark {label} (require-model)\"\n\
        \x20 :message \"attacker-controlled data reached a {label} sink\"\n\
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
    /// Wall-clock budget for the whole taint run.
    pub timeout: Duration,
    /// Optional cap on the number of cases scored, for a smoke run. `None`
    /// scores the whole subset.
    pub case_limit: Option<usize>,
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
}

/// The run-level taint completion for one category, with sample diagnostics.
#[derive(Debug, Clone, Serialize)]
pub struct CategoryRunStatus {
    pub category: String,
    pub completion: String,
    pub findings: usize,
    pub retained_analyses: usize,
    pub sample_diagnostics: Vec<String>,
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
    let workspace = WorkspaceAnalyzer::build_ephemeral(project, analyzer_config)
        .map_err(|error| format!("build benchmark workspace: {error}"))?;

    let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
        .map_err(|error| format!("open pack catalog: {error}"))?;
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

    let cancellation = CancellationToken::new().with_timeout(config.timeout);
    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 1, 1).expect("a fixed evaluation date"),
    );

    // Accumulate per-case state across the six category runs.
    let mut flagged: BTreeMap<String, InjectionCategory> = BTreeMap::new();
    let mut case_completion: BTreeMap<String, CaseCompletion> = BTreeMap::new();
    let mut findings_total = 0usize;
    let mut taint_roots = 0usize;
    let mut category_runs = Vec::new();

    for category in InjectionCategory::ALL {
        let policy = build_policy(category);
        let inputs = [PolicyEvaluationInput::embedded(
            PolicySourceIdentity::new(policy_id(category)),
            &policy,
        )];
        let outcome = evaluate_policy_inputs_with_analyzer_and_semantic_models(
            &config.benchmark_root,
            &inputs,
            &workspace,
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
                    eprintln!("[debug]     run-diagnostic: {}", diagnostic.message());
                }
            }
            for diagnostic in outcome.report().diagnostics() {
                eprintln!("[debug]   diagnostic: {}", diagnostic.message());
            }
        }

        // Record the run-level taint completion and a few diagnostics so the
        // artifact explains the category's outcome.
        let mut sample_diagnostics = Vec::new();
        let mut completion_label = "no_taint_run".to_owned();
        for policy_run in outcome.report().runs() {
            completion_label = format!("{:?}", policy_run.completion());
            for diagnostic in policy_run.diagnostics() {
                let message = diagnostic.message().to_owned();
                if !sample_diagnostics.contains(&message) {
                    sample_diagnostics.push(message);
                }
            }
        }
        sample_diagnostics.truncate(6);
        category_runs.push(CategoryRunStatus {
            category: category.label().to_owned(),
            completion: completion_label,
            findings: outcome.taint_findings().len(),
            retained_analyses: outcome.taint_analysis_results().len(),
            sample_diagnostics,
        });

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
            merge_completion(&mut case_completion, name, completion);
        }
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
            let _ = writeln!(
                out,
                "{index}\t{}\t{}\treal={}\tflagged={}\t{:?}",
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
    })
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
            "schema_version": 1,
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
