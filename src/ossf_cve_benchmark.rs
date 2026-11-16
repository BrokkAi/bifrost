//! OpenSSF CVE Benchmark scorer (#11041).
//!
//! The OpenSSF CVE Benchmark (<https://github.com/ossf-cve-benchmark/ossf-cve-benchmark>)
//! is a set of real JavaScript and TypeScript CVEs. Each case names a
//! repository, the vulnerable ("pre-patch") commit with the file and line of
//! each weakness, the fixing ("post-patch") commit, and the CVE's CWEs.
//!
//! The module has the same two halves as `owasp_benchmark`. The scoring core
//! is pure: it reads one record per CVE per tool (the alerts each rule raised
//! on each commit, plus, for Bifrost, how the analysis of the weakness files
//! concluded) and applies upstream's scoring rule, so a Bifrost record and a
//! CodeQL record are scored by the same code. The live runner builds one
//! workspace per commit, evaluates the taint policy of each category the CVE's
//! CWEs map to, and writes the record. It renders its policies with the OWASP
//! harness's `build_policy` and evaluates them with its `evaluate_policy`, so
//! the policy shape, the completion buckets and the `cause:` census are the
//! same in both benchmarks.
//!
//! Upstream's rule, from its report server at commit 91c59fd5: an alert is on
//! target when its file and line equal a weakness location of the pre-patch
//! commit, and a tool detects the CVE when one of its alerts is on target. For
//! each rule with an on-target alert, the tool recognizes the patch when that
//! rule's alert count on the post-patch commit is lower than on the pre-patch
//! commit. A detection whose rules all keep their count is a patched-commit
//! false positive, reported apart from detection.
//!
//! Bifrost's patch verdicts are further qualified by completion: a count
//! drop recognizes the patch only when the post-patch run concluded, and a
//! kept count is "still reported" only when the pre-patch run did; otherwise
//! the verdict is unknown, because a lower bound proves neither. The per-rule
//! count itself is kept, though it moves with unrelated alerts, so that the
//! CodeQL reference is scored by the same rule. Misses are split by why the
//! weakness went unreported (timed out, failed, no sink, no root,
//! inconclusive, subset complete), so an unanalyzed case never reads as clean.
//!
//! The scoring is reproduced here rather than driven through upstream's
//! tooling, which is TypeScript that needs `npm install` of its dependency
//! tree, and the CVE repositories are untrusted: nothing from them is
//! installed or run. The policies are rendered from the sink tables below
//! rather than taken from the shipped packs, which carry almost no
//! JavaScript taint rules, so the score measures the engine; each table
//! declares a proven subset, and a missing sink is a pack gap, not a verdict.
//!
//! Running it: the fetch script (one blobless clone per repository, plain
//! trees with hooks, symlinks and LFS filters disabled) and the CodeQL
//! reference driver are posted on #11041 with the baselines. `ossf-cve`
//! analyzes `<trees>/<CVE>/{pre,post}`, appends one record per CVE bound to
//! the build identity and the CVE's metadata digest, and resumes; `ossf-cve-score`
//! scores shards and the CodeQL results together.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use brokk_bifrost_analysis::retention_budget::RetentionBudget;
use brokk_bifrost_analysis::{AnalyzerConfig, FilesystemProject, Project, WorkspaceAnalyzer};
use brokk_bifrost_flow::dataflow::UnmodeledCallBehavior;
use brokk_bifrost_policy::{PolicyEvaluationDate, PolicyEvaluationOptions};

use crate::owasp_benchmark::{
    BenchmarkSuite, CaseCompletion, CategorySpec, InjectionCategory, PolicyNaming, Sink, Source,
    SuiteSemanticModels, WorkspaceRun, build_policy, evaluate_policy, policy_id,
};

/// The upstream commit the case metadata is read from.
pub const UPSTREAM_COMMIT: &str = "91c59fd54b2b768c0f310bb0027d2ac59cdf74d4";

/// [`cases_sha256`] of the `CVEs/` directory at [`UPSTREAM_COMMIT`]. A score
/// names the upstream commit only when the cases it read hash to this.
pub const UPSTREAM_CASES_SHA256: &str =
    "6e753eda387291460846c973cd2841716d57efe215aa89cd981e6afa45cec8ad";

/// Why every category declares a proven subset: the tables name the Node.js
/// core and DOM calls each category needs, by callee name, and nothing else.
/// A sink written as a property assignment (`el.innerHTML = s`), a sink in a
/// third-party library, and a library that returns its unsafe result instead
/// of passing it to a sink are not selected, so a CVE without a finding is
/// never reported as proven clean.
const NAMED_CALL_SINKS_ONLY: &str = "only the named Node.js core and DOM call sinks are selected";

/// The OpenSSF CVE Benchmark, as the shared policy renderer reads it.
///
/// The source is every function parameter: most cases are libraries whose
/// attacker input is an argument of an exported function, and a server's
/// request object reaches its handler as a parameter too. The sinks are
/// callee-name selectors, as in the OWASP suites; a name such as `exec` also
/// selects `RegExp.prototype.exec`, which costs precision on the post-patch
/// comparison, not detection.
pub static OSSF_CVE: BenchmarkSuite = BenchmarkSuite {
    name: "OpenSSF CVE Benchmark",
    repo: "https://github.com/ossf-cve-benchmark/ossf-cve-benchmark",
    version: UPSTREAM_COMMIT,
    expected_results_file: "CVEs",
    policy_naming: PolicyNaming {
        id_prefix: "bifrost.ossf-cve-benchmark",
        title: "OpenSSF CVE Benchmark",
        taxonomy: "OpenSSF-CVE-Benchmark",
    },
    languages: &["javascript", "typescript"],
    sources: &[Source::Parameter],
    categories: &[
        // `document.write`, a response's `write`, `send` and `end`, jQuery's
        // `html`, and `insertAdjacentHTML(position, html)`.
        CategorySpec {
            category: InjectionCategory::Xss,
            partial_coverage: Some(NAMED_CALL_SINKS_ONLY),
            sinks: &[
                Sink::name("write", 0),
                Sink::name("writeln", 0),
                Sink::name("send", 0),
                Sink::name("end", 0),
                Sink::name("html", 0),
                Sink::name("insertAdjacentHTML", 1),
            ],
        },
        // `child_process`: the command string or file of every spawning call.
        CategorySpec {
            category: InjectionCategory::Cmdi,
            partial_coverage: Some(NAMED_CALL_SINKS_ONLY),
            sinks: &[
                Sink::name("exec", 0),
                Sink::name("execSync", 0),
                Sink::name("execFile", 0),
                Sink::name("execFileSync", 0),
                Sink::name("spawn", 0),
                Sink::name("spawnSync", 0),
            ],
        },
        // `eval`, the `Function` constructor, and the `vm` module's runners.
        // Every argument of `Function(p1, ..., body)` is spliced into the
        // compiled source and the body is the last, so its first three
        // positions are sinks; each needs the arity it names.
        CategorySpec {
            category: InjectionCategory::Codeinj,
            partial_coverage: Some(NAMED_CALL_SINKS_ONLY),
            sinks: &[
                Sink::name("eval", 0),
                Sink::name("Function", 0),
                Sink::name("Function", 1),
                Sink::name("Function", 2),
                Sink::name("runInNewContext", 0),
                Sink::name("runInThisContext", 0),
                Sink::name("runInContext", 0),
            ],
        },
        // The `fs` calls that open, read, write, list, test or remove a path, and
        // Express's `res.sendFile`.
        CategorySpec {
            category: InjectionCategory::Pathtraver,
            partial_coverage: Some(NAMED_CALL_SINKS_ONLY),
            sinks: &[
                Sink::name("readFile", 0),
                Sink::name("readFileSync", 0),
                Sink::name("createReadStream", 0),
                Sink::name("writeFile", 0),
                Sink::name("writeFileSync", 0),
                Sink::name("createWriteStream", 0),
                Sink::name("appendFile", 0),
                Sink::name("appendFileSync", 0),
                Sink::name("open", 0),
                Sink::name("openSync", 0),
                Sink::name("readdir", 0),
                Sink::name("readdirSync", 0),
                Sink::name("unlink", 0),
                Sink::name("unlinkSync", 0),
                Sink::name("stat", 0),
                Sink::name("statSync", 0),
                Sink::name("exists", 0),
                Sink::name("existsSync", 0),
                Sink::name("sendFile", 0),
            ],
        },
        // Express's `res.redirect(url)`.
        CategorySpec {
            category: InjectionCategory::Redirect,
            partial_coverage: Some(NAMED_CALL_SINKS_ONLY),
            sinks: &[Sink::name("redirect", 0)],
        },
        // The `query(sql)` of the common SQL drivers.
        CategorySpec {
            category: InjectionCategory::Sqli,
            partial_coverage: Some(NAMED_CALL_SINKS_ONLY),
            sinks: &[Sink::name("query", 0)],
        },
    ],
};

/// The number of a `CWE-<n>` token (the suite writes both `CWE-079` and
/// `CWE-79`).
fn cwe_number(cwe: &str) -> Option<u32> {
    cwe.strip_prefix("CWE-")?.parse().ok()
}

/// Prototype pollution. Every such case in the suite lists it together with
/// the CWEs of the pollution's possible consequences (78, 79, 94 and 400),
/// while its weakness is the polluting assignment, not a sink of any of
/// those categories.
const PROTOTYPE_POLLUTION: u32 = 915;

/// The taint category a CWE belongs to, when the harness scores one. CWE-116
/// (improper output encoding) accompanies CWE-79 on most XSS cases. The
/// path-traversal family names the variants the suite lists. ReDoS,
/// prototype pollution, SSRF and the rest have no category.
pub fn category_for_cwe(cwe: &str) -> Option<InjectionCategory> {
    Some(match cwe_number(cwe)? {
        79 | 116 => InjectionCategory::Xss,
        78 | 88 => InjectionCategory::Cmdi,
        94 | 95 => InjectionCategory::Codeinj,
        22 | 23 | 36 | 73 | 99 => InjectionCategory::Pathtraver,
        601 => InjectionCategory::Redirect,
        89 => InjectionCategory::Sqli,
        _ => return None,
    })
}

// ===========================================================================
// Case metadata
// ===========================================================================

/// One file and line, relative to the repository root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Site {
    pub file: String,
    pub line: usize,
}

/// One CVE, as `CVEs/<id>.json` describes it.
#[derive(Debug, Clone)]
pub struct CveCase {
    pub cve: String,
    pub repository: String,
    pub pre_commit: String,
    pub post_commit: String,
    pub weaknesses: Vec<Site>,
    pub cwes: Vec<String>,
    /// The scored categories the CWEs map to, deduplicated, in suite order.
    pub categories: Vec<InjectionCategory>,
    /// SHA-256 of the case's metadata file. A record is scored only against
    /// the metadata it was produced from.
    pub metadata_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveFile {
    #[serde(rename = "CVE")]
    cve: String,
    repository: String,
    pre_patch: PrePatch,
    post_patch: PostPatch,
    #[serde(rename = "CWEs")]
    cwes: Vec<String>,
}

#[derive(Deserialize)]
struct PrePatch {
    commit: String,
    #[serde(default)]
    weaknesses: Vec<Weakness>,
}

#[derive(Deserialize)]
struct PostPatch {
    commit: String,
}

#[derive(Deserialize)]
struct Weakness {
    location: Option<Site>,
}

/// Parse one CVE file.
pub fn parse_case(json: &str) -> Result<CveCase, String> {
    use sha2::{Digest, Sha256};

    let file: CveFile = serde_json::from_str(json).map_err(|error| error.to_string())?;
    let prototype_pollution = file
        .cwes
        .iter()
        .any(|cwe| cwe_number(cwe) == Some(PROTOTYPE_POLLUTION));
    let mapped: BTreeSet<InjectionCategory> = if prototype_pollution {
        BTreeSet::new()
    } else {
        file.cwes
            .iter()
            .filter_map(|cwe| category_for_cwe(cwe))
            .collect()
    };
    let categories = OSSF_CVE
        .categories()
        .filter(|category| mapped.contains(category))
        .collect();
    Ok(CveCase {
        cve: file.cve,
        repository: file.repository,
        pre_commit: file.pre_patch.commit,
        post_commit: file.post_patch.commit,
        weaknesses: file
            .pre_patch
            .weaknesses
            .into_iter()
            .filter_map(|weakness| weakness.location)
            .collect(),
        cwes: file.cwes,
        categories,
        metadata_sha256: brokk_bifrost_analysis::analyzer::canonical_hash::lower_hex_string(
            &Sha256::digest(json.as_bytes()).into(),
        ),
    })
}

/// SHA-256 over every case's name and metadata digest, in CVE order: the
/// identity of the case set a run or a score read.
pub fn cases_sha256(cases: &[CveCase]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for case in cases {
        hasher.update(case.cve.as_bytes());
        hasher.update(b" ");
        hasher.update(case.metadata_sha256.as_bytes());
        hasher.update(b"\n");
    }
    brokk_bifrost_analysis::analyzer::canonical_hash::lower_hex_string(&hasher.finalize().into())
}

/// Read every case under `<benchmark>/CVEs`, in CVE order.
pub fn load_cases(benchmark_root: &Path) -> Result<Vec<CveCase>, String> {
    let dir = benchmark_root.join(OSSF_CVE.expected_results_file);
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .map_err(|error| format!("read {}: {error}", dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<_, _>>()
        .map_err(|error| format!("list {}: {error}", dir.display()))?;
    paths.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "json")
    });
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let json = fs::read_to_string(path)
                .map_err(|error| format!("read {}: {error}", path.display()))?;
            parse_case(&json).map_err(|error| format!("parse {}: {error}", path.display()))
        })
        .collect()
}

// ===========================================================================
// Per-CVE records and the scoring core
// ===========================================================================

/// What happened to one CVE in one tool's run, before scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    /// Both commits were analyzed.
    Analyzed,
    /// The tool has no rule for any of the CVE's CWEs.
    OutOfScope,
    /// A commit could not be obtained (the repository or commit is gone).
    Unavailable,
    /// The tool failed on a commit.
    Error,
}

/// The alerts one rule raised on each commit. For Bifrost a rule is one
/// category's policy; for CodeQL it is one query id.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleAlerts {
    pub rule: String,
    pub pre: Vec<Site>,
    pub post: Vec<Site>,
    /// How the rule's run on a commit terminated, when it did not finish (a
    /// deadline, above all). Its alert list is then a lower bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_termination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_termination: Option<String>,
    /// Bifrost only: the rule's run-level completion on each commit
    /// (`Complete`, `ProvenSubset`, `ProvenBySummary`, `Inconclusive`, or
    /// `Failed`, `NotRun` or `Unsupported` when the run formed no verdict, or
    /// `NoRun` when the evaluation formed no taint run). `None` for a tool
    /// that reports no completeness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_completion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_completion: Option<String>,
    /// Bifrost only: the source and sink endpoints the policy compiled on the
    /// pre-patch commit, anywhere in the repository.
    #[serde(default)]
    pub pre_source_endpoints: u64,
    #[serde(default)]
    pub pre_sink_endpoints: u64,
    /// Bifrost only: the pre-patch run's diagnostics when it formed no
    /// verdict, so the failure census can name why.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre_failure: Vec<String>,
}

/// How the taint roots in the weakness files concluded on the pre-patch
/// commit. Bifrost only; other tools report no completeness.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WeaknessRoots {
    pub complete: usize,
    pub proven_by_summary: usize,
    pub inconclusive: usize,
    /// Per `cause:` row, how many of those roots it blocked.
    pub causes: BTreeMap<String, usize>,
    /// Findings anywhere in a weakness file, on target or not, so a near miss
    /// (the right flow reported at another line) is visible.
    pub findings_in_weakness_files: usize,
}

/// What produced a record: the binary and the analysis settings. Records
/// from different runs are combined only when this is equal, so a resumed or
/// sharded baseline cannot mix configurations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunIdentity {
    /// `BIFROST_BUILD_IDENTITY`: the source revision the binary was built
    /// from.
    pub build: String,
    pub call_modeling: String,
    pub timeout_secs: u64,
}

/// One CVE's record for one tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseRecord {
    pub cve: String,
    /// Bifrost only; `None` for the CodeQL reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<RunIdentity>,
    /// Bifrost only: the [`CveCase::metadata_sha256`] the record was
    /// produced from. Scoring it against other metadata (other commits,
    /// weakness locations or CWEs) is an error, not a verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_sha256: Option<String>,
    pub status: CaseStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default)]
    pub rules: Vec<RuleAlerts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weakness_roots: Option<WeaknessRoots>,
    #[serde(default)]
    pub seconds: f64,
}

/// Whether a detection survives the patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchVerdict {
    /// An on-target rule raised fewer alerts after the patch.
    Recognized,
    /// Every on-target rule raised as many alerts after the patch or more,
    /// and its pre-patch run concluded: a false positive on the patched
    /// commit.
    StillReported,
    /// The comparison rests on a lower bound. Either an on-target rule's
    /// count dropped but its post-patch run did not conclude, so the lower
    /// count may be missing flows rather than showing the fix; or no count
    /// dropped but a pre-patch run did not conclude, so its true count may
    /// exceed the post-patch one.
    Unknown,
}

/// Why a CVE in scope was not detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissKind {
    /// The tool reports no completeness, and raised nothing on target.
    NoAlert,
    /// A rule's pre-patch run did not finish.
    TimedOut,
    /// A rule's pre-patch run finished without a verdict: it failed, or it
    /// could not run. Its zero endpoint counts and zero roots say nothing
    /// about the code.
    RunFailed,
    /// The run concluded, but no rule selected a sink anywhere in the
    /// repository: the sink tables do not cover the code.
    NoSinkSelected,
    /// The run concluded and selected sinks, but no taint root formed in any
    /// weakness file.
    NotAnalyzed,
    /// A root in a weakness file did not conclude, or the run as a whole did
    /// not.
    Inconclusive,
    /// Every root in the weakness files concluded within the declared
    /// subset: the sink or the flow is outside the policy's tables.
    SubsetComplete,
}

/// One CVE's score for one tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "verdict", content = "kind")]
pub enum Verdict {
    Detected(PatchVerdict),
    Missed(MissKind),
    OutOfScope,
    Unavailable,
    Error,
}

/// Apply upstream's scoring rule to one record.
pub fn verdict(case: &CveCase, record: &CaseRecord) -> Verdict {
    if record
        .metadata_sha256
        .as_ref()
        .is_some_and(|digest| *digest != case.metadata_sha256)
    {
        return Verdict::Error;
    }
    match record.status {
        CaseStatus::Analyzed => {}
        CaseStatus::OutOfScope => return Verdict::OutOfScope,
        CaseStatus::Unavailable => return Verdict::Unavailable,
        CaseStatus::Error => return Verdict::Error,
    }
    let targets: BTreeSet<&Site> = case.weaknesses.iter().collect();
    let on_target: Vec<&RuleAlerts> = record
        .rules
        .iter()
        .filter(|rule| rule.pre.iter().any(|site| targets.contains(site)))
        .collect();
    if !on_target.is_empty() {
        // A may-analysis's findings are a lower bound, so a count that did
        // not drop is a still-reported patch whatever the post-patch run
        // reached; a count that dropped shows the fix only when that run
        // concluded.
        let dropped: Vec<&&RuleAlerts> = on_target
            .iter()
            .filter(|rule| rule.post.len() < rule.pre.len())
            .collect();
        return Verdict::Detected(if dropped.is_empty() {
            if on_target.iter().all(|rule| pre_concluded(rule)) {
                PatchVerdict::StillReported
            } else {
                PatchVerdict::Unknown
            }
        } else if dropped.iter().any(|rule| post_concluded(rule)) {
            PatchVerdict::Recognized
        } else {
            PatchVerdict::Unknown
        });
    }
    if record
        .rules
        .iter()
        .any(|rule| rule.pre_termination.is_some())
    {
        return Verdict::Missed(MissKind::TimedOut);
    }
    if record.rules.iter().any(run_failed) {
        return Verdict::Missed(MissKind::RunFailed);
    }
    // A run that did not conclude may have missed the flow anywhere: in a
    // root outside the weakness files, or in a file whose endpoints partial
    // discovery never selected. Only a concluded run's empty or complete
    // weakness-file roots say the tables or the flow are at fault.
    Verdict::Missed(match &record.weakness_roots {
        None => MissKind::NoAlert,
        Some(roots) if roots.inconclusive > 0 || !record.rules.iter().all(pre_concluded) => {
            MissKind::Inconclusive
        }
        Some(_) if record.rules.iter().all(|rule| rule.pre_sink_endpoints == 0) => {
            MissKind::NoSinkSelected
        }
        Some(roots) if roots.complete + roots.proven_by_summary == 0 => MissKind::NotAnalyzed,
        Some(_) => MissKind::SubsetComplete,
    })
}

/// Whether a resumed run may keep this record for `case`. A record made
/// from other metadata, or whose run timed out or formed no verdict on either
/// commit, is retried, as are errors and unavailable trees; the later line
/// supersedes it when the file is scored.
pub fn is_settled(case: &CveCase, record: &CaseRecord) -> bool {
    if record.metadata_sha256.as_deref() != Some(case.metadata_sha256.as_str()) {
        return false;
    }
    match record.status {
        CaseStatus::OutOfScope => true,
        CaseStatus::Analyzed => record.rules.iter().all(|rule| {
            rule.pre_termination.is_none()
                && rule.post_termination.is_none()
                && !run_failed(rule)
                && rule.post_completion.as_deref().is_none_or(is_verdict)
        }),
        CaseStatus::Unavailable | CaseStatus::Error => false,
    }
}

/// Whether a rule's pre-patch run formed no verdict.
fn run_failed(rule: &RuleAlerts) -> bool {
    rule.pre_completion
        .as_deref()
        .is_some_and(|completion| !is_verdict(completion))
}

/// Whether a run-level completion is a verdict, conclusive or not.
fn is_verdict(completion: &str) -> bool {
    is_conclusive(completion) || completion == "Inconclusive"
}

/// Whether a rule's pre-patch run finished and concluded, so its alert
/// count is the whole count. A tool that reports no completeness is taken at
/// its word, as upstream does.
fn pre_concluded(rule: &RuleAlerts) -> bool {
    rule.pre_termination.is_none() && rule.pre_completion.as_deref().is_none_or(is_conclusive)
}

/// Whether a run-level completion proves its result whole.
fn is_conclusive(completion: &str) -> bool {
    matches!(completion, "Complete" | "ProvenSubset" | "ProvenBySummary")
}

/// Whether a rule's post-patch run finished and concluded, so its alert
/// count is the whole count. A tool that reports no completeness is taken at
/// its word, as upstream does.
fn post_concluded(rule: &RuleAlerts) -> bool {
    rule.post_termination.is_none() && rule.post_completion.as_deref().is_none_or(is_conclusive)
}

/// Counts of verdicts over a set of CVEs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Tally {
    pub cves: usize,
    pub detected: usize,
    pub patch_recognized: usize,
    pub patch_still_reported: usize,
    pub patch_unknown: usize,
    pub missed_no_alert: usize,
    pub missed_timed_out: usize,
    pub missed_run_failed: usize,
    pub missed_no_sink_selected: usize,
    pub missed_not_analyzed: usize,
    pub missed_inconclusive: usize,
    pub missed_subset_complete: usize,
    pub out_of_scope: usize,
    pub unavailable: usize,
    pub error: usize,
}

impl Tally {
    fn add(&mut self, verdict: Verdict) {
        self.cves += 1;
        match verdict {
            Verdict::Detected(patch) => {
                self.detected += 1;
                match patch {
                    PatchVerdict::Recognized => self.patch_recognized += 1,
                    PatchVerdict::StillReported => self.patch_still_reported += 1,
                    PatchVerdict::Unknown => self.patch_unknown += 1,
                }
            }
            Verdict::Missed(kind) => match kind {
                MissKind::NoAlert => self.missed_no_alert += 1,
                MissKind::TimedOut => self.missed_timed_out += 1,
                MissKind::RunFailed => self.missed_run_failed += 1,
                MissKind::NoSinkSelected => self.missed_no_sink_selected += 1,
                MissKind::NotAnalyzed => self.missed_not_analyzed += 1,
                MissKind::Inconclusive => self.missed_inconclusive += 1,
                MissKind::SubsetComplete => self.missed_subset_complete += 1,
            },
            Verdict::OutOfScope => self.out_of_scope += 1,
            Verdict::Unavailable => self.unavailable += 1,
            Verdict::Error => self.error += 1,
        }
    }
}

/// One tool's scores: every CVE once in `total`, and each CVE again under
/// every Bifrost category its CWEs map to (`other` when none), so the two
/// tools' rows cover the same CVEs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Scoreboard {
    pub total: Tally,
    pub per_category: BTreeMap<String, Tally>,
    /// Per `cause:` family (the cause label and status, without the path and
    /// the declaration), the number of inconclusive misses it blocked.
    pub miss_causes: BTreeMap<String, usize>,
    /// Per failure family (the first diagnostic of a failed pre-patch run,
    /// with its locators, quoted names and numbers elided), the number of
    /// CVEs it failed.
    pub run_failures: BTreeMap<String, usize>,
}

/// Score every case. A case without a record counts as an error, so a
/// partial run cannot look like a clean one.
pub fn score(cases: &[CveCase], records: &BTreeMap<String, CaseRecord>) -> Scoreboard {
    let mut board = Scoreboard::default();
    for case in cases {
        let verdict = records
            .get(&case.cve)
            .map_or(Verdict::Error, |record| verdict(case, record));
        board.total.add(verdict);
        if case.categories.is_empty() {
            board
                .per_category
                .entry("other".to_owned())
                .or_default()
                .add(verdict);
        }
        for category in &case.categories {
            board
                .per_category
                .entry(category.label().to_owned())
                .or_default()
                .add(verdict);
        }
        if verdict == Verdict::Missed(MissKind::Inconclusive) {
            let mut families: BTreeSet<String> = records[&case.cve]
                .weakness_roots
                .iter()
                .flat_map(|roots| roots.causes.keys())
                .map(|cause| cause_family(cause))
                .collect();
            if families.is_empty() {
                // No weakness-file root was blocked; the run as a whole was.
                families.insert("run-inconclusive".to_owned());
            }
            for family in families {
                *board.miss_causes.entry(family).or_default() += 1;
            }
        }
        if verdict == Verdict::Missed(MissKind::RunFailed) {
            let families: BTreeSet<String> = records[&case.cve]
                .rules
                .iter()
                .filter(|rule| run_failed(rule))
                .map(|rule| {
                    rule.pre_failure.first().map_or_else(
                        || "unrecorded".to_owned(),
                        |message| failure_family(message),
                    )
                })
                .collect();
            for family in families {
                *board.run_failures.entry(family).or_default() += 1;
            }
        }
    }
    board
}

/// The family of a run-failure diagnostic: the message with each
/// `DeclarationLocator(..)`, each backquoted name and each number replaced,
/// so one defect in many procedures counts as one family.
fn failure_family(message: &str) -> String {
    let mut family = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(start) = rest.find("DeclarationLocator(") {
        family.push_str(&rest[..start]);
        family.push_str("<locator>");
        let mut depth = 0usize;
        let mut end = rest.len();
        for (offset, ch) in rest[start..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + offset + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = &rest[end..];
    }
    family.push_str(rest);
    let mut elided = String::with_capacity(family.len());
    let mut in_quote = false;
    let mut in_number = false;
    for ch in family.chars() {
        if ch == '`' {
            if !in_quote {
                elided.push_str("`_`");
            }
            in_quote = !in_quote;
            continue;
        }
        if in_quote {
            continue;
        }
        if ch.is_ascii_digit() {
            if !in_number {
                elided.push('N');
            }
            in_number = true;
            continue;
        }
        in_number = false;
        elided.push(ch);
    }
    elided
}

/// The family of a `cause:<label>:<status>:<path>:<declaration>` row: its
/// label and status. The split counts from the left, because a path can hold
/// a colon and the label and status cannot.
fn cause_family(cause: &str) -> String {
    cause.splitn(4, ':').take(3).collect::<Vec<_>>().join(":")
}

// ===========================================================================
// CodeQL records
// ===========================================================================

/// One line of the CodeQL reference driver's output: one commit of one CVE.
#[derive(Deserialize)]
struct CodeqlLine {
    cve: String,
    side: String,
    /// SHA-256 of the CVE metadata file the driver read, as in
    /// [`CveCase::metadata_sha256`].
    metadata_sha256: String,
    status: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    alerts: Vec<CodeqlAlert>,
}

#[derive(Deserialize)]
struct CodeqlAlert {
    file: String,
    line: usize,
    rule: String,
}

/// Fold the CodeQL driver's JSON lines (one per commit) into one record per
/// CVE, bound to the metadata the driver read. A CVE missing either commit's
/// line is left out, so `score` counts it as an error.
pub fn codeql_records(jsonl: &str) -> Result<BTreeMap<String, CaseRecord>, String> {
    let mut sides: BTreeMap<String, BTreeMap<String, CodeqlLine>> = BTreeMap::new();
    for (number, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: CodeqlLine = serde_json::from_str(line)
            .map_err(|error| format!("CodeQL results line {}: {error}", number + 1))?;
        sides
            .entry(parsed.cve.clone())
            .or_default()
            .insert(parsed.side.clone(), parsed);
    }
    let mut records = BTreeMap::new();
    for (cve, mut by_side) in sides {
        let (Some(pre), Some(post)) = (by_side.remove("pre"), by_side.remove("post")) else {
            continue;
        };
        if pre.metadata_sha256 != post.metadata_sha256 {
            return Err(format!(
                "CodeQL results for {cve} read two versions of its metadata: {} and {}",
                pre.metadata_sha256, post.metadata_sha256
            ));
        }
        let metadata_sha256 = Some(pre.metadata_sha256.clone());
        let status = match (pre.status.as_str(), post.status.as_str()) {
            ("success", "success") => CaseStatus::Analyzed,
            ("unsupported", _) | (_, "unsupported") => CaseStatus::OutOfScope,
            _ if [&pre, &post].iter().any(|side| {
                side.error
                    .as_deref()
                    .is_some_and(|error| error.contains("not fetched"))
            }) =>
            {
                CaseStatus::Unavailable
            }
            _ => CaseStatus::Error,
        };
        let mut rules: BTreeMap<String, RuleAlerts> = BTreeMap::new();
        for (alerts, is_pre) in [(&pre.alerts, true), (&post.alerts, false)] {
            for alert in alerts {
                let rule = rules
                    .entry(alert.rule.clone())
                    .or_insert_with(|| RuleAlerts {
                        rule: alert.rule.clone(),
                        ..RuleAlerts::default()
                    });
                let site = Site {
                    file: alert.file.clone(),
                    line: alert.line,
                };
                if is_pre {
                    rule.pre.push(site);
                } else {
                    rule.post.push(site);
                }
            }
        }
        let detail = pre.error.or(post.error);
        records.insert(
            cve.clone(),
            CaseRecord {
                cve,
                identity: None,
                metadata_sha256,
                status,
                detail,
                rules: rules.into_values().collect(),
                weakness_roots: None,
                seconds: 0.0,
            },
        );
    }
    Ok(records)
}

// ===========================================================================
// Live runner
// ===========================================================================

/// Configuration for one live run.
pub struct RunConfig {
    /// The benchmark checkout, holding `CVEs/`.
    pub benchmark_root: PathBuf,
    /// The fetched trees: `<trees>/<CVE>/pre` and `<trees>/<CVE>/post`, each
    /// with a `.fetched` marker naming its commit.
    pub trees_root: PathBuf,
    pub call_modeling: UnmodeledCallBehavior,
    /// Wall-clock budget for each category's run on each commit.
    pub timeout: Duration,
}

impl RunConfig {
    /// The identity every record this configuration produces carries.
    pub fn identity(&self) -> RunIdentity {
        RunIdentity {
            build: crate::BIFROST_BUILD_IDENTITY.to_owned(),
            call_modeling: self.call_modeling.label().to_owned(),
            timeout_secs: self.timeout.as_secs(),
        }
    }
}

/// The marker the fetch step writes into a tree once its checkout is whole.
const FETCHED_MARKER: &str = ".fetched";

/// Analyze one CVE on both commits.
pub fn run_case(config: &RunConfig, case: &CveCase) -> CaseRecord {
    let started = Instant::now();
    let mut record = CaseRecord {
        cve: case.cve.clone(),
        identity: Some(config.identity()),
        metadata_sha256: Some(case.metadata_sha256.clone()),
        status: CaseStatus::Analyzed,
        detail: None,
        rules: Vec::new(),
        weakness_roots: None,
        seconds: 0.0,
    };
    if case.categories.is_empty() {
        record.status = CaseStatus::OutOfScope;
        return record;
    }
    let trees = config.trees_root.join(&case.cve);
    for (side, commit) in [("pre", &case.pre_commit), ("post", &case.post_commit)] {
        let marker = trees.join(side).join(FETCHED_MARKER);
        match fs::read_to_string(&marker) {
            Ok(fetched) if fetched.trim() == commit.as_str() => {}
            Ok(fetched) => {
                record.status = CaseStatus::Error;
                record.detail = Some(format!(
                    "{side} tree holds {}, not {commit}",
                    fetched.trim()
                ));
                return record;
            }
            Err(_) => {
                record.status = CaseStatus::Unavailable;
                record.detail = Some(format!("{side} tree not fetched"));
                return record;
            }
        }
    }
    match analyze_case(config, case, &trees) {
        Ok((rules, roots)) => {
            record.rules = rules;
            record.weakness_roots = Some(roots);
        }
        Err(error) => {
            record.status = CaseStatus::Error;
            record.detail = Some(error);
        }
    }
    record.seconds = started.elapsed().as_secs_f64();
    record
}

fn analyze_case(
    config: &RunConfig,
    case: &CveCase,
    trees: &Path,
) -> Result<(Vec<RuleAlerts>, WeaknessRoots), String> {
    let mut rules: Vec<RuleAlerts> = case
        .categories
        .iter()
        .map(|category| RuleAlerts {
            rule: category.label().to_owned(),
            ..RuleAlerts::default()
        })
        .collect();
    let weakness_files: BTreeSet<&str> = case
        .weaknesses
        .iter()
        .map(|site| site.file.as_str())
        .collect();
    let mut roots = WeaknessRoots::default();
    let options = PolicyEvaluationOptions::new(
        PolicyEvaluationDate::from_ymd(2026, 1, 1).expect("a fixed evaluation date"),
    );
    for is_pre in [true, false] {
        let root = trees.join(if is_pre { "pre" } else { "post" });
        let budget = RetentionBudget::new(AnalyzerConfig::default().retention_budget_bytes());
        let project = FilesystemProject::new(&root)
            .map_err(|error| format!("open {}: {error}", root.display()))?;
        let project: Arc<dyn Project> = Arc::new(project);
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun_with_budget(
            project,
            AnalyzerConfig::default(),
            &budget,
        )
        .map_err(|error| format!("build workspace over {}: {error}", root.display()))?;
        let flow_state = brokk_bifrost_flow::FlowWorkspaceState::new();
        let run = WorkspaceRun {
            analysis_root: &root,
            workspace: &workspace,
            semantic_models: &SuiteSemanticModels::Published,
            flow_state: &flow_state,
            options: &options,
            budget: &budget,
        };
        for (category, rule) in case.categories.iter().zip(rules.iter_mut()) {
            let policy = build_policy(&OSSF_CVE, *category, config.call_modeling);
            let evaluation = evaluate_policy(
                &run,
                policy_id(&OSSF_CVE, *category, config.call_modeling),
                &policy,
                category.label(),
                config.timeout,
            )?;
            // A leak reached from several roots is reported once per root;
            // count it once, as one alert.
            let mut leaks = BTreeSet::new();
            let sites: Vec<Site> = evaluation
                .findings
                .iter()
                .filter(|finding| leaks.insert(finding.content_key()))
                .map(|finding| Site {
                    file: finding.sink.path.clone(),
                    line: finding.sink.range.start_line,
                })
                .collect();
            // The variant name alone: `ProvenSubset { codes: [..] }` and
            // `Inconclusive { reasons: [..] }` carry detail the roots and the
            // causes already record.
            let completion = match evaluation.status.completion.as_str() {
                "no_taint_run" => "NoRun".to_owned(),
                label => label.split([' ', '{']).next().unwrap_or(label).to_owned(),
            };
            if is_pre {
                if !is_verdict(&completion) {
                    rule.pre_failure = evaluation.status.sample_diagnostics.clone();
                }
                rule.pre_completion = Some(completion);
                roots.findings_in_weakness_files += sites
                    .iter()
                    .filter(|site| weakness_files.contains(site.file.as_str()))
                    .count();
                for root in &evaluation.roots {
                    if !weakness_files.contains(root.path.as_str()) {
                        continue;
                    }
                    match root.completion {
                        CaseCompletion::Complete => roots.complete += 1,
                        CaseCompletion::ProvenBySummary => roots.proven_by_summary += 1,
                        CaseCompletion::Inconclusive | CaseCompletion::NotAnalyzed => {
                            roots.inconclusive += 1;
                        }
                    }
                    for reason in &root.reasons {
                        if reason.starts_with("cause:") {
                            *roots.causes.entry(reason.clone()).or_default() += 1;
                        }
                    }
                }
                rule.pre = sites;
                rule.pre_termination = evaluation.status.termination;
                let work = &evaluation.status.work;
                rule.pre_source_endpoints = work
                    .get("taint.compiled_source_endpoints")
                    .copied()
                    .unwrap_or(0);
                rule.pre_sink_endpoints = work
                    .get("taint.compiled_sink_endpoints")
                    .copied()
                    .unwrap_or(0);
            } else {
                rule.post = sites;
                rule.post_completion = Some(completion);
                rule.post_termination = evaluation.status.termination;
            }
        }
    }
    Ok((rules, roots))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(file: &str, line: usize) -> Site {
        Site {
            file: file.to_owned(),
            line,
        }
    }

    fn case(categories: &[InjectionCategory]) -> CveCase {
        CveCase {
            cve: "CVE-0000-0001".to_owned(),
            repository: String::new(),
            pre_commit: "a".to_owned(),
            post_commit: "b".to_owned(),
            weaknesses: vec![site("lib/index.js", 10)],
            cwes: vec!["CWE-078".to_owned()],
            categories: categories.to_vec(),
            metadata_sha256: String::new(),
        }
    }

    fn analyzed(rules: Vec<RuleAlerts>, roots: Option<WeaknessRoots>) -> CaseRecord {
        CaseRecord {
            cve: "CVE-0000-0001".to_owned(),
            identity: None,
            metadata_sha256: None,
            status: CaseStatus::Analyzed,
            detail: None,
            rules,
            weakness_roots: roots,
            seconds: 0.0,
        }
    }

    fn rule(pre: Vec<Site>, post: Vec<Site>) -> RuleAlerts {
        RuleAlerts {
            rule: "cmdi".to_owned(),
            pre,
            post,
            pre_sink_endpoints: 1,
            ..RuleAlerts::default()
        }
    }

    #[test]
    fn parses_the_upstream_case_shape_and_maps_cwes() {
        let parsed = parse_case(
            r#"{"CVE": "CVE-2017-0931", "state": "PUBLISHED",
                "repository": "https://github.com/guardian/html-janitor.git",
                "prePatch": {"commit": "8c99e653", "weaknesses": [
                    {"location": {"file": "src/html-janitor.js", "line": 43},
                     "explanation": "Client-side cross-site scripting"}]},
                "postPatch": {"commit": "0f60a424"},
                "CWEs": ["CWE-079", "CWE-116", "CWE-400"]}"#,
        )
        .expect("the upstream shape parses");
        assert_eq!(parsed.weaknesses, vec![site("src/html-janitor.js", 43)]);
        assert_eq!(parsed.categories, vec![InjectionCategory::Xss]);
        assert_eq!(category_for_cwe("CWE-730"), None);
        let polluting = parse_case(
            r#"{"CVE": "CVE-2019-11358", "repository": "", "prePatch": {"commit": "a"},
                "postPatch": {"commit": "b"},
                "CWEs": ["CWE-078", "CWE-079", "CWE-094", "CWE-400", "CWE-915"]}"#,
        )
        .expect("a case without weaknesses parses");
        assert!(polluting.categories.is_empty());
        assert_eq!(
            category_for_cwe("CWE-22"),
            Some(InjectionCategory::Pathtraver)
        );
    }

    /// The scoring rule, verdict by verdict: an on-target alert is a
    /// detection, judged after the patch by its rule's count; without one,
    /// the miss is split by what the analysis of the weakness file reached.
    #[test]
    fn verdicts_follow_upstream_rule_and_completion() {
        let cmdi = case(&[InjectionCategory::Cmdi]);
        let target = || site("lib/index.js", 10);
        let elsewhere = || site("lib/other.js", 3);

        let recognized = analyzed(
            vec![rule(vec![target(), elsewhere()], vec![elsewhere()])],
            None,
        );
        assert_eq!(
            verdict(&cmdi, &recognized),
            Verdict::Detected(PatchVerdict::Recognized)
        );
        // The count did not drop: the flow moved, and the patched commit is
        // still reported.
        let kept = analyzed(
            vec![rule(vec![target()], vec![site("lib/index.js", 12)])],
            None,
        );
        assert_eq!(
            verdict(&cmdi, &kept),
            Verdict::Detected(PatchVerdict::StillReported)
        );
        // A drop only shows the fix when the post-patch run concluded: an
        // inconclusive or cut-short run's lower count may be missing flows.
        let mut inconclusive_drop = recognized.clone();
        inconclusive_drop.rules[0].post_completion = Some("Inconclusive".to_owned());
        assert_eq!(
            verdict(&cmdi, &inconclusive_drop),
            Verdict::Detected(PatchVerdict::Unknown)
        );
        let mut cut_short = recognized.clone();
        cut_short.rules[0].post_completion = Some("ProvenSubset".to_owned());
        cut_short.rules[0].post_termination = Some("DeadlineExceeded".to_owned());
        assert_eq!(
            verdict(&cmdi, &cut_short),
            Verdict::Detected(PatchVerdict::Unknown)
        );
        let mut inconclusive_kept = kept.clone();
        inconclusive_kept.rules[0].post_completion = Some("Inconclusive".to_owned());
        assert_eq!(
            verdict(&cmdi, &inconclusive_kept),
            Verdict::Detected(PatchVerdict::StillReported)
        );
        // An unchanged count against a pre-patch lower bound proves nothing.
        let mut kept_after_partial = kept.clone();
        kept_after_partial.rules[0].pre_completion = Some("Inconclusive".to_owned());
        assert_eq!(
            verdict(&cmdi, &kept_after_partial),
            Verdict::Detected(PatchVerdict::Unknown)
        );
        // A record made from other metadata than the case's is an error.
        let mut stale = kept.clone();
        stale.metadata_sha256 = Some("other".to_owned());
        assert_eq!(verdict(&cmdi, &stale), Verdict::Error);

        let off_target = || vec![rule(vec![elsewhere()], vec![])];
        assert_eq!(
            verdict(&cmdi, &analyzed(off_target(), None)),
            Verdict::Missed(MissKind::NoAlert)
        );
        let mut timed_out = analyzed(off_target(), Some(WeaknessRoots::default()));
        timed_out.rules[0].pre_termination = Some("DeadlineExceeded".to_owned());
        assert_eq!(
            verdict(&cmdi, &timed_out),
            Verdict::Missed(MissKind::TimedOut)
        );
        assert_eq!(
            verdict(
                &cmdi,
                &analyzed(off_target(), Some(WeaknessRoots::default()))
            ),
            Verdict::Missed(MissKind::NotAnalyzed)
        );
        // A failed run selects nothing; that is a failure, not a table gap.
        let mut failed = analyzed(vec![rule(vec![], vec![])], Some(WeaknessRoots::default()));
        failed.rules[0].pre_sink_endpoints = 0;
        failed.rules[0].pre_completion = Some("Failed".to_owned());
        assert_eq!(
            verdict(&cmdi, &failed),
            Verdict::Missed(MissKind::RunFailed)
        );
        // A resumed run retries timed-out and failed runs and records made
        // from other metadata, not concluded ones.
        assert!(!is_settled(&cmdi, &timed_out));
        assert!(!is_settled(&cmdi, &failed));
        assert!(!is_settled(&cmdi, &stale));
        let mut settled = kept.clone();
        settled.metadata_sha256 = Some(cmdi.metadata_sha256.clone());
        assert!(is_settled(&cmdi, &settled));
        let mut no_sink = analyzed(vec![rule(vec![], vec![])], Some(WeaknessRoots::default()));
        no_sink.rules[0].pre_sink_endpoints = 0;
        assert_eq!(
            verdict(&cmdi, &no_sink),
            Verdict::Missed(MissKind::NoSinkSelected)
        );
        // A run that did not conclude is no evidence of a table gap.
        let mut partial = no_sink.clone();
        partial.rules[0].pre_completion = Some("Inconclusive".to_owned());
        assert_eq!(
            verdict(&cmdi, &partial),
            Verdict::Missed(MissKind::Inconclusive)
        );
        let inconclusive = WeaknessRoots {
            complete: 3,
            inconclusive: 1,
            ..WeaknessRoots::default()
        };
        assert_eq!(
            verdict(&cmdi, &analyzed(off_target(), Some(inconclusive))),
            Verdict::Missed(MissKind::Inconclusive)
        );
        let complete = WeaknessRoots {
            complete: 2,
            ..WeaknessRoots::default()
        };
        assert_eq!(
            verdict(&cmdi, &analyzed(off_target(), Some(complete))),
            Verdict::Missed(MissKind::SubsetComplete)
        );
    }

    /// A CVE with no record is an error, never a clean miss, and a CVE with
    /// two categories counts once in the total and once per category.
    #[test]
    fn score_counts_missing_records_as_errors() {
        let mut two = case(&[InjectionCategory::Cmdi, InjectionCategory::Codeinj]);
        two.cve = "CVE-0000-0002".to_owned();
        let one = case(&[InjectionCategory::Cmdi]);
        let mut records = BTreeMap::new();
        let mut record = analyzed(vec![rule(vec![site("lib/index.js", 10)], vec![])], None);
        record.cve = two.cve.clone();
        records.insert(two.cve.clone(), record);
        let board = score(&[one, two], &records);
        assert_eq!(board.total.cves, 2);
        assert_eq!(board.total.error, 1);
        assert_eq!(board.total.patch_recognized, 1);
        assert_eq!(board.per_category["cmdi"].cves, 2);
        assert_eq!(board.per_category["codeinj"].detected, 1);
    }

    #[test]
    fn codeql_lines_fold_into_one_record_per_cve() {
        let jsonl = concat!(
            r#"{"cve": "CVE-0000-0001", "side": "pre", "metadata_sha256": "m1", "status": "success", "queries": [], "alerts": [{"file": "lib/index.js", "line": 10, "rule": "js/command-line-injection"}]}"#,
            "\n",
            r#"{"cve": "CVE-0000-0001", "side": "post", "metadata_sha256": "m1", "status": "success", "queries": [], "alerts": []}"#,
            "\n",
            r#"{"cve": "CVE-0000-0002", "side": "pre", "metadata_sha256": "m2", "status": "unsupported", "queries": []}"#,
            "\n",
        );
        let records = codeql_records(jsonl).expect("the driver's lines parse");
        let mut read = case(&[]);
        read.metadata_sha256 = "m1".to_owned();
        assert_eq!(
            verdict(&read, &records["CVE-0000-0001"]),
            Verdict::Detected(PatchVerdict::Recognized)
        );
        // Results for other metadata do not score against this case.
        assert_eq!(
            verdict(&case(&[]), &records["CVE-0000-0001"]),
            Verdict::Error
        );
        // Only one commit's line: no record, so `score` counts an error.
        assert!(!records.contains_key("CVE-0000-0002"));
    }
}
