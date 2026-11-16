//! Driver for the taint benchmarks: the OWASP Benchmark bakeoff (BenchmarkJava
//! and BenchmarkPython) and the OpenSSF CVE Benchmark.
//!
//! Two subcommands:
//!
//!   promote-esapi --staged <path> --jar <path> --out <path>
//!       Digest the resolved ESAPI jar and write the pinned sanitizer pack.
//!
//!   run [--suite java] --benchmark <dir> --packs-dir <dir> --deps <dir>
//!       --jdk-catalog <dir> --out <path> [--esapi-digest <hex>] [common flags]
//!       Build the BenchmarkJava workspace, activate the curated
//!       sanitizer/summary packs and, through the product dependency-pack path
//!       (#2558), the real `bifrost.jdk` release bundle installed at
//!       `--jdk-catalog`; run one taint policy per category, score, and write
//!       the artifact.
//!
//!   run --suite python --benchmark <dir> --catalog <dir>
//!       --premium-packs-dir <dir> --wheels <dir> --work-dir <dir>
//!       --out <path> [common flags]
//!       Stage the BenchmarkPython workspace in `--work-dir` (absent or empty)
//!       with the wheels from `--wheels` installed as runtime evidence, pin
//!       the premium Flask, Werkzeug and ldap3 models from
//!       `--premium-packs-dir` to those wheels, activate them and the CPython
//!       packs installed at `--catalog`, then run and score as for Java.
//!
//!   Common flags: [--progress-out <path>] [--limit <n>] [--timeout-secs <s>]
//!       [--call-modeling paranoid|optimistic|require-model]
//!
//!   ossf-cve --benchmark <dir> --trees <dir> --cases-out <path>
//!       [--only <CVE,...>] [--shard k/n] [--timeout-secs <s>] [--call-modeling ...]
//!       Analyze OpenSSF CVE Benchmark cases (#11041): for each CVE, build a
//!       workspace over `<trees>/<CVE>/pre` and `.../post`, run the taint
//!       policy of each category its CWEs map to, and append one record per
//!       CVE to `--cases-out`.
//!
//!   ossf-cve-score --benchmark <dir> --out <path> [--cases <path>,...]
//!       [--codeql <path>]
//!       Score Bifrost's records and the CodeQL reference driver's results by
//!       upstream's rule over the same cases, print a table per tool, and
//!       write the scoreboards.
//!
//! A catalog must already have its bundle installed
//! (`bifrost-semantic-pack install <bundle-dir> <catalog-dir>`, from a
//! `BrokkAi/bifrost-packs` release); the runner never installs into it and
//! opens it read-only.
//!
//! The heavy logic is gated behind the `release-tooling` feature so it stays out
//! of normal runtime builds, matching the other facade tooling binaries.

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(not(feature = "release-tooling"))]
    {
        eprintln!(
            "bifrost_owasp_benchmark requires the `release-tooling` feature; \
             rebuild with `--features release-tooling`."
        );
        ExitCode::FAILURE
    }
    #[cfg(feature = "release-tooling")]
    {
        match imp::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        }
    }
}

#[cfg(feature = "release-tooling")]
mod imp {
    use std::collections::{BTreeMap, BTreeSet};
    use std::env;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use brokk_bifrost::analyzer::semantic_model::{
        CatalogCoordinate, CompilerOptions, SourceFormat, compile_source,
    };
    use brokk_bifrost::ossf_cve_benchmark::{
        CaseRecord, CveCase, RunConfig as OssfCveRunConfig, RunIdentity,
        Scoreboard as OssfCveScoreboard, UPSTREAM_CASES_SHA256 as OSSF_CVE_UPSTREAM_CASES_SHA256,
        UPSTREAM_COMMIT as OSSF_CVE_UPSTREAM_COMMIT, cases_sha256, codeql_records, is_settled,
        load_cases, run_case, score as score_ossf_cve, verdict as ossf_cve_verdict,
    };
    use brokk_bifrost::owasp_benchmark::{
        JavaInputs, PackSpec, PythonInputs, RunConfig, RunResult, SuiteActivation, SuiteInputs,
        build_policy, policy_id, promote_staged_sanitizer_pack, run as run_bakeoff,
    };
    use brokk_bifrost_flow::dataflow::UnmodeledCallBehavior;
    use semver::Version;
    use serde::Serialize;
    use tempfile::NamedTempFile;

    pub fn run() -> Result<(), String> {
        let mut args = env::args().skip(1);
        let command = args.next().ok_or_else(|| {
            "missing subcommand (promote-esapi | run | ossf-cve | ossf-cve-score)".to_owned()
        })?;
        let rest: Vec<String> = args.collect();
        match command.as_str() {
            "promote-esapi" => promote_esapi(&rest),
            "run" => run_command(&rest),
            "ossf-cve" => ossf_cve_command(&rest),
            "ossf-cve-score" => ossf_cve_score_command(&rest),
            other => Err(format!("unknown subcommand: {other}")),
        }
    }

    /// Parse `--flag value` pairs into a map.
    fn parse_flags(args: &[String]) -> Result<BTreeMap<String, String>, String> {
        let mut map = BTreeMap::new();
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            let key = flag
                .strip_prefix("--")
                .ok_or_else(|| format!("expected a --flag, got {flag:?}"))?;
            let value = iter
                .next()
                .ok_or_else(|| format!("flag --{key} needs a value"))?;
            map.insert(key.to_owned(), value.clone());
        }
        Ok(map)
    }

    fn sha256_file(path: &Path) -> Result<String, String> {
        let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
        Ok(brokk_bifrost::analyzer::semantic_model::csmi::sha256_hex(
            &bytes,
        ))
    }

    fn promote_esapi(args: &[String]) -> Result<(), String> {
        let flags = parse_flags(args)?;
        let staged = flags
            .get("staged")
            .ok_or_else(|| "--staged <path> is required".to_owned())?;
        let jar = flags
            .get("jar")
            .ok_or_else(|| "--jar <path> is required".to_owned())?;
        let out = flags
            .get("out")
            .ok_or_else(|| "--out <path> is required".to_owned())?;
        let digest = sha256_file(Path::new(jar))?;
        let staged_json =
            fs::read_to_string(staged).map_err(|error| format!("read {staged}: {error}"))?;
        let pinned = promote_staged_sanitizer_pack(&staged_json, &digest)?;
        // Validate the promoted pack compiles before writing it.
        compile_source(
            SourceFormat::Json,
            pinned.as_bytes(),
            &CompilerOptions::default(),
        )
        .map_err(|diagnostics| format!("promoted pack failed to compile: {diagnostics:#?}"))?;
        if let Some(parent) = Path::new(out).parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("mkdir {}: {error}", parent.display()))?;
        }
        fs::write(out, pinned.as_bytes()).map_err(|error| format!("write {out}: {error}"))?;
        println!("promoted ESAPI pack to {out}");
        println!("esapi artifact sha256: {digest}");
        Ok(())
    }

    /// A pack the run activates, described so both the loader and the artifact
    /// can name it. `file` is resolved under `--packs-dir` (the `semantic-packs`
    /// root), so it carries the pack family subdirectory.
    struct PackDescriptor {
        pack_id: &'static str,
        file: &'static str,
        ecosystem: &'static str,
        package: Option<&'static str>,
        /// An exact package version to advertise in the activation evidence, for
        /// a pack whose shard pins one (the servlet declarations pin `=4.0.1`).
        package_version: Option<&'static str>,
        mandatory: bool,
        /// True when this pack carries a byte-level `artifact_sha256` pin fed
        /// from the resolved jar digest.
        pinned_to_esapi_digest: bool,
    }

    /// The packs the bakeoff activates as curated session content (#1935's
    /// four-blocker punch list, minus the JDK declaration pack). Each is
    /// authored bakeoff content with no real generation-time extraction
    /// behind it: sanitizer knowledge, or behavioral procedure summaries that
    /// mechanical extraction cannot produce from bytecode or source alone.
    /// `SemanticPackCatalog::register_session_pack` is the right mechanism
    /// for exactly this content, because it never has a completeness gate to
    /// bypass -- there is no generation-time `Completeness` to check for
    /// something that was never mechanically extracted.
    ///
    /// This is deliberately not the whole activated set (#2558): the JDK
    /// *declaration* pack is real, generated content (a full extraction of
    /// the JDK's own `src.zip`), and it activates separately through the
    /// product dependency path (`activate_jdk_dependency_pack`, using
    /// `--jdk-catalog`) so #2401's declaration-scoped completeness gate and
    /// gap accounting run on it exactly as they would for a customer. The
    /// servlet-API declaration pack stays here, unlike the JDK one, because
    /// there is no real product-path input for it to converge onto: the
    /// Benchmark's `pom.xml` never declares `javax.servlet-api` (the servlet
    /// container supplies it at deploy time, container-provided rather than
    /// a real Maven dependency), so `target/dependency` never contains its
    /// jar and dependency discovery has nothing to find or produce a pack
    /// from -- converging it would mean fabricating a product-path input a
    /// real customer workspace does not have, which is a different kind of
    /// dishonesty than the one this issue closes.
    const PACKS: &[PackDescriptor] = &[
        PackDescriptor {
            pack_id: "bifrost.java-sanitizers",
            file: "sanitizers/bifrost.java-sanitizers.json",
            ecosystem: "jdk",
            package: None,
            package_version: None,
            mandatory: true,
            pinned_to_esapi_digest: false,
        },
        PackDescriptor {
            pack_id: "bifrost.esapi-sanitizers",
            file: "sanitizers/bifrost.esapi-sanitizers.json",
            ecosystem: "maven",
            package: Some("org.owasp.esapi:esapi"),
            package_version: None,
            mandatory: true,
            pinned_to_esapi_digest: true,
        },
        // bifrost.jdk-framework-decls converged onto the product dependency
        // path (#2558): see the doc comment on `PACKS` above. It is no
        // longer loaded as a session pack; `activate_jdk_dependency_pack`
        // activates the real `bifrost.jdk` bundle instead.
        PackDescriptor {
            pack_id: "bifrost.javax.servlet-api-framework-decls",
            file: "framework-decls/staged/bifrost.javax.servlet-api-framework-decls.json",
            ecosystem: "maven",
            package: Some("javax.servlet:javax.servlet-api"),
            package_version: Some("4.0.1"),
            mandatory: true,
            pinned_to_esapi_digest: false,
        },
        PackDescriptor {
            pack_id: "bifrost.jdk-golden-summaries",
            file: "golden-core/bifrost.jdk-golden-summaries.json",
            ecosystem: "jdk",
            package: None,
            package_version: None,
            mandatory: true,
            pinned_to_esapi_digest: false,
        },
        // #2354: the servlet request/response accessors every Benchmark flow
        // starts at are external interface methods that never materialize, so
        // require-model has no model for them without this pack.
        PackDescriptor {
            pack_id: "bifrost.javax.servlet-api-summaries",
            file: "framework-decls/staged/bifrost.javax.servlet-api-summaries.json",
            ecosystem: "maven",
            package: Some("javax.servlet:javax.servlet-api"),
            package_version: Some("4.0.1"),
            mandatory: true,
            pinned_to_esapi_digest: false,
        },
        // #2354: the summary half of `bifrost.jdk-framework-decls`. #2454
        // declared `java.io.PrintWriter` and gave a chained receiver an
        // identity, so `response.getWriter().println(x)` now names a target;
        // this pack is what models it.
        PackDescriptor {
            pack_id: "bifrost.jdk-framework-summaries",
            file: "framework-decls/staged/bifrost.jdk-framework-summaries.json",
            ecosystem: "jdk",
            package: None,
            package_version: None,
            mandatory: true,
            pinned_to_esapi_digest: false,
        },
        // Keyed `java.util.Map` and `HashMap` collection flows (#10989). A
        // closed local map binds each constant key to its own cell, so a read
        // of a safe key no longer returns a value stored under another one.
        PackDescriptor {
            pack_id: "bifrost.jdk-collection-flows",
            file: "jdk-collections/bifrost.jdk-collection-flows.json",
            ecosystem: "jdk",
            package: None,
            package_version: None,
            mandatory: false,
            pinned_to_esapi_digest: false,
        },
        PackDescriptor {
            pack_id: "bifrost.encoder-sanitizers",
            file: "sanitizers/staged/bifrost.encoder-sanitizers.json",
            ecosystem: "maven",
            package: Some("org.owasp.encoder:encoder"),
            package_version: None,
            mandatory: false,
            pinned_to_esapi_digest: false,
        },
        PackDescriptor {
            pack_id: "bifrost.commons-text-sanitizers",
            file: "sanitizers/staged/bifrost.commons-text-sanitizers.json",
            ecosystem: "maven",
            package: Some("org.apache.commons:commons-text"),
            package_version: None,
            mandatory: false,
            pinned_to_esapi_digest: false,
        },
        PackDescriptor {
            pack_id: "bifrost.guava-sanitizers",
            file: "sanitizers/staged/bifrost.guava-sanitizers.json",
            ecosystem: "maven",
            package: Some("com.google.guava:guava"),
            package_version: None,
            mandatory: false,
            pinned_to_esapi_digest: false,
        },
        PackDescriptor {
            pack_id: "bifrost.spring-web-sanitizers",
            file: "sanitizers/staged/bifrost.spring-web-sanitizers.json",
            ecosystem: "maven",
            package: Some("org.springframework:spring-web"),
            package_version: None,
            mandatory: false,
            pinned_to_esapi_digest: false,
        },
    ];

    fn collect_dependency_jars(deps_dir: &Path) -> Result<Vec<PathBuf>, String> {
        let mut jars = Vec::new();
        let entries = fs::read_dir(deps_dir)
            .map_err(|error| format!("read deps dir {}: {error}", deps_dir.display()))?;
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "jar") {
                jars.push(path);
            }
        }
        jars.sort();
        Ok(jars)
    }

    fn git_head(root: &Path) -> Option<String> {
        let commit = brokk_bifrost_analysis::git_commit(root)?;
        (!commit.is_empty()).then_some(commit)
    }

    #[derive(Serialize)]
    struct Artifact {
        schema: &'static str,
        suite: &'static str,
        benchmark: BenchmarkMeta,
        bifrost: BifrostMeta,
        scope: ScopeMeta,
        policy: PolicyMeta,
        packs: PacksMeta,
        run: RunMeta,
        result: ResultSummary,
        scoring_methodology: Vec<&'static str>,
        headline: Headline,
        category_runs: Vec<brokk_bifrost::owasp_benchmark::CategoryRunStatus>,
        scoreboard: brokk_bifrost::owasp_benchmark::Scoreboard,
    }

    /// A plain-language verdict a reader gets before the tables. Every field is
    /// computed from the run, so the summary is honest for any outcome -- a real
    /// score, a partial one, or a still-near-zero abstention.
    #[derive(Serialize)]
    struct ResultSummary {
        verdict: String,
        headline_number: String,
        false_greens: u32,
        findings: usize,
        real_true_positives: u32,
        honest_vs_naive: String,
        /// Per category, the residual abstention count and a sample binding
        /// diagnostic, for every category that did not fully decide. Empty when
        /// every case reached a verdict.
        remaining_abstention: Vec<String>,
    }

    /// Compute the plain-language result summary from the run outcome.
    fn result_summary(result: &RunResult) -> ResultSummary {
        let overall = &result.scoreboard.overall;
        let fmt_youden = |value: Option<f64>| {
            value.map_or_else(|| "undefined".to_owned(), |v| format!("{v:.4}"))
        };
        let verdict = if overall.real_flagged > 0 || overall.fake_flagged > 0 {
            format!(
                "productive: {} of {} real taint cases flagged as vulnerable (true positives), \
                 {} of {} fake cases flagged (false positives), {} false greens. \
                 {} real and {} fake cases still abstained (no reliable verdict).",
                overall.real_flagged,
                overall.real,
                overall.fake_flagged,
                overall.fake,
                overall.false_greens,
                overall.real_abstained,
                overall.fake_abstained,
            )
        } else {
            format!(
                "still abstains: no case reached a flag over the taint subset. {} real and {} \
                 fake cases abstained; {} cleared. The stack activated but a boundary upstream \
                 of a finding still fails closed (see remaining_abstention and category_runs).",
                overall.real_abstained,
                overall.fake_abstained,
                overall.real_cleared + overall.fake_cleared,
            )
        };
        let honest_vs_naive = format!(
            "naive Youden J = {} folds every abstention into the negatives; honest Youden J = {} \
             scores only the {} cases that reached a reliable verdict and holds out the {} that \
             abstained. The gap is the cost of honest abstention.",
            fmt_youden(overall.naive_metrics.youden),
            fmt_youden(overall.honest_metrics.youden),
            overall.honest.tp
                + overall.honest.fp
                + overall.honest.false_negative
                + overall.honest.tn,
            overall.real_abstained + overall.fake_abstained,
        );
        let mut remaining_abstention = Vec::new();
        for score in &result.scoreboard.per_category {
            let abstained = score.real_abstained + score.fake_abstained;
            if abstained == 0 {
                continue;
            }
            let sample = result
                .category_runs
                .iter()
                .find(|run| run.category == score.category)
                .and_then(|run| run.sample_diagnostics.first())
                .map_or_else(|| "no binding diagnostic recorded".to_owned(), Clone::clone);
            remaining_abstention.push(format!(
                "{}: {} of {} cases abstained ({} real, {} fake); e.g. {}",
                score.category,
                abstained,
                score.total,
                score.real_abstained,
                score.fake_abstained,
                sample,
            ));
        }
        ResultSummary {
            verdict,
            headline_number: format!(
                "naive Youden J = {}; honest Youden J = {} over {} taint cases. {} findings, {} \
                 false positives, {} false greens.",
                fmt_youden(overall.naive_metrics.youden),
                fmt_youden(overall.honest_metrics.youden),
                overall.total,
                result.findings_total,
                overall.fake_flagged,
                overall.false_greens,
            ),
            false_greens: overall.false_greens,
            findings: result.findings_total,
            real_true_positives: overall.real_flagged,
            honest_vs_naive,
            remaining_abstention,
        }
    }

    #[derive(Serialize)]
    struct BenchmarkMeta {
        repo: &'static str,
        commit: String,
        version: &'static str,
        expected_results: &'static str,
    }

    #[derive(Serialize)]
    struct BifrostMeta {
        version: &'static str,
        commit: Option<String>,
    }

    #[derive(Serialize)]
    struct ScopeMeta {
        scored_categories: Vec<&'static str>,
        note: &'static str,
        skipped_non_taint_categories: BTreeMap<String, u32>,
    }

    #[derive(Serialize)]
    struct PolicyMeta {
        call_modeling: &'static str,
        note: &'static str,
        per_category: Vec<CategoryPolicy>,
    }

    #[derive(Serialize)]
    struct CategoryPolicy {
        category: &'static str,
        policy_id: String,
        source: String,
    }

    #[derive(Serialize)]
    struct PacksMeta {
        activated: Vec<String>,
        skipped: Vec<SkippedPack>,
        #[serde(skip_serializing_if = "Option::is_none")]
        esapi: Option<EsapiMeta>,
        /// #2558: the JDK declaration pack, activated through the product
        /// dependency path rather than as a curated session pack.
        #[serde(skip_serializing_if = "Option::is_none")]
        jdk: Option<JdkPackMeta>,
        /// The wheels the premium Python models were pinned to.
        #[serde(skip_serializing_if = "Option::is_none")]
        python_artifacts: Option<Vec<brokk_bifrost::owasp_benchmark::PythonArtifact>>,
    }

    #[derive(Serialize)]
    struct SkippedPack {
        pack_id: String,
        reason: String,
    }

    #[derive(Serialize)]
    struct JdkPackMeta {
        pack_version: &'static str,
        activation_route: &'static str,
        /// Named warning-grade extraction gaps the activated bundle carries.
        /// A reference to a gapped declaration degrades to a typed
        /// `PackExtractionGap` incomplete reason rather than a false absence
        /// proof (#2401); this is the honesty budget the product activation
        /// path enforces.
        gaps: usize,
    }

    #[derive(Serialize)]
    struct EsapiMeta {
        coordinate: &'static str,
        artifact_sha256: Option<String>,
    }

    #[derive(Serialize)]
    struct RunMeta {
        cases_scored: usize,
        cases_with_taint_roots: usize,
        taint_roots: usize,
        findings_total: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        dependency_jars: Option<usize>,
        case_limit: Option<usize>,
        /// The workspace volume the coordinator scales its budget lanes by.
        analyzed_files: usize,
        analyzed_source_bytes: u64,
    }

    #[derive(Serialize)]
    struct Headline {
        note: &'static str,
        overall_naive_youden: Option<f64>,
        overall_honest_youden: Option<f64>,
        real_cases: u32,
        real_flagged_true_positive: u32,
        real_cleared_false_green: u32,
        real_abstained_inconclusive: u32,
    }

    #[derive(Serialize)]
    struct ProgressRunStarted<'a> {
        schema: &'static str,
        event: &'static str,
        suite: &'static str,
        bifrost_version: &'static str,
        bifrost_commit: Option<String>,
        benchmark_repo: &'static str,
        benchmark_commit: Option<String>,
        benchmark_version: &'static str,
        timeout_secs_per_category: u64,
        call_modeling: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        dependency_jars: Option<usize>,
        case_limit: Option<usize>,
        final_artifact: &'a str,
    }

    #[derive(Serialize)]
    struct ProgressTerminal<'a> {
        event: &'static str,
        final_artifact: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<&'a str>,
    }

    fn write_progress_record(
        path: &Path,
        record: &impl Serialize,
        truncate: bool,
    ) -> Result<(), String> {
        let mut rendered = serde_json::to_vec(record)
            .map_err(|error| format!("serialize OWASP progress record: {error}"))?;
        rendered.push(b'\n');
        let mut options = OpenOptions::new();
        options.create(true).write(true);
        if truncate {
            options.truncate(true);
        } else {
            options.append(true);
        }
        let mut file = options
            .open(path)
            .map_err(|error| format!("open OWASP progress {}: {error}", path.display()))?;
        file.write_all(&rendered)
            .map_err(|error| format!("write OWASP progress {}: {error}", path.display()))?;
        file.sync_data()
            .map_err(|error| format!("sync OWASP progress {}: {error}", path.display()))
    }

    fn output_identity(path: &Path) -> Result<PathBuf, String> {
        let file_name = path
            .file_name()
            .ok_or_else(|| format!("output path must name a file: {}", path.display()))?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .map_err(|error| format!("mkdir {}: {error}", parent.display()))?;
        let canonical_parent = fs::canonicalize(parent)
            .map_err(|error| format!("resolve output directory {}: {error}", parent.display()))?;
        Ok(canonical_parent.join(file_name))
    }

    fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .map_err(|error| format!("mkdir {}: {error}", parent.display()))?;
        let mut temporary = NamedTempFile::new_in(parent).map_err(|error| {
            format!(
                "create temporary OWASP artifact beside {}: {error}",
                path.display()
            )
        })?;
        temporary
            .write_all(bytes)
            .and_then(|()| temporary.flush())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|error| format!("write temporary OWASP artifact: {error}"))?;
        temporary.into_temp_path().persist(path).map_err(|error| {
            format!(
                "atomically replace OWASP artifact {}: {error}",
                path.display()
            )
        })
    }

    fn required_dir(flags: &BTreeMap<String, String>, flag: &str) -> Result<PathBuf, String> {
        flags
            .get(flag)
            .map(PathBuf::from)
            .ok_or_else(|| format!("--{flag} <dir> is required"))
    }

    fn java_inputs(flags: &BTreeMap<String, String>) -> Result<JavaInputs, String> {
        let packs_dir = required_dir(flags, "packs-dir")?;
        // #2558: an operator catalog directory with the real `bifrost.jdk`
        // release bundle already installed
        // (`bifrost-semantic-pack install <bundle> <this dir>`). The JDK
        // declaration pack activates from here through the product
        // dependency-pack path, not as a curated session pack.
        let jdk_catalog_root = required_dir(flags, "jdk-catalog")?;
        let esapi_digest = flags.get("esapi-digest").cloned();
        let dependency_jars = match flags.get("deps") {
            Some(dir) => collect_dependency_jars(Path::new(dir))?,
            None => Vec::new(),
        };
        let packs = PACKS
            .iter()
            .map(|descriptor| {
                let version = descriptor
                    .package_version
                    .map(|raw| {
                        Version::parse(raw).map_err(|error| {
                            format!("pack {} version: {error}", descriptor.pack_id)
                        })
                    })
                    .transpose()?;
                Ok(PackSpec {
                    pack_id: descriptor.pack_id.to_owned(),
                    json_path: packs_dir.join(descriptor.file),
                    ecosystem: descriptor.ecosystem.to_owned(),
                    package: descriptor.package.map(|name| CatalogCoordinate {
                        name: name.to_owned(),
                        version: version.clone(),
                    }),
                    artifact_sha256: descriptor
                        .pinned_to_esapi_digest
                        .then(|| esapi_digest.clone())
                        .flatten(),
                    mandatory: descriptor.mandatory,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(JavaInputs {
            dependency_jars,
            packs,
            jdk_catalog_root,
        })
    }

    fn python_inputs(flags: &BTreeMap<String, String>) -> Result<PythonInputs, String> {
        Ok(PythonInputs {
            catalog_root: required_dir(flags, "catalog")?,
            premium_packs_dir: required_dir(flags, "premium-packs-dir")?,
            wheels_dir: required_dir(flags, "wheels")?,
            work_dir: required_dir(flags, "work-dir")?,
        })
    }

    /// `--timeout-secs`, a wall-clock budget per policy run.
    fn timeout_flag(flags: &BTreeMap<String, String>, default: u64) -> Result<Duration, String> {
        Ok(Duration::from_secs(
            flags
                .get("timeout-secs")
                .map(|s| {
                    s.parse::<u64>()
                        .map_err(|error| format!("--timeout-secs: {error}"))
                })
                .transpose()?
                .unwrap_or(default),
        ))
    }

    /// `--call-modeling`. The policy language's own default is `paranoid`.
    /// `require-model` abstains at every unmodeled call, which on the
    /// Benchmark turned almost every case into an abstention rather than a
    /// verdict.
    fn call_modeling_flag(
        flags: &BTreeMap<String, String>,
    ) -> Result<UnmodeledCallBehavior, String> {
        match flags.get("call-modeling").map(String::as_str) {
            None | Some("paranoid") => Ok(UnmodeledCallBehavior::Paranoid),
            Some("optimistic") => Ok(UnmodeledCallBehavior::Optimistic),
            Some("require-model") => Ok(UnmodeledCallBehavior::RequireModel),
            Some(other) => Err(format!(
                "--call-modeling must be paranoid, optimistic, or require-model, not {other:?}"
            )),
        }
    }

    fn run_command(args: &[String]) -> Result<(), String> {
        let flags = parse_flags(args)?;
        let benchmark_root = PathBuf::from(
            flags
                .get("benchmark")
                .ok_or_else(|| "--benchmark <dir> is required".to_owned())?,
        );
        let out = flags
            .get("out")
            .ok_or_else(|| "--out <path> is required".to_owned())?;
        let progress_path = flags
            .get("progress-out")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(format!("{out}.progress.jsonl")));
        let artifact_identity = output_identity(Path::new(out))?;
        let progress_identity = output_identity(&progress_path)?;
        if artifact_identity == progress_identity {
            return Err(format!(
                "--out and --progress-out must name different files: {}",
                artifact_identity.display()
            ));
        }
        let case_limit = flags
            .get("limit")
            .map(|s| {
                s.parse::<usize>()
                    .map_err(|error| format!("--limit: {error}"))
            })
            .transpose()?;
        let timeout = timeout_flag(&flags, 3600)?;
        let call_modeling = call_modeling_flag(&flags)?;

        let inputs = match flags.get("suite").map(String::as_str) {
            None | Some("java") => SuiteInputs::Java(java_inputs(&flags)?),
            Some("python") => SuiteInputs::Python(python_inputs(&flags)?),
            Some(other) => return Err(format!("--suite must be java or python, not {other:?}")),
        };
        let config = RunConfig {
            inputs,
            benchmark_root: benchmark_root.clone(),
            call_modeling,
            timeout,
            case_limit,
            progress_path: Some(progress_path.clone()),
        };

        if let Some(parent) = progress_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|error| format!("mkdir {}: {error}", parent.display()))?;
        }
        write_progress_record(
            &progress_path,
            &ProgressRunStarted {
                schema: "bifrost.owasp-benchmark.progress.v2",
                event: "run_started",
                suite: config.suite().name,
                bifrost_version: env!("CARGO_PKG_VERSION"),
                bifrost_commit: git_head(Path::new(".")),
                benchmark_repo: config.suite().repo,
                benchmark_commit: git_head(&benchmark_root),
                benchmark_version: config.suite().version,
                timeout_secs_per_category: timeout.as_secs(),
                call_modeling: call_modeling.label(),
                dependency_jars: dependency_jar_count(&config),
                case_limit,
                final_artifact: out,
            },
            true,
        )?;
        eprintln!(
            "[owasp-progress] writing progress to {}",
            progress_path.display()
        );

        eprintln!("building benchmark workspace and running taint policies...");
        let result = match run_bakeoff(&config) {
            Ok(result) => result,
            Err(error) => {
                if let Err(progress_error) = write_progress_record(
                    &progress_path,
                    &ProgressTerminal {
                        event: "run_failed",
                        final_artifact: out,
                        error: Some(&error),
                    },
                    false,
                ) {
                    return Err(format!(
                        "{error}; additionally failed to record run_failed: {progress_error}"
                    ));
                }
                return Err(error);
            }
        };
        let artifact = assemble_artifact(&benchmark_root, &result, &flags, &config);
        let mut rendered = serde_json::to_string_pretty(&artifact)
            .map_err(|error| format!("serialize artifact: {error}"))?;
        rendered.push('\n');
        if let Some(parent) = Path::new(out)
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|error| format!("mkdir {}: {error}", parent.display()))?;
        }
        write_atomic(Path::new(out), rendered.as_bytes())?;
        write_progress_record(
            &progress_path,
            &ProgressTerminal {
                event: "run_completed",
                final_artifact: out,
                error: None,
            },
            false,
        )?;

        print_summary(&config, &result);
        println!("wrote artifact to {out}");
        println!("wrote progress stream to {}", progress_path.display());
        Ok(())
    }

    fn assemble_artifact(
        benchmark_root: &Path,
        result: &RunResult,
        flags: &BTreeMap<String, String>,
        config: &RunConfig,
    ) -> Artifact {
        let benchmark_commit = git_head(benchmark_root).unwrap_or_else(|| "unknown".to_owned());
        let suite = config.suite();
        let per_category = suite
            .categories()
            .map(|category| CategoryPolicy {
                category: category.label(),
                policy_id: policy_id(suite, category, config.call_modeling),
                source: build_policy(suite, category, config.call_modeling),
            })
            .collect();
        let overall = &result.scoreboard.overall;
        Artifact {
            schema: "bifrost.owasp-benchmark.v3",
            suite: suite.name,
            benchmark: BenchmarkMeta {
                repo: suite.repo,
                commit: benchmark_commit,
                version: suite.version,
                expected_results: suite.expected_results_file,
            },
            bifrost: BifrostMeta {
                version: env!("CARGO_PKG_VERSION"),
                commit: git_head(Path::new(".")),
            },
            scope: ScopeMeta {
                scored_categories: suite
                    .categories()
                    .map(|category| category.label())
                    .collect(),
                note: "Scores only the injection/taint subset (a source reaches a sink). \
                       The Benchmark's crypto, hash, weakrand, securecookie, and trustbound \
                       categories are not source-to-sink taint problems and are out of scope.",
                skipped_non_taint_categories: result.label_set.skipped_non_taint.clone(),
            },
            policy: PolicyMeta {
                call_modeling: config.call_modeling.label(),
                note: "One taint policy per category, sharing the attacker-controlled source \
                       set and differing only in sinks, so a finding attributes unambiguously \
                       to a category. `call_modeling` decides what crosses a call with neither \
                       an analyzed body nor a model: paranoid propagates, optimistic preserves, \
                       require-model abstains. Cases whose analysis stayed incomplete are scored \
                       as abstentions in the honest matrix either way.",
                per_category,
            },
            packs: PacksMeta {
                activated: result.activated_pack_ids.clone(),
                skipped: result
                    .skipped_packs
                    .iter()
                    .map(|(pack_id, reason)| SkippedPack {
                        pack_id: pack_id.clone(),
                        reason: reason.clone(),
                    })
                    .collect(),
                esapi: matches!(config.inputs, SuiteInputs::Java(_)).then(|| EsapiMeta {
                    coordinate: "org.owasp.esapi:esapi:2.7.0.0",
                    artifact_sha256: flags.get("esapi-digest").cloned(),
                }),
                jdk: match result.activation {
                    SuiteActivation::Java { jdk_pack_gaps } => Some(JdkPackMeta {
                        pack_version: "21.0.8",
                        activation_route: "product:activate_dependency_packs",
                        gaps: jdk_pack_gaps,
                    }),
                    SuiteActivation::Python { .. } => None,
                },
                python_artifacts: match &result.activation {
                    SuiteActivation::Python { python_artifacts } => Some(python_artifacts.clone()),
                    SuiteActivation::Java { .. } => None,
                },
            },
            run: RunMeta {
                cases_scored: result.label_set.cases.len(),
                cases_with_taint_roots: result.cases_with_roots,
                taint_roots: result.taint_roots,
                findings_total: result.findings_total,
                dependency_jars: dependency_jar_count(config),
                case_limit: config.case_limit,
                analyzed_files: result.analyzed_files,
                analyzed_source_bytes: result.analyzed_source_bytes,
            },
            result: result_summary(result),
            scoring_methodology: vec![
                "Each Benchmark case belongs to exactly one category, so each category is scored \
                 over only its own labeled cases.",
                "flagged = Bifrost produced >=1 taint finding of the case's category on the \
                 case's file.",
                "cleared = no finding AND the case's flow analysis reliably concluded (Complete \
                 or ProvenBySummary on every root that touched it).",
                "abstained = no finding AND the analysis was Inconclusive, or no taint root \
                 formed at all.",
                "naive score: an abstention folds into the negatives (an abstained real is a \
                 false negative, an abstained fake is a true negative).",
                "honest score: abstentions are excluded from the confusion matrix and reported \
                 separately. The gap between naive and honest is the cost of honest abstention.",
                "false green = a real vulnerability Bifrost affirmatively cleared as safe. The \
                 'no false greens' pitch is that this count stays near zero: when Bifrost cannot \
                 prove safety it abstains rather than clearing.",
                "TPR = TP/(TP+FN); FPR = FP/(FP+TN); Youden J = TPR - FPR.",
            ],
            headline: Headline {
                note: "Overall Youden over the taint subset, both ways, plus the real-case \
                       disposition that carries the honest-completion story.",
                overall_naive_youden: overall.naive_metrics.youden,
                overall_honest_youden: overall.honest_metrics.youden,
                real_cases: overall.real,
                real_flagged_true_positive: overall.real_flagged,
                real_cleared_false_green: overall.real_cleared,
                real_abstained_inconclusive: overall.real_abstained,
            },
            category_runs: result.category_runs.clone(),
            scoreboard: result.scoreboard.clone(),
        }
    }

    fn print_summary(config: &RunConfig, result: &RunResult) {
        let board = &result.scoreboard;
        println!("== OWASP {} taint bakeoff ==", config.suite().name);
        println!(
            "cases scored: {}, cases with taint roots: {}, taint roots: {}, findings: {}",
            result.label_set.cases.len(),
            result.cases_with_roots,
            result.taint_roots,
            result.findings_total
        );
        println!("activated packs: {:?}", result.activated_pack_ids);
        if !result.skipped_packs.is_empty() {
            println!("skipped packs: {:?}", result.skipped_packs);
        }
        println!();
        println!("run-level taint completion per category:");
        for status in &result.category_runs {
            let termination = status
                .termination
                .as_deref()
                .map(|termination| format!(" [terminated: {termination}]"))
                .unwrap_or_default();
            println!(
                "  {:<12} {}{} (findings={}, retained={})",
                status.category,
                status.completion,
                termination,
                status.findings,
                status.retained_analyses
            );
            if let Some(sample) = status.sample_diagnostics.first() {
                println!("      e.g. {sample}");
            }
        }
        println!();
        println!(
            "{:<12} {:>5} {:>5} {:>5} | naive TPR/FPR/J     | honest TPR/FPR/J    | compl C/PbS/Inc/NA | false-green",
            "category", "total", "real", "fake"
        );
        for score in board
            .per_category
            .iter()
            .chain(std::iter::once(&board.overall))
        {
            println!(
                "{:<12} {:>5} {:>5} {:>5} | {:>5}/{:>5}/{:>6} | {:>5}/{:>5}/{:>6} | {:>4}/{:>4}/{:>4}/{:>4} | {}",
                score.category,
                score.total,
                score.real,
                score.fake,
                fmt_rate(score.naive_metrics.tpr),
                fmt_rate(score.naive_metrics.fpr),
                fmt_rate(score.naive_metrics.youden),
                fmt_rate(score.honest_metrics.tpr),
                fmt_rate(score.honest_metrics.fpr),
                fmt_rate(score.honest_metrics.youden),
                score.completion.complete,
                score.completion.proven_by_summary,
                score.completion.inconclusive,
                score.completion.not_analyzed,
                score.false_greens,
            );
        }
    }

    /// The Java run's dependency jar count; Python has no jars.
    fn dependency_jar_count(config: &RunConfig) -> Option<usize> {
        match &config.inputs {
            SuiteInputs::Java(inputs) => Some(inputs.dependency_jars.len()),
            SuiteInputs::Python(_) => None,
        }
    }

    fn fmt_rate(value: Option<f64>) -> String {
        value.map_or_else(|| "-".to_owned(), |v| format!("{v:.2}"))
    }

    /// Analyze OpenSSF CVE Benchmark cases and append one record per CVE to
    /// `--cases-out`. CVEs already recorded there are skipped, so an
    /// interrupted run resumes, and `--shard k/n` splits the cases across
    /// processes that write separate files.
    fn ossf_cve_command(args: &[String]) -> Result<(), String> {
        let flags = parse_flags(args)?;
        let config = OssfCveRunConfig {
            benchmark_root: required_dir(&flags, "benchmark")?,
            trees_root: required_dir(&flags, "trees")?,
            call_modeling: call_modeling_flag(&flags)?,
            timeout: timeout_flag(&flags, 600)?,
        };
        let cases_out = PathBuf::from(
            flags
                .get("cases-out")
                .ok_or_else(|| "--cases-out <path> is required".to_owned())?,
        );
        let only: Option<BTreeSet<&str>> = flags
            .get("only")
            .map(|list| list.split(',').map(str::trim).collect());
        let (shard, shards) = match flags.get("shard") {
            None => (0, 1),
            Some(spec) => {
                let (k, n) = spec
                    .split_once('/')
                    .ok_or_else(|| format!("--shard must be k/n, not {spec:?}"))?;
                let k: usize = k.parse().map_err(|error| format!("--shard: {error}"))?;
                let n: usize = n.parse().map_err(|error| format!("--shard: {error}"))?;
                if n == 0 || k >= n {
                    return Err(format!("--shard needs 0 <= k < n, not {spec:?}"));
                }
                (k, n)
            }
        };
        // A record from another binary or other settings must not be
        // resumed into this run: the file would mix configurations. Records
        // that are not settled (errors, unavailable trees, timed-out or
        // failed runs) are retried; a later line supersedes an earlier one
        // when the file is scored.
        let identity = config.identity();
        let cases = load_cases(&config.benchmark_root)?;
        let by_cve: BTreeMap<&str, &CveCase> =
            cases.iter().map(|case| (case.cve.as_str(), case)).collect();
        let mut done = BTreeSet::new();
        for record in read_case_records(&cases_out)? {
            if record.identity.as_ref() != Some(&identity) {
                return Err(format!(
                    "{} holds {} recorded by {:?}, not this run's {identity:?}; write to another file",
                    cases_out.display(),
                    record.cve,
                    record.identity
                ));
            }
            if by_cve
                .get(record.cve.as_str())
                .is_some_and(|case| is_settled(case, &record))
            {
                done.insert(record.cve);
            }
        }
        let selected: Vec<_> = cases
            .iter()
            .enumerate()
            .filter(|(index, case)| {
                index % shards == shard
                    && only
                        .as_ref()
                        .is_none_or(|only| only.contains(case.cve.as_str()))
                    && !done.contains(&case.cve)
            })
            .map(|(_, case)| case)
            .collect();
        eprintln!(
            "[ossf-cve] {} cases to run ({} already recorded in {})",
            selected.len(),
            done.len(),
            cases_out.display()
        );
        for (ordinal, case) in selected.iter().enumerate() {
            eprintln!(
                "[ossf-cve] {}/{} {} {:?}",
                ordinal + 1,
                selected.len(),
                case.cve,
                case.categories
            );
            let record = run_case(&config, case);
            eprintln!(
                "[ossf-cve] {} {:?} in {:.0}s: {:?}",
                case.cve,
                record.status,
                record.seconds,
                ossf_cve_verdict(case, &record)
            );
            let line = serde_json::to_string(&record)
                .map_err(|error| format!("serialize {}: {error}", case.cve))?;
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&cases_out)
                .map_err(|error| format!("open {}: {error}", cases_out.display()))?;
            writeln!(file, "{line}")
                .and_then(|()| file.sync_data())
                .map_err(|error| format!("write {}: {error}", cases_out.display()))?;
        }
        Ok(())
    }

    /// Every record in one `ossf-cve` output file; an absent file has none.
    fn read_case_records(path: &Path) -> Result<Vec<CaseRecord>, String> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("read {}: {error}", path.display())),
        };
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line).map_err(|error| format!("{}: {error}", path.display()))
            })
            .collect()
    }

    /// Score recorded OpenSSF CVE Benchmark runs: Bifrost's records from one
    /// or more `--cases` files (comma-separated, for shards) and, with
    /// `--codeql`, the CodeQL reference driver's lines, by the same rule over
    /// the same cases. Prints a table per tool and writes the scoreboards.
    fn ossf_cve_score_command(args: &[String]) -> Result<(), String> {
        let flags = parse_flags(args)?;
        let cases = load_cases(&required_dir(&flags, "benchmark")?)?;
        let out = flags
            .get("out")
            .ok_or_else(|| "--out <path> is required".to_owned())?;
        let mut boards = BTreeMap::new();
        let mut bifrost_identity = None;
        if let Some(files) = flags.get("cases") {
            let mut records = BTreeMap::new();
            for file in files.split(',') {
                for record in read_case_records(Path::new(file))? {
                    // Shards are combined only when one binary and one set
                    // of settings produced them all, and every record says
                    // which.
                    let (Some(identity), Some(_)) = (&record.identity, &record.metadata_sha256)
                    else {
                        return Err(format!(
                            "{file}: {} carries no run identity or metadata digest",
                            record.cve
                        ));
                    };
                    match &bifrost_identity {
                        None => bifrost_identity = Some(identity.clone()),
                        Some(first) if first == identity => {}
                        Some(first) => {
                            return Err(format!(
                                "{file}: {} was recorded by {identity:?}, other records by {first:?}",
                                record.cve
                            ));
                        }
                    }
                    records.insert(record.cve.clone(), record);
                }
            }
            boards.insert("bifrost", score_ossf_cve(&cases, &records));
        }
        if let Some(file) = flags.get("codeql") {
            let text = fs::read_to_string(file).map_err(|error| format!("read {file}: {error}"))?;
            boards.insert("codeql", score_ossf_cve(&cases, &codeql_records(&text)?));
        }
        if boards.is_empty() {
            return Err("give --cases <jsonl>[,<jsonl>...] and/or --codeql <jsonl>".to_owned());
        }
        // Each CVE counts once in `total` and once under every category its
        // CWEs map to, whichever policy found it: the rows group CVEs, as
        // upstream scores whole CVEs, so both tools' rows cover the same set.
        let cases_digest = cases_sha256(&cases);
        if cases_digest != OSSF_CVE_UPSTREAM_CASES_SHA256 {
            eprintln!(
                "[ossf-cve] the case metadata (sha256 {cases_digest}) is not upstream {OSSF_CVE_UPSTREAM_COMMIT}'s; the artifact names no upstream commit"
            );
        }
        for (tool, board) in &boards {
            println!("{tool} (rows group CVEs by their CWE categories)");
            println!(
                "  {:<11} {:>4} {:>8} {:>8} {:>8} {:>8} | {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} | {:>5} {:>5} {:>5}",
                "category",
                "cves",
                "detected",
                "patched",
                "still",
                "unknown",
                "noalert",
                "timeout",
                "failed",
                "nosink",
                "noroot",
                "inconcl",
                "subset",
                "scope",
                "unav",
                "error"
            );
            for (category, tally) in board
                .per_category
                .iter()
                .chain([(&"total".to_owned(), &board.total)])
            {
                println!(
                    "  {:<11} {:>4} {:>8} {:>8} {:>8} {:>8} | {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} | {:>5} {:>5} {:>5}",
                    category,
                    tally.cves,
                    tally.detected,
                    tally.patch_recognized,
                    tally.patch_still_reported,
                    tally.patch_unknown,
                    tally.missed_no_alert,
                    tally.missed_timed_out,
                    tally.missed_run_failed,
                    tally.missed_no_sink_selected,
                    tally.missed_not_analyzed,
                    tally.missed_inconclusive,
                    tally.missed_subset_complete,
                    tally.out_of_scope,
                    tally.unavailable,
                    tally.error,
                );
            }
            for (cause, count) in &board.miss_causes {
                println!("  inconclusive-miss cause {cause}: {count}");
            }
            for (family, count) in &board.run_failures {
                println!("  run-failure {family}: {count}");
            }
        }
        #[derive(Serialize)]
        struct Artifact<'a> {
            schema: &'static str,
            /// The digest of the case metadata that was scored.
            cases_sha256: String,
            /// The pinned upstream commit, only when the scored metadata is
            /// that commit's; `None` for a modified or other checkout.
            upstream_commit: Option<&'static str>,
            /// The binary and settings that produced the Bifrost records.
            bifrost_run: Option<RunIdentity>,
            scoreboards: &'a BTreeMap<&'static str, OssfCveScoreboard>,
        }
        let artifact = Artifact {
            schema: "bifrost.ossf-cve-benchmark.v3",
            upstream_commit: (cases_digest == OSSF_CVE_UPSTREAM_CASES_SHA256)
                .then_some(OSSF_CVE_UPSTREAM_COMMIT),
            cases_sha256: cases_digest,
            bifrost_run: bifrost_identity,
            scoreboards: &boards,
        };
        let json = serde_json::to_string_pretty(&artifact)
            .map_err(|error| format!("serialize the scoreboards: {error}"))?;
        fs::write(out, json + "\n").map_err(|error| format!("write {out}: {error}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn output_identity_collapses_equivalent_parent_paths() {
            let scratch = tempfile::tempdir().expect("scratch dir");
            let direct = scratch.path().join("result.json");
            let dotted = scratch.path().join(".").join("result.json");
            assert_eq!(
                output_identity(&direct).expect("direct identity"),
                output_identity(&dotted).expect("dotted identity")
            );
        }

        #[test]
        fn atomic_write_replaces_the_complete_artifact() {
            let scratch = tempfile::tempdir().expect("scratch dir");
            let output = scratch.path().join("result.json");
            fs::write(&output, b"old").expect("write old artifact");
            write_atomic(&output, b"{\"complete\":true}\n").expect("replace artifact");
            assert_eq!(
                fs::read_to_string(output).expect("read replacement"),
                "{\"complete\":true}\n"
            );
        }
    }
}
