//! Query execution reads the selected durable publication, never build files.
use super::*;
use crate::query::{DependencyEvidenceFilter, DependencyEvidenceSeed};
use brokk_bifrost_analysis::analyzer::semantic_model::DependencyEvidence;

#[derive(Debug, Clone)]
pub(super) struct DependencyEvidenceValue {
    pub(super) row: Arc<DependencyEvidence>,
    pub(super) file: ProjectFile,
    pub(super) location:
        Option<brokk_bifrost_analysis::analyzer::semantic_model::DependencyEvidenceLocation>,
}
impl DependencyEvidenceValue {
    pub(super) fn display_range(&self) -> Option<CodeQueryRange> {
        self.location.map(|l| CodeQueryRange {
            start_line: l.start_line,
            start_column: l.start_column,
            end_line: l.end_line,
            end_column: l.end_column,
        })
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }
}
fn axis(values: &[String], value: Option<&str>) -> bool {
    values.is_empty() || value.is_some_and(|value| values.iter().any(|v| v == value))
}
enum VersionRange {
    Cargo(semver::VersionReq),
    Npm(brokk_bifrost_js_ts_analysis::dependency_evidence::NpmVersionRange),
    Nuget(brokk_bifrost_csharp_analysis::dependency_evidence::NugetVersionRange),
    Go(brokk_bifrost_go_analysis::analyzer::GoVersionRange),
    Ruby(brokk_bifrost_ruby_analysis::analyzer::RubyVersionRange),
    Composer(brokk_bifrost_php_analysis::analyzer::ComposerVersionRange),
    Maven(brokk_bifrost_jvm_analysis::analyzer::MavenVersionRange),
}

/// Parse one validated range with its ecosystem's own version semantics.
fn version_range(ecosystem: &str, requirement: &str) -> VersionRange {
    match ecosystem {
        "npm" => VersionRange::Npm(
            brokk_bifrost_js_ts_analysis::dependency_evidence::NpmVersionRange::parse(requirement)
                .expect("validated npm range"),
        ),
        "nuget" => VersionRange::Nuget(
            brokk_bifrost_csharp_analysis::dependency_evidence::NugetVersionRange::parse(
                requirement,
            )
            .expect("validated NuGet range"),
        ),
        brokk_bifrost_go_analysis::analyzer::GO_MODULE_ECOSYSTEM
        | brokk_bifrost_go_analysis::analyzer::GO_TOOLCHAIN_ECOSYSTEM => VersionRange::Go(
            brokk_bifrost_go_analysis::analyzer::GoVersionRange::parse(ecosystem, requirement)
                .expect("validated Go range"),
        ),
        brokk_bifrost_ruby_analysis::analyzer::RUBYGEMS_ECOSYSTEM
        | brokk_bifrost_ruby_analysis::analyzer::RUBY_TOOLCHAIN_ECOSYSTEM => VersionRange::Ruby(
            brokk_bifrost_ruby_analysis::analyzer::RubyVersionRange::parse(ecosystem, requirement)
                .expect("validated Ruby range"),
        ),
        brokk_bifrost_php_analysis::analyzer::COMPOSER_ECOSYSTEM
        | brokk_bifrost_php_analysis::analyzer::PHP_TOOLCHAIN_ECOSYSTEM => VersionRange::Composer(
            brokk_bifrost_php_analysis::analyzer::ComposerVersionRange::parse(
                ecosystem,
                requirement,
            )
            .expect("validated Composer range"),
        ),
        brokk_bifrost_jvm_analysis::analyzer::MAVEN_ECOSYSTEM
        | brokk_bifrost_jvm_analysis::analyzer::JVM_TOOLCHAIN_ECOSYSTEM => VersionRange::Maven(
            brokk_bifrost_jvm_analysis::analyzer::MavenVersionRange::parse(ecosystem, requirement)
                .expect("validated Maven range"),
        ),
        "cargo" | brokk_bifrost_rust_analysis::analyzer::RUST_TOOLCHAIN_ECOSYSTEM => {
            VersionRange::Cargo(
                semver::VersionReq::parse(requirement).expect("validated Cargo range"),
            )
        }
        _ => unreachable!("version range ecosystems are validated"),
    }
}
/// Reuse the seed's strict ecosystem-specific version interpretation for a
/// mitigation on this exact row. Unsupported evidence stays unknown.
pub(super) fn mitigation_version_predicate(
    ecosystem: &str,
    requirements: &[String],
) -> impl Fn(&DependencyEvidence) -> Option<bool> {
    let ranges = requirements
        .iter()
        .map(|requirement| version_range(ecosystem, requirement))
        .collect::<Vec<_>>();
    let filter = DependencyEvidenceFilter {
        ecosystems: vec![ecosystem.to_owned()],
        ..Default::default()
    };
    move |row| matches(row, &filter, &ranges).ok()
}

/// Why a row's predicate is unknown: the predicate's name and the reason.
type Unresolved = (&'static str, String);

fn matches(
    row: &DependencyEvidence,
    filter: &DependencyEvidenceFilter,
    ranges: &[VersionRange],
) -> Result<bool, Unresolved> {
    if !(axis(&filter.ecosystems, Some(&row.ecosystem))
        && axis(&filter.packages, Some(&row.package))
        && axis(&filter.kinds, Some(row.kind.label()))
        && axis(&filter.exact_versions, row.exact_version.as_deref())
        && axis(&filter.sources, row.source.as_deref())
        && axis(&filter.declared_by, row.declared_by.as_deref())
        && axis(&filter.scopes, Some(row.scope.label()))
        && lock_association_matches(row, &filter.lock_associations))
    {
        return Ok(false);
    }
    // Three-valued AND: a definite false on either predicate wins over the
    // other's unknown.
    let features = requests_feature(row, &filter.features).map_err(|e| ("feature", e));
    if features == Ok(false) {
        return Ok(false);
    }
    let version = version_matches(row, ranges).map_err(|e| ("version", e));
    match (features, version) {
        (_, Ok(false)) => Ok(false),
        (Err(unresolved), _) | (_, Err(unresolved)) => Err(unresolved),
        (Ok(_), Ok(true)) => Ok(true),
    }
}

/// Whether a Cargo row's recorded lock association is one of `wanted`. A
/// member owns its direct lock instance and every transitive copy through
/// `declared_by`; the association is what tells them apart (#9919). The
/// producer records it on every declaration and owned lock row, so a row
/// without one (an unowned lock instance) is a definite non-match.
fn lock_association_matches(row: &DependencyEvidence, wanted: &[String]) -> bool {
    wanted.is_empty()
        || row.conditions.iter().any(|condition| {
            condition.kind == "cargo.lock_association" && wanted.contains(&condition.value)
        })
}

/// Whether the manifest that owns this Cargo row requests any of `features`
/// of the row's package. A request is not an enabled build feature, and the
/// absence of an explicit request is a definite `false` only when nothing in
/// the owning manifest can request the feature indirectly: the package's
/// default features (whose list a files-only checkout does not have), a
/// member-level `default-features` setting, a member `[features]` entry that
/// forwards to this dependency, or another requested feature that the
/// package's own feature table may imply. Rows that record no request of
/// their own (an unowned or transitive lock instance) are unknown.
fn requests_feature(row: &DependencyEvidence, features: &[String]) -> Result<bool, String> {
    if features.is_empty() {
        return Ok(true);
    }
    let values = |kind: &'static str| {
        row.conditions
            .iter()
            .filter(move |condition| condition.kind == kind)
            .map(|condition| condition.value.as_str())
    };
    if values("cargo.default_features").next().is_none()
        || values("cargo.lock_association").any(|value| value == "transitive")
    {
        return Err("the row records no feature request of its own".into());
    }
    let requested = values("cargo.requested_feature").collect::<Vec<_>>();
    if requested
        .iter()
        .any(|feature| features.iter().any(|wanted| wanted == feature))
    {
        return Ok(true);
    }
    if values("cargo.default_features")
        .chain(values("cargo.member_default_features"))
        .any(|value| value == "true")
    {
        return Err("default features are enabled and their list is unknown".into());
    }
    let conditional = values("cargo.conditional_requested_feature").collect::<Vec<_>>();
    if !conditional.is_empty() {
        return Err(format!(
            "member feature tables request {conditional:?} when enabled"
        ));
    }
    if !requested.is_empty() {
        return Err(format!(
            "the package's own feature table may imply a requested feature from {requested:?}"
        ));
    }
    Ok(false)
}

fn version_matches(row: &DependencyEvidence, ranges: &[VersionRange]) -> Result<bool, String> {
    const NO_EXACT: &str = "no complete exact version evidence";
    if ranges.is_empty() {
        return Ok(true);
    }
    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyEvidenceKind;
    if !row.complete
        || !matches!(
            row.kind,
            DependencyEvidenceKind::Locked | DependencyEvidenceKind::Installed
        )
    {
        return Err(NO_EXACT.into());
    }
    let mut matched = false;
    for range in ranges {
        matched |= match range {
            VersionRange::Npm(range) => {
                brokk_bifrost_js_ts_analysis::dependency_evidence::npm_dependency_version_matches(row, range)
                    .map_err(|e| e.to_string())?
                    .ok_or(NO_EXACT)?
            }
            VersionRange::Nuget(range) => {
                brokk_bifrost_csharp_analysis::dependency_evidence::nuget_dependency_version_matches(row, range)?
                    .ok_or(NO_EXACT)?
            }
            VersionRange::Go(range) => {
                brokk_bifrost_go_analysis::analyzer::go_dependency_version_matches(row, range)?
                    .ok_or(NO_EXACT)?
            }
            VersionRange::Ruby(range) => {
                brokk_bifrost_ruby_analysis::analyzer::ruby_dependency_version_matches(row, range)?
                    .ok_or(NO_EXACT)?
            }
            VersionRange::Composer(range) => {
                brokk_bifrost_php_analysis::analyzer::composer_dependency_version_matches(
                    row, range,
                )?
                .ok_or(NO_EXACT)?
            }
            VersionRange::Maven(range) => {
                brokk_bifrost_jvm_analysis::analyzer::maven_dependency_version_matches(row, range)?
                    .ok_or(NO_EXACT)?
            }
            VersionRange::Cargo(range) => {
                let raw = row.exact_version.as_deref().ok_or(NO_EXACT)?;
                let version = semver::Version::parse(raw).map_err(|e| e.to_string())?;
                range.matches(&version)
            }
        };
    }
    Ok(matched)
}
pub(super) fn execute_dependency_evidence_seed(
    seed: &DependencyEvidenceSeed,
    terminal_cap: Option<usize>,
    state: &mut QueryExecutionState<'_>,
    limits: CodeQueryExecutionLimits,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> PlanExecution {
    if state
        .cancellation
        .is_some_and(CancellationToken::is_cancelled)
    {
        return PlanExecution::cancelled(Vec::new());
    }
    let cap = terminal_cap.unwrap_or(limits.max_pipeline_rows).min(
        limits
            .max_pipeline_rows
            .saturating_sub(state.budget.pipeline_rows),
    );
    let ranges = seed
        .filter
        .version_ranges
        .iter()
        .map(|range| version_range(&seed.filter.ecosystems[0], range))
        .collect::<Vec<_>>();
    let evidence = match state.analyzer.dependency_file_evidence() {
        Ok(evidence) => evidence,
        Err(error) => {
            brokk_bifrost_core::profiling::note_with(|| {
                format!(
                    "policy.units unbounded origin={}:{} cause=provider:dependency_evidence detail={error:?}",
                    file!(),
                    line!()
                )
            });
            state.analyzer.mark_execution_dependent();
            diagnostics.push(super::QueryExecutionState::diagnostic(
                state.analyzer,
                CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                    incompleteness: brokk_bifrost_rql::Incompleteness::Operational(
                        brokk_bifrost_rql::DiagnosticExecutionCause::Provider,
                    ),
                    related: Vec::new(),
                    source: None,
                    code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "workspace",
                    message: format!("static dependency publication is unavailable: {error}"),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                }),
                Some(DerivationExecutionCause::Provider),
            ));
            return PlanExecution::truncated(Vec::new());
        }
    };
    let mut incomplete = !evidence.complete();
    for gap in &evidence.gaps {
        diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
            incompleteness: Incompleteness::Content,
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message: format!(
                "dependency evidence {:?} at {}:{}..{}: {}",
                gap.kind,
                crate::path_utils::workspace_relative_slash_path(&gap.build_file),
                gap.byte_range.start,
                gap.byte_range.end,
                gap.message
            ),
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        }));
    }
    let locations = match state.analyzer.dependency_file_locations() {
        Ok(locations) => locations.into_iter().collect::<HashMap<_, _>>(),
        Err(error) => {
            incomplete = true;
            diagnostics.push(super::QueryExecutionState::diagnostic(
                state.analyzer,
                CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                    incompleteness: brokk_bifrost_rql::Incompleteness::Operational(
                        brokk_bifrost_rql::DiagnosticExecutionCause::Provider,
                    ),
                    related: Vec::new(),
                    source: None,
                    code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "workspace",
                    message: format!("dependency source presentation proof unavailable: {error}"),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                }),
                Some(DerivationExecutionCause::Provider),
            ));
            HashMap::default()
        }
    };
    let mut rows = Vec::new();
    let mut indexes = HashMap::default();
    let mut truncated = incomplete;
    let mut missing_location_reported = false;
    for row in evidence.rows {
        if state
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return PlanExecution::cancelled(Vec::new());
        }
        let file = ProjectFile::new(state.analyzer.project().root(), row.build_file.clone());
        if !seed.where_globs.matches(&rel_path_string(&file)) {
            continue;
        }
        match matches(&row, &seed.filter, &ranges) {
            Ok(true) => {}
            Ok(false) => continue,
            Err((predicate, reason)) => {
                truncated = true;
                diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                    incompleteness: Incompleteness::Content,
                    related: Vec::new(),
                    source: None,
                    code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "workspace",
                    message: format!(
                        "dependency {predicate} predicate unresolved for {} at {}: {reason}",
                        row.id(),
                        crate::path_utils::workspace_relative_slash_path(&row.build_file),
                    ),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                }));
                continue;
            }
        }
        if !locations.contains_key(&row.id()) && !missing_location_reported {
            missing_location_reported = true;
            truncated = true;
            diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
                incompleteness: Incompleteness::Content,
                related: Vec::new(),
                source: None,
                code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: "workspace",
                message: "selected dependency rows lack retained source presentation proof".into(),
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            }));
        }
        if rows.len() >= cap {
            truncated = true;
            push_pipeline_budget_diagnostic(diagnostics, &state.budget);
            break;
        }
        state.budget.pipeline_rows = state.budget.pipeline_rows.saturating_add(1);
        insert_pipeline_row(
            &mut rows,
            &mut indexes,
            PipelineValue::DependencyEvidence(DependencyEvidenceValue {
                location: locations.get(&row.id()).copied(),
                row: Arc::new(row),
                file,
            }),
            Vec::new(),
            false,
        );
    }
    PlanExecution::new(rows, truncated)
}
pub(super) fn public_row(value: &DependencyEvidenceValue) -> results::CodeQueryDependencyEvidence {
    let row = &value.row;
    results::CodeQueryDependencyEvidence {
        id: row.id(),
        path: rel_path_string(&value.file),
        ecosystem: row.ecosystem.clone(),
        package: row.package.clone(),
        evidence_kind: row.kind.label().into(),
        version_requirement: row.version_requirement.clone(),
        exact_version: row.exact_version.clone(),
        source: row.source.clone(),
        locator: row.locator.clone(),
        declared_by: row.declared_by.clone(),
        scope: row.scope.label().into(),
        conditions: row
            .conditions
            .iter()
            .map(|c| results::CodeQueryDependencyCondition {
                kind: c.kind.clone(),
                value: c.value.clone(),
            })
            .collect(),
        source_digest: row.source_digest.clone(),
        range: value.display_range(),
        start_byte: row.byte_range.start,
        end_byte: row.byte_range.end,
        complete: row.complete,
    }
}

pub(super) fn evidence_key(value: &DependencyEvidenceValue) -> DetailedCodeQueryKey {
    let row = &value.row;
    DetailedCodeQueryKey::DependencyEvidence {
        id: row.id(),
        ecosystem: row.ecosystem.clone(),
        package: row.package.clone(),
        evidence_kind: row.kind.label().into(),
        scope: row.scope.label().into(),
        source_digest: row.source_digest.clone(),
        version_requirement: row.version_requirement.clone(),
        exact_version: row.exact_version.clone(),
        source: row.source.clone(),
        declared_by: row.declared_by.clone(),
    }
}
