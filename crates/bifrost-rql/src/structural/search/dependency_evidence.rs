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
}
/// Reuse the seed's strict ecosystem-specific version interpretation for a
/// mitigation on this exact row. Unsupported evidence stays unknown.
pub(super) fn mitigation_version_predicate(
    ecosystem: &str,
    requirements: &[String],
) -> impl Fn(&DependencyEvidence) -> Option<bool> {
    let ranges = requirements
        .iter()
        .map(|requirement| match ecosystem {
            "npm" => VersionRange::Npm(
                brokk_bifrost_js_ts_analysis::dependency_evidence::NpmVersionRange::parse(
                    requirement,
                )
                .expect("validated mitigation range"),
            ),
            "cargo" => VersionRange::Cargo(
                semver::VersionReq::parse(requirement).expect("validated mitigation range"),
            ),
            _ => unreachable!("mitigation ecosystems are validated"),
        })
        .collect::<Vec<_>>();
    let filter = DependencyEvidenceFilter {
        ecosystems: vec![ecosystem.to_owned()],
        ..Default::default()
    };
    move |row| matches(row, &filter, &ranges).ok().flatten()
}

fn matches(
    row: &DependencyEvidence,
    filter: &DependencyEvidenceFilter,
    ranges: &[VersionRange],
) -> Result<Option<bool>, String> {
    if !(axis(&filter.ecosystems, Some(&row.ecosystem))
        && axis(&filter.packages, Some(&row.package))
        && axis(&filter.kinds, Some(row.kind.label()))
        && axis(&filter.exact_versions, row.exact_version.as_deref())
        && axis(&filter.sources, row.source.as_deref())
        && axis(&filter.declared_by, row.declared_by.as_deref())
        && axis(&filter.scopes, Some(row.scope.label())))
    {
        return Ok(Some(false));
    }
    if ranges.is_empty() {
        return Ok(Some(true));
    }
    use brokk_bifrost_analysis::analyzer::semantic_model::DependencyEvidenceKind;
    if !row.complete
        || !matches!(
            row.kind,
            DependencyEvidenceKind::Locked | DependencyEvidenceKind::Installed
        )
    {
        return Ok(None);
    }
    let mut matched = false;
    for range in ranges {
        matched |= match range {
            VersionRange::Npm(range) => {
                let value = brokk_bifrost_js_ts_analysis::dependency_evidence::npm_dependency_version_matches(row, range)
                    .map_err(|e| e.to_string())?;
                let Some(value) = value else {
                    return Ok(None);
                };
                value
            }
            VersionRange::Cargo(range) => {
                let Some(raw) = row.exact_version.as_deref() else {
                    return Ok(None);
                };
                let version = semver::Version::parse(raw).map_err(|e| e.to_string())?;
                range.matches(&version)
            }
        };
    }
    Ok(Some(matched))
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
        return cancelled_plan_execution();
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
        .map(|range| {
            if seed.filter.ecosystems == ["npm"] {
                VersionRange::Npm(
                    brokk_bifrost_js_ts_analysis::dependency_evidence::NpmVersionRange::parse(
                        range,
                    )
                    .expect("validated npm requirement"),
                )
            } else {
                VersionRange::Cargo(
                    semver::VersionReq::parse(range).expect("validated Cargo requirement"),
                )
            }
        })
        .collect::<Vec<_>>();
    let evidence = match state.analyzer.dependency_file_evidence() {
        Ok(evidence) => evidence,
        Err(error) => {
            diagnostics.push(CodeQueryDiagnostic {
                related: Vec::new(),
                source: None,
                code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: "workspace",
                message: format!("static dependency publication is unavailable: {error}"),
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            });
            return PlanExecution {
                rows: Vec::new(),
                truncated: true,
                cancelled: false,
                pipeline_halted: false,
            };
        }
    };
    let mut incomplete = !evidence.complete();
    for gap in &evidence.gaps {
        diagnostics.push(CodeQueryDiagnostic {
            related: Vec::new(),
            source: None,
            code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
            impact: CodeQueryDiagnosticImpact::Incomplete,
            branch: Vec::new(),
            language: "workspace",
            message: format!(
                "dependency evidence {:?} at {}:{}..{}: {}",
                gap.kind,
                gap.build_file.display(),
                gap.byte_range.start,
                gap.byte_range.end,
                gap.message
            ),
            exhausted_roots: Vec::new(),
            withheld_rows_path: None,
        });
    }
    let locations = match state.analyzer.dependency_file_locations() {
        Ok(locations) => locations.into_iter().collect::<HashMap<_, _>>(),
        Err(error) => {
            incomplete = true;
            diagnostics.push(CodeQueryDiagnostic {
                related: Vec::new(),
                source: None,
                code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: "workspace",
                message: format!("dependency source presentation proof unavailable: {error}"),
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            });
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
            return cancelled_plan_execution();
        }
        let file = ProjectFile::new(state.analyzer.project().root(), row.build_file.clone());
        if !seed.where_globs.matches(&rel_path_string(&file)) {
            continue;
        }
        match matches(&row, &seed.filter, &ranges) {
            Ok(Some(true)) => {}
            Ok(Some(false)) => continue,
            unknown => {
                truncated = true;
                diagnostics.push(CodeQueryDiagnostic {
                    related: Vec::new(),
                    source: None,
                    code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: "workspace",
                    message: format!(
                        "dependency version predicate unresolved for {} at {}: {}",
                        row.id(),
                        row.build_file.display(),
                        unknown
                            .err()
                            .unwrap_or_else(|| "no complete exact version evidence".into())
                    ),
                    exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                });
                continue;
            }
        }
        if !locations.contains_key(&row.id()) && !missing_location_reported {
            missing_location_reported = true;
            truncated = true;
            diagnostics.push(CodeQueryDiagnostic {
                related: Vec::new(),
                source: None,
                code: CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: "workspace",
                message: "selected dependency rows lack retained source presentation proof".into(),
                exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            });
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
    PlanExecution {
        rows,
        truncated,
        cancelled: false,
        pipeline_halted: false,
    }
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
