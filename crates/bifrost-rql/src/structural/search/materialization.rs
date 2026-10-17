//! The execution adapter between the query engine and the
//! declaration-materialization producer (#1476, Milestone 4).
//!
//! Three row families arrive here: generation sites, exports, and declaration
//! states, all from the per-file materialization derivation
//! (`materialization_for_file`). They follow the environment precedent —
//! plain pipeline values derived on demand and memoised per request, never
//! semantic-artifact backed.
//!
//! The honesty rule lives here as well: an axis the file's adapter does not
//! answer becomes an `Incomplete` diagnostic, a dynamic generation site makes
//! a generated-set answer incomplete, and a configuration-gated file reports
//! that no active configuration is known. An empty answer is never silently a
//! complete one.

use super::super::materialization::{MaterializationAxis, SourceExportLocalDefinition};
use super::super::materialization_rows::{
    DeclarationStateRow, ExportRow, GenerationSiteRow, MaterializationCompleteness,
    MaterializationFileResult, MaterializationIncompleteReason, materialization_for_file,
};
use super::results::{
    CodeQueryDeclarationState, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact, CodeQueryExport, CodeQueryExportBinding,
    CodeQueryExportLocalDefinition, CodeQueryGeneratedDeclaration, CodeQueryGenerationSite,
    CodeQueryRange,
};
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_rql::{ExportFilter, GenerationSiteFilter};
use std::sync::Arc;

/// Domain separator for a generation-site row's stable id.
const GENERATION_SITE_ID_DOMAIN: &[u8] = b"bifrost.code_query.generation_site.v1";
/// Domain separator for an export row's stable id.
const EXPORT_ID_DOMAIN: &[u8] = b"bifrost.code_query.export.v1";
/// Domain separator for a declaration-state row's stable id.
const DECLARATION_STATE_ID_DOMAIN: &[u8] = b"bifrost.code_query.declaration_state.v1";

/// Per-request memo of derived materialization rows plus the diagnostics
/// already reported, so one file is derived once and one axis gap is reported
/// once.
#[derive(Default)]
pub(super) struct MaterializationTraversalCache {
    files: HashMap<ProjectFile, Arc<MaterializationFileResult>>,
    reported: HashSet<(ProjectFile, CodeQueryDiagnosticCode)>,
    reported_axes: HashSet<(Language, MaterializationAxis)>,
}

impl MaterializationTraversalCache {
    /// Derive (or replay) one file's materialization rows.
    pub(super) fn materialization_for(
        &mut self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
    ) -> Arc<MaterializationFileResult> {
        if let Some(cached) = self.files.get(file) {
            return Arc::clone(cached);
        }
        let derived = Arc::new(materialization_for_file(analyzer, file));
        self.files.insert(file.clone(), Arc::clone(&derived));
        derived
    }

    /// Turn one file's materialization completeness into typed diagnostics,
    /// scoped to the axes the query actually depends on.
    pub(super) fn report_completeness(
        &mut self,
        file: &ProjectFile,
        result: &MaterializationFileResult,
        required: &[MaterializationAxis],
        diagnostics: &mut Vec<CodeQueryDiagnostic>,
    ) {
        let MaterializationCompleteness::Incomplete { reasons, .. } = &result.completeness else {
            return;
        };
        let language = crate::analyzer::common::language_for_file(file);
        for axis in required {
            if result.completeness.covers(*axis) {
                continue;
            }
            let unsupported = reasons.iter().any(|reason| {
                matches!(reason, MaterializationIncompleteReason::AxisUnsupported(other) if other == axis)
            });
            let code = if unsupported {
                CodeQueryDiagnosticCode::MaterializationAxisUnsupported
            } else {
                CodeQueryDiagnosticCode::MaterializationDerivationIncomplete
            };
            if unsupported {
                // An unsupported axis is a property of the adapter, so it is
                // reported once per language rather than once per file.
                if !self.reported_axes.insert((language, *axis)) {
                    continue;
                }
                diagnostics.push(CodeQueryDiagnostic {
                    source: None,
                    code,
                    impact: CodeQueryDiagnosticImpact::Incomplete,
                    branch: Vec::new(),
                    language: language.config_label(),
                    message: format!(
                        "structural adapter for {} does not support declaration materialization axis(es): {}",
                        language.config_label(),
                        axis.label()
                    ),
                exhausted_roots: Vec::new(),
                    withheld_rows_path: None,
                });
                continue;
            }
            if !self.reported.insert((file.clone(), code)) {
                continue;
            }
            diagnostics.push(CodeQueryDiagnostic {
                source: None,
                code,
                impact: CodeQueryDiagnosticImpact::Incomplete,
                branch: Vec::new(),
                language: language.config_label(),
                message: format!(
                    "{} has incomplete declaration materialization ({}); its {} rows are not the whole set",
                    super::rel_path_string(file),
                    reasons
                        .iter()
                        .map(incomplete_reason_label)
                        .collect::<Vec<_>>()
                        .join(", "),
                    axis.label()
                ),
            exhausted_roots: Vec::new(),
                withheld_rows_path: None,
            });
        }
    }
}

fn incomplete_reason_label(reason: &MaterializationIncompleteReason) -> &'static str {
    match reason {
        MaterializationIncompleteReason::AxisUnsupported(_) => "axis unsupported",
        MaterializationIncompleteReason::NoStructuralAdapter => "no structural adapter",
        MaterializationIncompleteReason::FactsUnavailable => "no structural facts",
        MaterializationIncompleteReason::DynamicGenerationPresent => {
            "a generation site has dynamic inputs"
        }
        MaterializationIncompleteReason::DynamicExportSurface => {
            "the Python export surface has dynamic inputs"
        }
        MaterializationIncompleteReason::DynamicExportDefinition => {
            "Python module definitions may be dynamic"
        }
        MaterializationIncompleteReason::ExportSyntaxUnavailable => {
            "Python export syntax is unavailable"
        }
        MaterializationIncompleteReason::NoActiveConfiguration => {
            "no active preprocessing configuration is known"
        }
    }
}

/// One generation-site row travelling through the pipeline. The whole file
/// result travels with the row because `generates` is answered from it, and a
/// derived result is shared rather than cloned per row.
#[derive(Debug, Clone)]
pub(super) struct GenerationSiteValue {
    pub(super) file: ProjectFile,
    pub(super) result: Arc<MaterializationFileResult>,
    pub(super) index: usize,
}

impl GenerationSiteValue {
    pub(super) fn row(&self) -> &GenerationSiteRow {
        &self.result.sites[self.index]
    }

    pub(super) fn key(&self) -> GenerationSiteKey {
        GenerationSiteKey {
            file: self.file.clone(),
            index: self.index,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn id(&self) -> String {
        let row = self.row();
        let mut digest = LengthDelimitedDigest::new(GENERATION_SITE_ID_DOMAIN);
        digest.push(row.content_identity.as_bytes());
        digest.push(&row.site.start_byte.to_le_bytes());
        digest.push(&row.site.end_byte.to_le_bytes());
        digest.push(row.kind.label().as_bytes());
        digest.finish().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct GenerationSiteKey {
    pub(super) file: ProjectFile,
    pub(super) index: usize,
}

/// One export row travelling through the pipeline.
#[derive(Debug, Clone)]
pub(super) struct ExportValue {
    pub(super) file: ProjectFile,
    pub(super) result: Arc<MaterializationFileResult>,
    pub(super) index: usize,
}

impl ExportValue {
    pub(super) fn row(&self) -> &ExportRow {
        &self.result.exports[self.index]
    }

    pub(super) fn key(&self) -> ExportKey {
        ExportKey {
            file: self.file.clone(),
            index: self.index,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn id(&self) -> String {
        let row = self.row();
        let mut digest = LengthDelimitedDigest::new(EXPORT_ID_DOMAIN);
        digest.push(row.content_identity.as_bytes());
        digest.push(&row.range.start_byte.to_le_bytes());
        digest.push(&row.range.end_byte.to_le_bytes());
        digest.push(row.form.label().as_bytes());
        digest.push(row.exported_name.as_bytes());
        digest.finish().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct ExportKey {
    pub(super) file: ProjectFile,
    pub(super) index: usize,
}

/// One declaration-state row travelling through the pipeline.
#[derive(Debug, Clone)]
pub(super) struct DeclarationStateValue {
    pub(super) file: ProjectFile,
    pub(super) result: Arc<MaterializationFileResult>,
    pub(super) index: usize,
}

impl DeclarationStateValue {
    pub(super) fn row(&self) -> &DeclarationStateRow {
        &self.result.states[self.index]
    }

    pub(super) fn key(&self) -> DeclarationStateKey {
        DeclarationStateKey {
            file: self.file.clone(),
            index: self.index,
        }
    }

    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn id(&self) -> String {
        let row = self.row();
        let mut digest = LengthDelimitedDigest::new(DECLARATION_STATE_ID_DOMAIN);
        digest.push(super::rel_path_string(&row.file).as_bytes());
        digest.push(row.unit.fq_name().as_bytes());
        digest.push(row.unit.kind().display_lowercase().as_bytes());
        digest.finish().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct DeclarationStateKey {
    pub(super) file: ProjectFile,
    pub(super) index: usize,
}

/// Generation-site indices of one file result that satisfy a filter, in
/// recording order.
pub(super) fn select_generation_sites<'rows>(
    result: &'rows MaterializationFileResult,
    filter: &'rows GenerationSiteFilter,
) -> impl Iterator<Item = usize> + 'rows {
    result
        .sites
        .iter()
        .enumerate()
        .filter(|(_, row)| filter.matches(row.kind, row.input))
        .map(|(index, _)| index)
}

/// Export indices of one file result that satisfy a filter, in recording order.
pub(super) fn select_exports<'rows>(
    result: &'rows MaterializationFileResult,
    filter: &'rows ExportFilter,
) -> impl Iterator<Item = usize> + 'rows {
    result
        .exports
        .iter()
        .enumerate()
        .filter(|(_, row)| filter.matches(row.form, &row.exported_name))
        .map(|(index, _)| index)
}

/// The axes a generation-site query depends on.
pub(super) const GENERATION_SITE_QUERY_AXES: &[MaterializationAxis] = &[
    MaterializationAxis::GenerationSites,
    MaterializationAxis::GeneratedSets,
];
/// The axes an export query depends on.
pub(super) const EXPORT_QUERY_AXES: &[MaterializationAxis] = &[MaterializationAxis::Exports];
/// The axes a declaration-state query depends on.
pub(super) const DECLARATION_STATE_QUERY_AXES: &[MaterializationAxis] =
    &[MaterializationAxis::DeclarationState];
/// The axes a declaration-state query that filters on the configuration gate
/// depends on.
pub(super) const DECLARATION_STATE_AND_GATING_QUERY_AXES: &[MaterializationAxis] = &[
    MaterializationAxis::DeclarationState,
    MaterializationAxis::ConfigurationGating,
];
/// The axes an implementation-linkage traversal depends on.
pub(super) const IMPLEMENTATION_QUERY_AXES: &[MaterializationAxis] = &[
    MaterializationAxis::DeclarationState,
    MaterializationAxis::ImplementationLinkage,
];

/// The public projection of one generation-site row.
pub(super) fn public_generation_site(
    value: &GenerationSiteValue,
    range: CodeQueryRange,
    mut render_argument: impl FnMut(&crate::analyzer::Range) -> CodeQueryRange,
) -> CodeQueryGenerationSite {
    let row = value.row();
    CodeQueryGenerationSite {
        id: value.id(),
        ast_id: row.ast_id(),
        path: super::rel_path_string(&row.file),
        language: crate::analyzer::common::language_for_file(&row.file).config_label(),
        range,
        start_byte: row.site.start_byte,
        end_byte: row.site.end_byte,
        kind: row.kind.label(),
        input: row.input.label(),
        generated_count: row.generated.len(),
        generated: row
            .generated
            .iter()
            .map(|(unit, argument)| CodeQueryGeneratedDeclaration {
                fq_name: unit.fq_name().to_string(),
                argument_start_byte: argument.start_byte,
                argument_end_byte: argument.end_byte,
                argument_range: render_argument(argument),
            })
            .collect(),
    }
}

/// The public projection of one export row.
pub(super) fn public_export(
    value: &ExportValue,
    range: CodeQueryRange,
    binding_range: Option<CodeQueryRange>,
) -> CodeQueryExport {
    let row = value.row();
    let metadata = super::public_source_metadata(&row.file, row.range, range);
    let local_definition = row
        .local_definition
        .as_ref()
        .map(|definition| match definition {
            SourceExportLocalDefinition::Defined { binding } => {
                let range =
                    binding_range.expect("defined export binding has a rendered source range");
                CodeQueryExportLocalDefinition::Defined {
                    binding: CodeQueryExportBinding {
                        name: binding.name.clone(),
                        kind: binding.kind.label().to_owned(),
                        start_byte: binding.range.start_byte,
                        end_byte: binding.range.end_byte,
                        range,
                    },
                }
            }
            SourceExportLocalDefinition::Undefined => CodeQueryExportLocalDefinition::Undefined,
            SourceExportLocalDefinition::Unknown => CodeQueryExportLocalDefinition::Unknown,
        });
    CodeQueryExport {
        id: value.id(),
        ast_id: row.ast_id(),
        path: metadata.path,
        language: metadata.language,
        range: metadata.range,
        start_byte: metadata.start_byte,
        end_byte: metadata.end_byte,
        form: row.form.label(),
        exported_name: row.exported_name.clone(),
        target_fq_name: row.target.as_ref().map(|unit| unit.fq_name().to_string()),
        local_definition,
    }
}

/// The public projection of one declaration-state row.
pub(super) fn public_declaration_state(
    value: &DeclarationStateValue,
    range: Option<CodeQueryRange>,
) -> CodeQueryDeclarationState {
    let row = value.row();
    CodeQueryDeclarationState {
        id: value.id(),
        ast_id: row.ast_id(),
        path: super::rel_path_string(&row.file),
        language: crate::analyzer::common::language_for_file(&row.file).config_label(),
        fq_name: row.unit.fq_name().to_string(),
        unit_kind: row.unit.kind().display_lowercase(),
        origin: row.origin.label(),
        declaration_only: row.declaration_only,
        config_gated: row.config_gated,
        range,
        start_byte: row.declaration.map(|declaration| declaration.start_byte),
        end_byte: row.declaration.map(|declaration| declaration.end_byte),
    }
}

#[cfg(test)]
mod tests {
    use super::super::execute_with_limits;
    use crate::analyzer::Language;
    use crate::structural::{CodeQuery, CodeQueryExecutionLimits};
    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    struct Fixture {
        analyzer: AnalyzerFixture,
    }

    impl Fixture {
        fn new(language: Language, relative_path: &str, source: &str) -> Self {
            Self {
                analyzer: AnalyzerFixture::new_for_language(language, &[(relative_path, source)]),
            }
        }

        fn run(&self, rql: &str) -> super::super::results::CodeQueryResult {
            let query = CodeQuery::from_sexp(rql).expect("query should parse");
            execute_with_limits(
                self.analyzer.analyzer().analyzer(),
                &query,
                CodeQueryExecutionLimits::default(),
            )
        }
    }

    #[test]
    fn unclaimed_language_reports_axis_unsupported() {
        let fixture = Fixture::new(Language::Go, "main.go", "package main\nfunc main() {}\n");
        let result = fixture.run("(generation-sites)");
        assert!(result.results.is_empty());
        assert!(
            result.diagnostics.iter().any(|diagnostic| matches!(
                diagnostic.code,
                super::CodeQueryDiagnosticCode::MaterializationAxisUnsupported
            )),
            "{:?}",
            result.diagnostics
        );
    }
}
