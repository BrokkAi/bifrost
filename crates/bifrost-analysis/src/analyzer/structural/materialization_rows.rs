//! Per-file declaration-materialization rows (issue #1476).
//!
//! The language walks record provenance at declaration-collection time
//! ([`MaterializationRecord`], persisted with the file's analysis facts).
//! This module derives the queryable row families from those records plus the
//! analyzer's declaration surface: the state of each declaration (its origin,
//! declaration-only flag and configuration gate), the generation sites with
//! their exact generated sets, the export rows, and the link from a
//! declaration-only signature to its implementation.
//!
//! Honesty follows the sibling layers (`occurrence_rows`,
//! `lexical_environment`): support is per axis and declared by the adapter,
//! a dynamic generation site makes the generated-set axis incomplete rather
//! than silently empty, and a file whose declarations sit under preprocessor
//! conditionals reports that no active configuration is known instead of
//! pretending the declarations unconditionally exist.

use super::facts::FileFacts;

use super::materialization::DeclarationMaterializationSupport;

use super::materialization::DeclarationOrigin;

use super::materialization::ExportForm;

use super::materialization::GenerationInputClass;

use super::materialization::GenerationKind;

use super::materialization::MaterializationAxis;

use super::materialization::MaterializationRecord;

use super::materialization::SourceExportLocalDefinition;

use super::occurrence_rows::ast_id;

use super::provider::StructuralSyntaxLimitedOutcome;

use crate::analyzer::common::language_for_file;

use crate::analyzer::semantic::ContentIdentity;

use crate::analyzer::structural_spec_for;

use crate::analyzer::CodeUnit;

use crate::analyzer::IAnalyzer;

use crate::analyzer::Language;

use crate::analyzer::ProjectFile;

use crate::analyzer::Range;

use crate::analyzer::SignatureMetadata;

use crate::hash::HashMap;

/// The axes this producer answers. All six: this layer is the only row
/// producer for the materialization vocabulary.
pub const MATERIALIZATION_PRODUCER_AXES: &[MaterializationAxis] = &[
    MaterializationAxis::DeclarationState,
    MaterializationAxis::GenerationSites,
    MaterializationAxis::GeneratedSets,
    MaterializationAxis::Exports,
    MaterializationAxis::ImplementationLinkage,
    MaterializationAxis::ConfigurationGating,
];

/// The state of one declaration of the file: where it came from and what it
/// must not be mistaken for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationStateRow {
    pub file: ProjectFile,
    pub content_identity: ContentIdentity,
    /// The arena fact whose range is exactly the unit's primary declaration
    /// range, when one exists. A generated unit (whose range is its naming
    /// argument) or a range-adjusted declaration has none; a row without an
    /// anchor cannot be addressed by a captured node.
    pub node: Option<u32>,
    pub unit: CodeUnit,
    pub origin: DeclarationOrigin,
    /// A signature that must not be treated as runnable behavior (a Python
    /// `@overload` stub).
    pub declaration_only: bool,
    /// The declaration lies inside a recorded preprocessor-conditional
    /// interval, so its existence depends on a configuration the analyzer has
    /// not evaluated.
    pub config_gated: bool,
    /// The declaration's primary source range, when the analyzer states one.
    pub declaration: Option<Range>,
}

impl DeclarationStateRow {
    pub fn ast_id(&self) -> Option<String> {
        self.node.map(|node| ast_id(self.content_identity, node))
    }
}

/// One construct that materializes declarations, with the exact set it
/// produces. For a `Dynamic` site the set is explicitly unknown: `generated`
/// holds only the literally named units (possibly none), and the file's
/// generated-set axis is incomplete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationSiteRow {
    pub file: ProjectFile,
    pub content_identity: ContentIdentity,
    /// The arena fact whose range is exactly the site, when one exists (a
    /// Ruby macro call is a `call` fact; a C `#define` is not a fact).
    pub node: Option<u32>,
    pub site: Range,
    pub kind: GenerationKind,
    pub input: GenerationInputClass,
    /// The generated declarations, paired with the literal argument that
    /// named each one.
    pub generated: Vec<(CodeUnit, Range)>,
}

impl GenerationSiteRow {
    pub fn ast_id(&self) -> Option<String> {
        self.node.map(|node| ast_id(self.content_identity, node))
    }
}

/// One export declaration of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRow {
    pub file: ProjectFile,
    pub content_identity: ContentIdentity,
    /// The arena fact whose range is exactly the export construct, when the
    /// kind table maps one.
    pub node: Option<u32>,
    pub range: Range,
    pub form: ExportForm,
    /// The name consumers import; `"default"` for default exports.
    pub exported_name: String,
    /// The declaration the export materialized, when the analyzer models one
    /// (an anonymous default's synthetic unit, an in-place CommonJS member).
    /// `None` for exports of existing bindings.
    pub target: Option<CodeUnit>,
    /// Source-backed Python `__all__` binding evidence. Other export forms do
    /// not currently claim this local-name relation.
    pub local_definition: Option<SourceExportLocalDefinition>,
}

impl ExportRow {
    pub fn ast_id(&self) -> Option<String> {
        self.node.map(|node| ast_id(self.content_identity, node))
    }
}

/// The link from a declaration-only signature to the implementation that
/// carries its behavior. `implementation: None` is a real, queryable answer:
/// the stub has no implementation in this file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImplementationLinkRow {
    pub file: ProjectFile,
    pub stub: CodeUnit,
    pub implementation: Option<CodeUnit>,
}

/// Why part of a file's materialization answer is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializationIncompleteReason {
    /// The adapter declares the axis unsupported, so absence of rows for it
    /// says nothing about the file.
    AxisUnsupported(MaterializationAxis),
    /// No structural adapter is registered for the file's language.
    NoStructuralAdapter,
    /// The analyzer holds no structural facts for the file, so no row can be
    /// anchored to an AST identity.
    FactsUnavailable,
    /// At least one generation site has non-literal inputs, so the file's
    /// generated sets are missing members rather than complete.
    DynamicGenerationPresent,
    /// The file has configuration-gated declarations and no active
    /// preprocessing/build configuration was supplied, so which of them exist
    /// is unknown.
    NoActiveConfiguration,
    /// A dynamic Python `__all__` expression or mutation leaves members
    /// unknown even though any statically readable names are still returned.
    DynamicExportSurface,
    /// Dynamic Python module namespace writes may define names that have no
    /// statically visible module binding.
    DynamicExportDefinition,
    /// The query could not obtain bounded prepared syntax to derive Python's
    /// source-level `__all__` rows.
    ExportSyntaxUnavailable,
}

/// Whether every axis of the file's materialization answer is complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializationCompleteness {
    Complete,
    Incomplete {
        unsupported_axes: Vec<MaterializationAxis>,
        reasons: Vec<MaterializationIncompleteReason>,
    },
}

impl MaterializationCompleteness {
    /// Whether `axis` is answered completely for this file.
    pub fn covers(&self, axis: MaterializationAxis) -> bool {
        match self {
            Self::Complete => true,
            Self::Incomplete {
                unsupported_axes,
                reasons,
            } => {
                !unsupported_axes.contains(&axis)
                    && !reasons.iter().any(|reason| match reason {
                        MaterializationIncompleteReason::AxisUnsupported(unsupported) => {
                            *unsupported == axis
                        }
                        MaterializationIncompleteReason::NoStructuralAdapter
                        | MaterializationIncompleteReason::FactsUnavailable => true,
                        MaterializationIncompleteReason::DynamicGenerationPresent => {
                            axis == MaterializationAxis::GeneratedSets
                        }
                        MaterializationIncompleteReason::NoActiveConfiguration => {
                            axis == MaterializationAxis::ConfigurationGating
                        }
                        MaterializationIncompleteReason::DynamicExportSurface
                        | MaterializationIncompleteReason::DynamicExportDefinition
                        | MaterializationIncompleteReason::ExportSyntaxUnavailable => {
                            axis == MaterializationAxis::Exports
                        }
                    })
            }
        }
    }
}

/// One file's materialization rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializationFileResult {
    pub states: Vec<DeclarationStateRow>,
    pub sites: Vec<GenerationSiteRow>,
    pub exports: Vec<ExportRow>,
    pub links: Vec<ImplementationLinkRow>,
    pub completeness: MaterializationCompleteness,
}

impl MaterializationFileResult {
    pub fn state_of(&self, unit: &CodeUnit) -> Option<&DeclarationStateRow> {
        self.states.iter().find(|row| &row.unit == unit)
    }
}

/// One file's materialization rows, derived from its recorded provenance,
/// its declaration surface, and its structural facts.
pub fn materialization_for_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> MaterializationFileResult {
    let language = language_for_file(file);
    let Some(spec) = structural_spec_for(language) else {
        return unavailable(MaterializationIncompleteReason::NoStructuralAdapter);
    };
    let providers = analyzer.structural_fact_providers();
    let Some(provider) = providers
        .into_iter()
        .find(|provider| provider.structural_language() == language)
    else {
        return unavailable(MaterializationIncompleteReason::FactsUnavailable);
    };
    let facts = provider.structural_facts(file);
    let Some(facts) = facts else {
        return unavailable(MaterializationIncompleteReason::FactsUnavailable);
    };

    let support = spec.materialization_support();
    let mut reasons: Vec<MaterializationIncompleteReason> = MATERIALIZATION_PRODUCER_AXES
        .iter()
        .copied()
        .filter(|axis| !support.is_supported(*axis))
        .map(MaterializationIncompleteReason::AxisUnsupported)
        .collect();

    let records = analyzer.materialization_records(file);
    let content_identity = facts.source_identity();

    let mut sites = Vec::new();
    let mut exports = Vec::new();
    let mut config_intervals = Vec::new();
    let mut origins: HashMap<CodeUnit, DeclarationOrigin> = HashMap::default();

    for record in &records {
        match record {
            MaterializationRecord::GeneratedDeclaration {
                site,
                argument,
                kind,
                unit,
            } => {
                origins.insert(unit.clone(), DeclarationOrigin::Generated);
                let row = site_row(&mut sites, file, content_identity, &facts, *site, *kind);
                row.generated.push((unit.clone(), *argument));
            }
            MaterializationRecord::DynamicGenerationSite { site, kind } => {
                let row = site_row(&mut sites, file, content_identity, &facts, *site, *kind);
                row.input = GenerationInputClass::Dynamic;
                super::note_once(
                    &mut reasons,
                    MaterializationIncompleteReason::DynamicGenerationPresent,
                );
            }
            MaterializationRecord::Export {
                range,
                form,
                exported_name,
                target,
            } => {
                if let Some(target) = target {
                    origins.insert(target.clone(), DeclarationOrigin::Generated);
                }
                exports.push(ExportRow {
                    file: file.clone(),
                    content_identity,
                    node: fact_at_range(&facts, *range),
                    range: *range,
                    form: *form,
                    exported_name: exported_name.clone(),
                    target: target.clone(),
                    local_definition: None,
                });
            }
            MaterializationRecord::RecoveredDeclaration { unit, .. } => {
                origins.insert(unit.clone(), DeclarationOrigin::Recovered);
            }
            MaterializationRecord::ConfigurationConditional { range } => {
                config_intervals.push(*range);
            }
        }
    }

    // Python's `__all__` is source evidence, not declaration materialization.
    // Derive it from one bounded prepared parse tree during this query rather
    // than adding more fields to the existing serialized materialization
    // payload.
    if language == Language::Python && support.is_supported(MaterializationAxis::Exports) {
        match provider.structural_syntax_limited(file, 1_048_576, None) {
            StructuralSyntaxLimitedOutcome::Available(syntax) => {
                let prepared = syntax.prepared();
                if let Some(source_exports) =
                    spec.source_export_facts(prepared.tree().root_node(), prepared.source())
                {
                    exports.extend(source_exports.exports.into_iter().map(|export| ExportRow {
                        file: file.clone(),
                        content_identity,
                        node: fact_at_range(&facts, export.range),
                        range: export.range,
                        form: ExportForm::PythonAll,
                        exported_name: export.exported_name,
                        target: None,
                        local_definition: Some(export.local_definition),
                    }));
                    if !source_exports.complete {
                        super::note_once(
                            &mut reasons,
                            MaterializationIncompleteReason::DynamicExportSurface,
                        );
                    }
                    if source_exports.declared && !source_exports.definitions_complete {
                        super::note_once(
                            &mut reasons,
                            MaterializationIncompleteReason::DynamicExportDefinition,
                        );
                    }
                } else {
                    super::note_once(
                        &mut reasons,
                        MaterializationIncompleteReason::ExportSyntaxUnavailable,
                    );
                }
            }
            StructuralSyntaxLimitedOutcome::Exceeded { .. }
            | StructuralSyntaxLimitedOutcome::Cancelled
            | StructuralSyntaxLimitedOutcome::Unavailable => super::note_once(
                &mut reasons,
                MaterializationIncompleteReason::ExportSyntaxUnavailable,
            ),
        }
    }

    let mut states = Vec::new();
    let mut links = Vec::new();
    let declarations: Vec<CodeUnit> = if support.is_supported(MaterializationAxis::DeclarationState)
    {
        analyzer.declarations(file).into_iter().collect()
    } else {
        Vec::new()
    };
    let mut any_config_gated = false;
    for unit in &declarations {
        let declaration = analyzer.ranges(unit).into_iter().next();
        let declaration_only =
            SignatureMetadata::unit_is_declaration_only(&analyzer.signature_metadata(unit));
        let config_gated = declaration.is_some_and(|range| {
            config_intervals.iter().any(|interval| {
                interval.start_byte <= range.start_byte && range.end_byte <= interval.end_byte
            })
        });
        any_config_gated |= config_gated;
        states.push(DeclarationStateRow {
            file: file.clone(),
            content_identity,
            node: declaration.and_then(|range| fact_at_range(&facts, range)),
            unit: unit.clone(),
            origin: origins
                .get(unit)
                .copied()
                .unwrap_or(DeclarationOrigin::Parsed),
            declaration_only,
            config_gated,
            declaration,
        });
    }
    if any_config_gated && support.is_supported(MaterializationAxis::ConfigurationGating) {
        // No consumer supplies an active configuration today, so which gated
        // declarations exist is honestly unknown.
        super::note_once(
            &mut reasons,
            MaterializationIncompleteReason::NoActiveConfiguration,
        );
    }

    if support.is_supported(MaterializationAxis::ImplementationLinkage) {
        for state in &states {
            if !state.declaration_only {
                continue;
            }
            let implementation = declarations
                .iter()
                .find(|candidate| {
                    *candidate != &state.unit
                        && candidate.kind() == state.unit.kind()
                        && candidate.fq_name() == state.unit.fq_name()
                        && !states
                            .iter()
                            .any(|other| &other.unit == *candidate && other.declaration_only)
                })
                .cloned();
            links.push(ImplementationLinkRow {
                file: file.clone(),
                stub: state.unit.clone(),
                implementation,
            });
        }
    }

    MaterializationFileResult {
        states,
        sites,
        exports,
        links,
        completeness: completeness(support, reasons),
    }
}

/// The existing site row for `(site, kind)`, or a fresh literal one. Records
/// for one site arrive in recording order, so grouping preserves it.
fn site_row<'rows>(
    sites: &'rows mut Vec<GenerationSiteRow>,
    file: &ProjectFile,
    content_identity: ContentIdentity,
    facts: &FileFacts,
    site: Range,
    kind: GenerationKind,
) -> &'rows mut GenerationSiteRow {
    let index = sites
        .iter()
        .position(|row| row.site == site && row.kind == kind)
        .unwrap_or_else(|| {
            sites.push(GenerationSiteRow {
                file: file.clone(),
                content_identity,
                node: fact_at_range(facts, site),
                site,
                kind,
                input: GenerationInputClass::Literal,
                generated: Vec::new(),
            });
            sites.len() - 1
        });
    &mut sites[index]
}

/// The arena fact whose range is exactly `range`, when one exists. The
/// records and the facts snapshot describe one `ContentIdentity`, so an exact
/// byte-range match is an inverse of extraction, not a heuristic.
fn fact_at_range(facts: &FileFacts, range: Range) -> Option<u32> {
    facts
        .nodes()
        .iter()
        .position(|node| {
            node.range.start_byte == range.start_byte && node.range.end_byte == range.end_byte
        })
        .map(|index| u32::try_from(index).expect("facts arena node count fits in u32"))
}

fn unavailable(reason: MaterializationIncompleteReason) -> MaterializationFileResult {
    MaterializationFileResult {
        states: Vec::new(),
        sites: Vec::new(),
        exports: Vec::new(),
        links: Vec::new(),
        completeness: MaterializationCompleteness::Incomplete {
            unsupported_axes: MATERIALIZATION_PRODUCER_AXES.to_vec(),
            reasons: vec![reason],
        },
    }
}

fn completeness(
    support: &DeclarationMaterializationSupport,
    reasons: Vec<MaterializationIncompleteReason>,
) -> MaterializationCompleteness {
    if reasons.is_empty() {
        return MaterializationCompleteness::Complete;
    }
    let unsupported_axes = MATERIALIZATION_PRODUCER_AXES
        .iter()
        .copied()
        .filter(|axis| !support.is_supported(*axis))
        .collect();
    MaterializationCompleteness::Incomplete {
        unsupported_axes,
        reasons,
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;
