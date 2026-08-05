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
use super::materialization::{
    DeclarationMaterializationSupport, DeclarationOrigin, ExportForm, GenerationInputClass,
    GenerationKind, MaterializationAxis, MaterializationRecord,
};
use super::occurrence_rows::ast_id;
use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic::ContentIdentity;
use crate::analyzer::structural_spec_for;
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};
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
    let facts = analyzer
        .structural_search_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == language)
        .and_then(|provider| provider.structural_facts(file));
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
                note(
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
        let declaration_only = analyzer
            .signature_metadata(unit)
            .iter()
            .any(|metadata| metadata.is_declaration_only());
        let config_gated = declaration.is_some_and(|range| {
            config_intervals.iter().any(|interval| {
                interval.start_byte <= range.start_byte && range.end_byte <= interval.end_byte
            })
        });
        any_config_gated |= config_gated;
        states.push(DeclarationStateRow {
            file: file.clone(),
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
        note(
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

/// Record a reason once. Which axis is incomplete is what matters; how many
/// rows hit the same wall is not.
fn note(
    reasons: &mut Vec<MaterializationIncompleteReason>,
    reason: MaterializationIncompleteReason,
) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerConfig, Language, Project, TestProject, WorkspaceAnalyzer};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        workspace: WorkspaceAnalyzer,
        file: ProjectFile,
        source: String,
    }

    impl Fixture {
        fn new(language: Language, relative_path: &str, source: &str) -> Self {
            let temp = tempfile::tempdir().expect("temp dir");
            let root: PathBuf = temp.path().canonicalize().expect("canonical root");
            let file = ProjectFile::new(root.clone(), relative_path);
            file.write(source).expect("write fixture source");
            let project = TestProject::new(root, language);
            let workspace = WorkspaceAnalyzer::build(
                Arc::new(project) as Arc<dyn Project>,
                AnalyzerConfig::default(),
            );
            Self {
                _temp: temp,
                workspace,
                file,
                source: source.to_owned(),
            }
        }

        fn rows(&self) -> MaterializationFileResult {
            materialization_for_file(self.workspace.analyzer(), &self.file)
        }

        fn at(&self, needle: &str) -> usize {
            self.source
                .find(needle)
                .unwrap_or_else(|| panic!("fixture does not contain {needle:?}"))
        }
    }

    /// A literal Ruby `attr_accessor` is one anchored generation site whose
    /// generated set has exact cardinality, and each generated declaration's
    /// state row says `generated`.
    #[test]
    fn ruby_literal_generation_site_has_exact_cardinality() {
        let fixture = Fixture::new(
            Language::Ruby,
            "widget.rb",
            "class Widget\n  attr_accessor :name\n  def base; end\n  alias_method :aliased, :base\nend\n",
        );
        let rows = fixture.rows();

        assert!(
            rows.completeness.covers(MaterializationAxis::GeneratedSets),
            "completeness: {:?}",
            rows.completeness
        );
        assert_eq!(rows.sites.len(), 2, "sites: {:?}", rows.sites);

        let accessor = &rows.sites[0];
        assert_eq!(accessor.kind, GenerationKind::AccessorMacro);
        assert_eq!(accessor.input, GenerationInputClass::Literal);
        assert_eq!(accessor.site.start_byte, fixture.at("attr_accessor"));
        assert!(accessor.ast_id().is_some(), "a Ruby call is a fact");
        let generated: Vec<_> = accessor
            .generated
            .iter()
            .map(|(unit, _)| unit.fq_name().to_string())
            .collect();
        assert_eq!(
            generated,
            vec!["Widget.@name", "Widget.name", "Widget.name="],
            "exact generated set"
        );

        let alias = &rows.sites[1];
        assert_eq!(alias.kind, GenerationKind::AliasMacro);
        assert_eq!(alias.generated.len(), 1);

        let reader = rows
            .states
            .iter()
            .find(|row| row.unit.fq_name() == "Widget.name")
            .expect("generated reader state row");
        assert_eq!(reader.origin, DeclarationOrigin::Generated);
        let class = rows
            .states
            .iter()
            .find(|row| row.unit.fq_name() == "Widget")
            .expect("class state row");
        assert_eq!(class.origin, DeclarationOrigin::Parsed);
    }

    /// A dynamic argument keeps the site visible with an explicitly unknown
    /// generated set: the axis reports incomplete, never an empty answer.
    #[test]
    fn ruby_dynamic_generation_reports_incomplete_not_empty() {
        let fixture = Fixture::new(
            Language::Ruby,
            "dynamic.rb",
            "class Widget\n  attr_reader label.to_sym\nend\n",
        );
        let rows = fixture.rows();

        assert_eq!(rows.sites.len(), 1, "sites: {:?}", rows.sites);
        assert_eq!(rows.sites[0].input, GenerationInputClass::Dynamic);
        assert!(rows.sites[0].generated.is_empty());
        assert!(
            !rows.completeness.covers(MaterializationAxis::GeneratedSets),
            "completeness: {:?}",
            rows.completeness
        );
        assert!(
            rows.completeness
                .covers(MaterializationAxis::GenerationSites),
            "the site itself is a complete answer: {:?}",
            rows.completeness
        );
    }

    /// Python `@overload` stubs are declaration-only state rows linked to the
    /// runnable implementation; a stub without one links to an explicit
    /// absence.
    #[test]
    fn python_overload_stubs_link_to_their_implementation() {
        let fixture = Fixture::new(
            Language::Python,
            "over.py",
            concat!(
                "from typing import overload\n",
                "@overload\n",
                "def parse(value: int) -> int: ...\n",
                "@overload\n",
                "def parse(value: str) -> str: ...\n",
                "def parse(value):\n",
                "    return value\n",
                "@overload\n",
                "def orphan(value: int) -> int: ...\n",
            ),
        );
        let rows = fixture.rows();

        // Each overload stub is its own declaration-only unit: two `parse`
        // stubs plus the orphan.
        let stubs: Vec<_> = rows
            .states
            .iter()
            .filter(|row| row.declaration_only)
            .collect();
        assert_eq!(stubs.len(), 3, "states: {:?}", rows.states);

        assert_eq!(rows.links.len(), 3, "links: {:?}", rows.links);
        let parse_links: Vec<_> = rows
            .links
            .iter()
            .filter(|link| link.stub.identifier() == "parse")
            .collect();
        assert_eq!(parse_links.len(), 2);
        for link in parse_links {
            let implementation = link
                .implementation
                .as_ref()
                .expect("each parse stub links to the runnable def");
            assert_eq!(implementation.identifier(), "parse");
            assert!(
                !rows
                    .state_of(implementation)
                    .expect("implementation state row")
                    .declaration_only,
                "the linked implementation must be runnable"
            );
        }
        let orphan_link = rows
            .links
            .iter()
            .find(|link| link.stub.identifier() == "orphan")
            .expect("orphan stub link");
        assert_eq!(orphan_link.implementation, None);
    }

    /// JS export rows carry their form; the anonymous default's synthetic
    /// unit is the row target and its state row says `generated`.
    #[test]
    fn javascript_export_rows_state_their_forms() {
        let fixture = Fixture::new(
            Language::JavaScript,
            "exports.js",
            "export const answer = 42;\nconst table = { greet: 'hi' };\nexport default { wrap: table };\n",
        );
        let rows = fixture.rows();

        assert!(
            rows.completeness.covers(MaterializationAxis::Exports),
            "completeness: {:?}",
            rows.completeness
        );
        let forms: Vec<_> = rows
            .exports
            .iter()
            .map(|row| (row.form, row.exported_name.clone()))
            .collect();
        assert_eq!(
            forms,
            vec![
                (ExportForm::Named, "answer".to_string()),
                (ExportForm::DefaultAnonymous, "default".to_string()),
            ],
            "exports: {:?}",
            rows.exports
        );
        let default_row = &rows.exports[1];
        let target = default_row.target.as_ref().expect("synthetic default unit");
        let state = rows.state_of(target).expect("default unit state row");
        assert_eq!(state.origin, DeclarationOrigin::Generated);
    }

    /// C++ configuration gating: declarations inside a preprocessor
    /// conditional are gated, the axis reports that no active configuration
    /// is known, and a `#define` is a generation site producing its macro
    /// unit.
    #[test]
    fn cpp_config_gated_declarations_report_unknown_configuration() {
        let fixture = Fixture::new(
            Language::Cpp,
            "config.h",
            concat!(
                "#define WIDGET_MAX 8\n",
                "#ifdef USE_FAST\n",
                "int fast_path();\n",
                "#else\n",
                "int slow_path();\n",
                "#endif\n",
                "int always();\n",
            ),
        );
        let rows = fixture.rows();

        let macro_site = rows
            .sites
            .iter()
            .find(|row| row.kind == GenerationKind::PreprocessorDefinition)
            .expect("macro generation site");
        assert_eq!(macro_site.generated.len(), 1);
        assert_eq!(macro_site.generated[0].0.fq_name(), "WIDGET_MAX");

        let gated: Vec<_> = rows
            .states
            .iter()
            .filter(|row| row.config_gated)
            .map(|row| row.unit.fq_name().to_string())
            .collect();
        assert!(
            gated.contains(&"fast_path".to_string()) && gated.contains(&"slow_path".to_string()),
            "gated: {gated:?}, states: {:?}",
            rows.states
        );
        let always = rows
            .states
            .iter()
            .find(|row| row.unit.fq_name() == "always")
            .expect("ungated declaration");
        assert!(!always.config_gated);

        assert!(
            !rows
                .completeness
                .covers(MaterializationAxis::ConfigurationGating),
            "no active configuration is known: {:?}",
            rows.completeness
        );
        assert!(rows.completeness.covers(MaterializationAxis::GeneratedSets));
    }

    /// A language that records no provenance reports every axis unsupported
    /// rather than answering with empty rows.
    #[test]
    fn unclaimed_language_reports_unsupported_axes() {
        let fixture = Fixture::new(Language::Go, "main.go", "package main\n\nfunc main() {}\n");
        let rows = fixture.rows();
        for &axis in MATERIALIZATION_PRODUCER_AXES {
            assert!(
                !rows.completeness.covers(axis),
                "axis {axis} must be uncovered for an unclaimed language: {:?}",
                rows.completeness
            );
        }
        assert!(rows.sites.is_empty() && rows.exports.is_empty() && rows.links.is_empty());
    }
}
