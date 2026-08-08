//! #1786: a Flow-annotated `.js` file the JavaScript grammar cannot parse must
//! degrade honestly instead of contributing what error recovery invented.
//!
//! `tree_sitter_javascript` has no Flow syntax, and its error recovery does not
//! fail locally: one `ref: ?Package` collapses the enclosing class, and
//! `const config: {bailout: boolean} = ...` leaves an object literal whose
//! `boolean` value identifier the declaration walk records as a field named
//! `boolean`. On yarn, 151 of 160 `src` files are contaminated this way.
//!
//! The rule these cases pin: a file is Flow-flagged by its `.flow.js` name or by
//! an `@flow` pragma in its leading docblock, and a Flow-flagged file whose tree
//! carries parse errors contributes no CodeUnits and is reported as typed
//! non-support. A pragma file that parses cleanly is ordinary JavaScript, and a
//! broken file with no Flow flag keeps exactly the behaviour it had.

use crate::common::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost::analyzer::{
    SemanticDiagnosticIncompleteReason, SemanticDiagnosticOutcome, SemanticDiagnosticReport,
};
use brokk_bifrost::{AnalyzerConfig, CodeUnit, IAnalyzer, Language, ProjectFile};

/// A class destroyed by a Flow-nullable property, plus the annotated `const`
/// whose object type is what mints the bogus `boolean` field today.
const FLOW_BODY: &str = "const config: {bailout: boolean} = {bailout: false};\n\
\n\
class Package {\n\
  ref: ?Package;\n\
\n\
  install(): void {\n\
    config.bailout = true;\n\
  }\n\
}\n";

const PRAGMA: &str = "/* @flow */\n";

fn workspace(files: Vec<(&str, String)>) -> BuiltInlineTestProject {
    let mut builder = InlineTestProject::with_language(Language::JavaScript);
    for (path, contents) in files {
        builder = builder.file(path, contents);
    }
    builder.build()
}

/// Every declaration the analyzer holds for `file`, other than the file-scope
/// unit the parse driver synthesizes for every file it reads at all.
fn declared_names(analyzer: &dyn IAnalyzer, file: &ProjectFile) -> Vec<String> {
    let file_scope = CodeUnit::file_scope(file.clone());
    let mut names: Vec<String> = analyzer
        .get_declarations(file)
        .into_iter()
        .filter(|unit| unit != &file_scope)
        .map(|unit| unit.fq_name().to_string())
        .collect();
    names.sort();
    names
}

fn report_for(project: &BuiltInlineTestProject, rel_path: &str) -> SemanticDiagnosticReport {
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file(rel_path);
    let source = analyzer
        .analyzer()
        .project()
        .read_source(&file)
        .expect("workspace source");
    analyzer.analyzer().semantic_diagnostics(&file, &source)
}

/// The one `UnsupportedSemantics` detail of a report that is a single
/// whole-file Incomplete, panicking on any other shape.
fn sole_unsupported_detail(report: &SemanticDiagnosticReport) -> String {
    assert!(
        report.diagnostics().is_empty(),
        "a file no request could judge must not carry errors: {:#?}",
        report.diagnostics()
    );
    let [SemanticDiagnosticOutcome::Incomplete { range, reasons }] = report.outcomes() else {
        panic!(
            "expected exactly one Incomplete outcome: {:#?}",
            report.outcomes()
        );
    };
    assert_eq!(&None, range, "the whole file is what could not be judged");
    let [SemanticDiagnosticIncompleteReason::UnsupportedSemantics { detail }] = reasons.as_slice()
    else {
        panic!("expected one UnsupportedSemantics reason: {reasons:#?}");
    };
    detail.clone()
}

#[test]
fn a_flow_pragma_file_with_parse_errors_mints_no_code_units() {
    let project = workspace(vec![("src/install.js", format!("{PRAGMA}{FLOW_BODY}"))]);
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("src/install.js");
    let names = declared_names(analyzer.analyzer(), &file);
    assert!(
        names.is_empty(),
        "a Flow file the grammar could not read declares nothing this walk can \
         record; got {names:#?}"
    );
    assert!(
        !names.iter().any(|name| name.ends_with("boolean")),
        "the `{{bailout: boolean}}` annotation must not mint a `boolean` field: {names:#?}"
    );
}

#[test]
fn a_flow_pragma_file_with_parse_errors_is_typed_non_support() {
    let project = workspace(vec![("src/install.js", format!("{PRAGMA}{FLOW_BODY}"))]);
    let detail = sole_unsupported_detail(&report_for(&project, "src/install.js"));
    assert!(
        detail.contains("Flow"),
        "the detail must name the dialect nothing here supports: {detail:?}"
    );
}

#[test]
fn the_same_broken_source_without_a_pragma_keeps_todays_behaviour() {
    // Nothing widens to plain broken JavaScript: the bogus units error recovery
    // invents are still minted, and the report still carries the generic
    // parse-error detail rather than the Flow one.
    let project = workspace(vec![("src/install.js", FLOW_BODY.to_string())]);
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("src/install.js");
    let names = declared_names(analyzer.analyzer(), &file);
    assert!(
        names.iter().any(|name| name.ends_with("boolean")),
        "an unflagged broken file keeps the extraction it has today: {names:#?}"
    );

    let detail = sole_unsupported_detail(&report_for(&project, "src/install.js"));
    assert_eq!("JS/TS source has parse errors", detail);
}

#[test]
fn a_flow_pragma_file_that_parses_cleanly_is_ordinary_javascript() {
    // The pragma alone suppresses nothing. This file is annotation-free, so the
    // JavaScript grammar reads exactly the program its author wrote.
    let source = format!(
        "{PRAGMA}export function install(config) {{\n  return config.bailout;\n}}\n\
         \nexport class Package {{\n  ref() {{\n    return this;\n  }}\n}}\n"
    );
    let project = workspace(vec![("src/install.js", source)]);
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("src/install.js");
    assert_eq!(
        vec![
            "Package".to_string(),
            "Package.ref".to_string(),
            "install".to_string()
        ],
        declared_names(analyzer.analyzer(), &file)
    );

    let report = report_for(&project, "src/install.js");
    assert!(
        report.diagnostics().is_empty(),
        "{:#?}",
        report.diagnostics()
    );
    assert!(
        !report.outcomes().iter().any(|outcome| matches!(
            outcome,
            SemanticDiagnosticOutcome::Incomplete { range: None, .. }
        )),
        "a clean parse is judged like any other file: {:#?}",
        report.outcomes()
    );
}

#[test]
fn a_flow_js_filename_is_flagged_without_a_pragma() {
    let project = workspace(vec![("src/install.flow.js", FLOW_BODY.to_string())]);
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("src/install.flow.js");
    assert!(
        declared_names(analyzer.analyzer(), &file).is_empty(),
        "the `.flow.js` name says Flow as plainly as the pragma does"
    );
    let detail = sole_unsupported_detail(&report_for(&project, "src/install.flow.js"));
    assert!(detail.contains("Flow"), "{detail:?}");
}

#[test]
fn an_at_flow_mention_below_the_leading_docblock_is_not_a_pragma() {
    // Flow reads the pragma out of the first docblock only, so prose that
    // mentions `@flow` further down declares nothing.
    let source = format!(
        "// nothing to see here\nexport const ready = true;\n\n// see @flow for the types\n{FLOW_BODY}"
    );
    let project = workspace(vec![("src/install.js", source)]);
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("src/install.js");
    assert!(
        declared_names(analyzer.analyzer(), &file)
            .iter()
            .any(|name| name.ends_with("boolean")),
        "a mid-file mention must not flag the file"
    );
    assert_eq!(
        "JS/TS source has parse errors",
        sole_unsupported_detail(&report_for(&project, "src/install.js"))
    );
}
