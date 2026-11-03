//! The execution adapter between the query engine and the build configuration
//! a file is analyzed under (#9048).
//!
//! One row per file and configuration: the selected configuration of the
//! file's language, with the provenance of each target axis, and the file's
//! own build constraint evaluated under it and across every known target. The
//! row family is shared by languages; each language with a selected build
//! contributes a producer here. A file of any other language gets no row and a
//! typed diagnostic, so a policy cannot read "not built for this target" off a
//! language nobody answered for.
//!
//! Go rows are derived on demand from the analyzer's selected configuration
//! and the file's prepared syntax. Rust rows (#9049) are derived from the
//! persisted `rust-toolchain` evidence of the Cargo package that owns the
//! file: the configured `build.target` values, or else the host, and each
//! further target its rustup toolchain file installs. A Rust file's own cfg
//! gating is not evaluated, so its status and target scopes stay unknown.

use super::results::{
    CodeQueryBuildConfiguration, CodeQueryDiagnostic, CodeQueryDiagnosticCode,
    CodeQueryDiagnosticImpact, DetailedCodeQueryKey,
};
use super::topology_rows::TopologyTraversalCache;
use crate::analyzer::semantic::LengthDelimitedDigest;
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::path_utils::rel_path_string;
use crate::path_utils::workspace_relative_slash_path;
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_go_analysis::{GoAnalyzer, GoFileBuildConfiguration, GoTargetScope};
use brokk_bifrost_rust_analysis::analyzer::RUST_TOOLCHAIN_ECOSYSTEM;
use brokk_bifrost_rust_analysis::analyzer::semantic_model::DependencyEvidence;

const CONFIGURATION_ID_DOMAIN: &[u8] = b"bifrost.code_query.build_configuration.v1";
const ROW_ID_DOMAIN: &[u8] = b"bifrost.code_query.build_configuration_file.v1";

/// One build-configuration row travelling through the pipeline.
#[derive(Debug, Clone)]
pub(super) struct BuildConfigurationValue {
    pub(super) file: ProjectFile,
    pub(super) row: CodeQueryBuildConfiguration,
}

impl BuildConfigurationValue {
    pub(super) fn file(&self) -> &ProjectFile {
        &self.file
    }

    pub(super) fn key(&self) -> String {
        self.row.id.clone()
    }

    pub(super) fn detailed_key(&self) -> DetailedCodeQueryKey {
        DetailedCodeQueryKey::BuildConfiguration {
            id: self.row.id.clone(),
            configuration_id: self.row.configuration_id.clone(),
        }
    }
}

/// The `build_configuration` row of one file, or none plus the reason.
pub(super) fn build_configurations_of_file(
    cache: &mut TopologyTraversalCache,
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<BuildConfigurationValue> {
    let language = crate::analyzer::common::language_for_file(file);
    if language == Language::Rust {
        return rust_rows(cache, analyzer, file, diagnostics);
    }
    let go = (language == Language::Go)
        .then(|| resolve_analyzer::<GoAnalyzer>(analyzer))
        .flatten();
    let Some(go) = go else {
        report(
            cache,
            language,
            language.config_label().to_owned(),
            brokk_bifrost_rql::Incompleteness::Content,
            format!(
                "no build-configuration provider answers for {} files, so the absence of a \
                 build_configuration row is not evidence of any target",
                language.config_label()
            ),
            diagnostics,
        );
        return Vec::new();
    };
    let Some(configuration) = go.file_build_configuration(token, file) else {
        let path = rel_path_string(file);
        report(
            cache,
            language,
            path.clone(),
            brokk_bifrost_rql::Incompleteness::Operational(
                brokk_bifrost_rql::DiagnosticExecutionCause::Provider,
            ),
            format!("the syntax of {path} is unavailable, so its build constraint is unknown"),
            diagnostics,
        );
        return Vec::new();
    };
    vec![BuildConfigurationValue {
        file: file.clone(),
        row: go_row(file, &configuration),
    }]
}

fn report(
    cache: &mut TopologyTraversalCache,
    language: Language,
    subject: String,
    incompleteness: brokk_bifrost_rql::Incompleteness,
    message: String,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) {
    if !cache.first_report(subject, "build_configuration") {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic::new(CodeQueryDiagnostic {
        incompleteness,
        related: Vec::new(),
        source: None,
        code: CodeQueryDiagnosticCode::TopologyDerivationIncomplete,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: language.config_label(),
        message,
        exhausted_roots: Vec::new(),
        withheld_rows_path: None,
    }));
}

fn go_row(
    file: &ProjectFile,
    configuration: &GoFileBuildConfiguration,
) -> CodeQueryBuildConfiguration {
    let build = &configuration.selected.build;
    let mut digest = LengthDelimitedDigest::new(CONFIGURATION_ID_DOMAIN);
    digest.push(b"go");
    digest.push(build.goos.as_bytes());
    digest.push(build.goarch.as_bytes());
    digest.push(&[u8::from(build.cgo_enabled)]);
    for tag in &build.tags {
        digest.push(tag.as_bytes());
    }
    let configuration_id = digest.finish().to_string();
    let path = rel_path_string(file);
    let mut digest = LengthDelimitedDigest::new(ROW_ID_DOMAIN);
    digest.push(configuration_id.as_bytes());
    digest.push(path.as_bytes());
    let (os_scope, os_values) = scope_columns(&configuration.goos_scope);
    let (arch_scope, arch_values) = scope_columns(&configuration.goarch_scope);
    CodeQueryBuildConfiguration {
        id: digest.finish().to_string(),
        configuration_id,
        language: Language::Go.config_label(),
        path,
        target: None,
        os: Some(build.goos.clone()),
        os_source: Some(configuration.selected.goos_source.label()),
        arch: Some(build.goarch.clone()),
        arch_source: Some(configuration.selected.goarch_source.label()),
        file_status: match configuration.included {
            Some(true) => "included",
            Some(false) => "excluded",
            None => "unknown",
        },
        constraint: match &configuration.constraint {
            Ok(expr) => expr.as_ref().map(|expr| expr.render()),
            Err(directive) => Some(directive.clone()),
        },
        os_scope,
        os_values,
        arch_scope,
        arch_values,
    }
}

fn scope_columns(scope: &GoTargetScope) -> (&'static str, Option<String>) {
    match scope {
        GoTargetScope::Any => ("any", None),
        GoTargetScope::Only(values) if values.is_empty() => ("none", None),
        GoTargetScope::Only(values) => ("restricted", Some(values.join(" "))),
        GoTargetScope::Unknown => ("unknown", None),
    }
}

/// The configurations a Rust file's owning Cargo package builds for.
fn rust_rows(
    cache: &mut TopologyTraversalCache,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<BuildConfigurationValue> {
    use brokk_bifrost_rust_analysis::analyzer::rust::{
        builtin_target_platform, host_target_triple,
    };
    let evidence = cache
        .rust_toolchain
        .get_or_insert_with(|| {
            analyzer
                .dependency_file_evidence()
                .map(|evidence| {
                    evidence
                        .rows
                        .into_iter()
                        .filter(|row| row.ecosystem == RUST_TOOLCHAIN_ECOSYSTEM)
                        .collect()
                })
                .map_err(|error| error.to_string())
        })
        .clone();
    let path = rel_path_string(file);
    let rows = match evidence {
        Ok(rows) => rows,
        Err(error) => {
            report(
                cache,
                Language::Rust,
                "rust-toolchain".to_owned(),
                brokk_bifrost_rql::Incompleteness::Operational(
                    brokk_bifrost_rql::DiagnosticExecutionCause::Provider,
                ),
                format!("Rust toolchain evidence is unavailable: {error}"),
                diagnostics,
            );
            return Vec::new();
        }
    };
    // The nearest enclosing package manifest owns the file.
    let owned = file.rel_path().ancestors().skip(1).find_map(|directory| {
        let manifest = workspace_relative_slash_path(&directory.join("Cargo.toml"));
        let owned = rows
            .iter()
            .filter(|row| condition_values(row, "cargo.member_manifest").any(|m| m == manifest))
            .collect::<Vec<_>>();
        (!owned.is_empty()).then_some(owned)
    });
    let Some(owned) = owned else {
        report(
            cache,
            Language::Rust,
            path.clone(),
            brokk_bifrost_rql::Incompleteness::Content,
            format!("no Cargo package owns {path}, so its build target is unknown"),
            diagnostics,
        );
        return Vec::new();
    };
    let evidence_values = |evidence: &'static str, key: &'static str| {
        owned
            .iter()
            .filter(move |row| {
                condition_values(row, "rust.toolchain_evidence").any(|value| value == evidence)
            })
            .flat_map(move |row| condition_values(row, key))
    };
    let mut targets = evidence_values("cargo_build_target", "rust.build_target")
        .map(|target| (target.to_owned(), "configuration"))
        .collect::<Vec<_>>();
    if targets.is_empty() {
        targets.push((host_target_triple().to_owned(), "host"));
    }
    for target in evidence_values("toolchain_file", "rust.toolchain_target") {
        if !targets.iter().any(|(selected, _)| selected == target) {
            targets.push((target.to_owned(), "toolchain"));
        }
    }
    targets
        .into_iter()
        .map(|(target, source)| {
            let mut digest = LengthDelimitedDigest::new(CONFIGURATION_ID_DOMAIN);
            digest.push(b"rust");
            digest.push(target.as_bytes());
            digest.push(source.as_bytes());
            let configuration_id = digest.finish().to_string();
            let mut digest = LengthDelimitedDigest::new(ROW_ID_DOMAIN);
            digest.push(configuration_id.as_bytes());
            digest.push(path.as_bytes());
            let platform = builtin_target_platform(&target);
            BuildConfigurationValue {
                file: file.clone(),
                row: CodeQueryBuildConfiguration {
                    id: digest.finish().to_string(),
                    configuration_id,
                    language: Language::Rust.config_label(),
                    path: path.clone(),
                    os: platform.map(|(os, _)| os.to_owned()),
                    os_source: Some(source),
                    arch: platform.map(|(_, arch)| arch.to_owned()),
                    arch_source: Some(source),
                    target: Some(target),
                    file_status: "unknown",
                    constraint: None,
                    os_scope: "unknown",
                    os_values: None,
                    arch_scope: "unknown",
                    arch_values: None,
                },
            }
        })
        .collect()
}

fn condition_values<'a>(
    row: &'a DependencyEvidence,
    kind: &'static str,
) -> impl Iterator<Item = &'a str> {
    row.conditions
        .iter()
        .filter(move |condition| condition.kind == kind)
        .map(|condition| condition.value.as_str())
}
