use crate::{CodeUnit, IAnalyzer, JavaAnalyzer, ProjectFile, TypeHierarchyProvider};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SummaryInput {
    File(ProjectFile),
    CodeUnit(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedSummary {
    pub label: String,
    pub text: String,
}

pub fn summarize_inputs(
    analyzer: &JavaAnalyzer,
    project_root: &Path,
    inputs: &[String],
) -> Result<Vec<RenderedSummary>, String> {
    inputs
        .iter()
        .map(|input| summarize_input(analyzer, project_root, input))
        .collect()
}

fn summarize_input(
    analyzer: &JavaAnalyzer,
    project_root: &Path,
    input: &str,
) -> Result<RenderedSummary, String> {
    let target = resolve_input(analyzer, project_root, input)?;
    match target {
        SummaryInput::File(file) => {
            let text = render_file_summary(analyzer, &file)
                .ok_or_else(|| format!("No summary found for: {}", file.rel_path().display()))?;
            Ok(RenderedSummary {
                label: file.rel_path().display().to_string(),
                text,
            })
        }
        SummaryInput::CodeUnit(fq_name) => {
            let text = render_code_unit_summary(analyzer, &fq_name)
                .ok_or_else(|| format!("No summary found for: {fq_name}"))?;
            Ok(RenderedSummary {
                label: fq_name,
                text,
            })
        }
    }
}

fn resolve_input(
    analyzer: &JavaAnalyzer,
    project_root: &Path,
    input: &str,
) -> Result<SummaryInput, String> {
    let candidate_path = PathBuf::from(input);
    if candidate_path.is_absolute()
        || candidate_path.components().count() > 1
        || input.ends_with(".java")
    {
        let absolute = if candidate_path.is_absolute() {
            candidate_path
        } else {
            project_root.join(candidate_path)
        };
        let canonical = absolute
            .canonicalize()
            .map_err(|_| format!("Path not found: {}", absolute.display()))?;
        let root = project_root.canonicalize().map_err(|err| {
            format!(
                "Failed to resolve project root {}: {err}",
                project_root.display()
            )
        })?;
        let rel_path = canonical
            .strip_prefix(&root)
            .map_err(|_| format!("Path is outside the project root: {}", canonical.display()))?;
        let file = ProjectFile::new(root, rel_path.to_path_buf());
        if !analyzer.analyzed_files().any(|analyzed| analyzed == &file) {
            return Err(format!(
                "File is not analyzable by the Java analyzer: {}",
                canonical.display()
            ));
        }
        return Ok(SummaryInput::File(file));
    }

    if analyzer.definitions(input).next().is_none() {
        Err(format!("Unknown symbol or file: {input}"))
    } else {
        Ok(SummaryInput::CodeUnit(input.to_string()))
    }
}

fn render_file_summary(analyzer: &JavaAnalyzer, file: &ProjectFile) -> Option<String> {
    let skeletons: BTreeMap<CodeUnit, String> = analyzer
        .top_level_declarations(file)
        .filter(|code_unit| !code_unit.is_anonymous())
        .filter_map(|code_unit| {
            analyzer
                .get_skeleton(code_unit)
                .filter(|skeleton| !skeleton.trim().is_empty())
                .map(|skeleton| (code_unit.clone(), skeleton))
        })
        .collect();
    let rendered = format_skeletons_by_package(&skeletons);
    (!rendered.is_empty()).then_some(rendered)
}

fn render_code_unit_summary(analyzer: &JavaAnalyzer, fq_name: &str) -> Option<String> {
    let primary_targets: Vec<_> = analyzer.definitions(fq_name).cloned().collect();
    if primary_targets.is_empty() {
        return None;
    }

    let primary_target = (primary_targets.len() == 1).then(|| primary_targets[0].clone());
    let mut skeletons = BTreeMap::new();
    for code_unit in &primary_targets {
        if code_unit.is_anonymous() {
            continue;
        }
        if let Some(skeleton) = analyzer.get_skeleton(code_unit)
            && !skeleton.trim().is_empty()
        {
            skeletons.insert(code_unit.clone(), skeleton);
        }
    }

    if skeletons.is_empty() {
        return None;
    }

    let ancestors = primary_target
        .as_ref()
        .filter(|code_unit| code_unit.is_class())
        .map(|code_unit| direct_named_ancestors(analyzer, code_unit))
        .unwrap_or_default();

    Some(format_summary_with_ancestors(
        primary_target.as_ref(),
        &ancestors,
        &skeletons,
        analyzer,
    ))
}

fn direct_named_ancestors(analyzer: &JavaAnalyzer, code_unit: &CodeUnit) -> Vec<CodeUnit> {
    let mut seen = BTreeSet::new();
    analyzer
        .get_direct_ancestors(code_unit)
        .into_iter()
        .filter(|ancestor| !ancestor.is_anonymous())
        .filter(|ancestor| {
            seen.insert((
                ancestor.kind(),
                ancestor.fq_name(),
                ancestor.signature().map(str::to_string),
            ))
        })
        .collect()
}

fn format_summary_with_ancestors(
    primary_target: Option<&CodeUnit>,
    ancestors: &[CodeUnit],
    skeletons: &BTreeMap<CodeUnit, String>,
    analyzer: &JavaAnalyzer,
) -> String {
    let Some(primary_target) = primary_target else {
        return format_skeletons_by_package(skeletons);
    };
    if !primary_target.is_class() {
        return format_skeletons_by_package(skeletons);
    }

    let mut out = String::new();
    let mut primary_skeletons = BTreeMap::new();
    if let Some(primary_skeleton) = skeletons.get(primary_target) {
        primary_skeletons.insert(primary_target.clone(), primary_skeleton.clone());
        let formatted = format_skeletons_by_package(&primary_skeletons);
        if !formatted.is_empty() {
            out.push_str(&formatted);
        }
    }

    let ancestor_skeletons: BTreeMap<CodeUnit, String> = ancestors
        .iter()
        .filter_map(|ancestor| {
            analyzer
                .get_skeleton(ancestor)
                .filter(|skeleton| !skeleton.trim().is_empty())
                .map(|skeleton| (ancestor.clone(), skeleton))
        })
        .collect();
    if ancestor_skeletons.is_empty() {
        return out;
    }

    if !out.is_empty() {
        out.push_str("\n\n");
    }
    let ancestor_names = ancestors
        .iter()
        .map(|ancestor| ancestor.short_name().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!(
        "// Direct ancestors of {}: {}",
        primary_target.short_name(),
        ancestor_names
    ));

    let formatted_ancestors = format_skeletons_by_package(&ancestor_skeletons);
    if !formatted_ancestors.is_empty() {
        out.push_str("\n\n");
        out.push_str(&formatted_ancestors);
    }
    out
}

fn format_skeletons_by_package(skeletons: &BTreeMap<CodeUnit, String>) -> String {
    let mut by_package: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (code_unit, skeleton) in skeletons {
        if code_unit.is_anonymous() || skeleton.is_empty() {
            continue;
        }
        let package = if code_unit.package_name().is_empty() {
            "(default package)".to_string()
        } else {
            code_unit.package_name().to_string()
        };
        by_package
            .entry(package)
            .or_default()
            .push(skeleton.clone());
    }

    by_package
        .into_iter()
        .map(|(package, skeletons)| format!("package {package};\n\n{}", skeletons.join("\n\n")))
        .collect::<Vec<_>>()
        .join("\n\n")
}
