//! Cyclomatic-complexity changes for functions introduced or edited by a diff.

use crate::analyzer::{CodeUnit, IAnalyzer};
use crate::code_quality::cyclomatic_complexities_for_file;
use crate::diff_analysis::{
    CommitSymbol, DiffAnalysisOptions, DiffEndpointParams, FileChange, PreparedDiff,
    analyze_prepared_symbol_changes,
};
use crate::path_utils::rel_path_string;
use crate::searchtools_render::{RenderOptions, RenderText};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct CyclomaticComplexityParams {
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub include_tests: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CyclomaticComplexityDiffResult {
    pub endpoints: CyclomaticComplexityEndpoints,
    pub summary: CyclomaticComplexitySummary,
    pub functions: Vec<CyclomaticComplexityChange>,
    pub analysis: CyclomaticComplexityAnalysis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CyclomaticComplexityEndpoints {
    pub base: String,
    pub target: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CyclomaticComplexitySummary {
    pub introduced: usize,
    pub edited: usize,
    pub increased: usize,
    pub decreased: usize,
    pub unchanged: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CyclomaticComplexityChange {
    pub change: CyclomaticComplexityChangeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<CyclomaticComplexityFunction>,
    pub after: CyclomaticComplexityFunction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CyclomaticComplexityChangeKind {
    Introduced,
    Edited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CyclomaticComplexityFunction {
    pub fqn: String,
    pub name: String,
    pub signature: String,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub language: String,
    pub is_test: bool,
    pub complexity: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CyclomaticComplexityAnalysis {
    pub paths_outside_analysis: Vec<String>,
    pub unresolved_changed_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FunctionKey {
    path: String,
    fqn: String,
}

impl FunctionKey {
    fn for_symbol(symbol: &CommitSymbol) -> Self {
        Self {
            path: symbol.path.clone(),
            fqn: symbol.fqn.clone(),
        }
    }

    fn for_code_unit(unit: &CodeUnit) -> Self {
        Self {
            path: rel_path_string(unit.source()),
            fqn: unit.fq_name(),
        }
    }
}

pub fn cyclomatic_complexity_at_root(
    root: &Path,
    params: CyclomaticComplexityParams,
    options: &DiffAnalysisOptions,
) -> Result<CyclomaticComplexityDiffResult, String> {
    let prepared = PreparedDiff::at_root(
        root,
        DiffEndpointParams {
            base: params.base,
            target: params.target,
        },
        options,
    )?;
    let endpoints = CyclomaticComplexityEndpoints {
        base: prepared.base.label(),
        target: prepared.target.label(),
    };
    let (base_paths, target_paths, paths_outside_analysis) =
        complexity_paths(&prepared.file_changes);
    let analyzed = analyze_prepared_symbol_changes(&prepared, params.include_tests)?;
    let (base_analyzer, target_analyzer) = analyzed.endpoint_analyzers();
    let (base_complexities, mut unresolved_changed_paths) =
        complexity_map(base_analyzer, &base_paths);
    let (target_complexities, target_unresolved_paths) =
        complexity_map(target_analyzer, &target_paths);
    unresolved_changed_paths.extend(target_unresolved_paths);

    let mut functions = Vec::new();
    for introduced in &analyzed.symbol_changes().introduced {
        let key = FunctionKey::for_symbol(&introduced.after);
        let Some(&complexity) = target_complexities.get(&key) else {
            continue;
        };
        functions.push(CyclomaticComplexityChange {
            change: CyclomaticComplexityChangeKind::Introduced,
            before: None,
            after: function_with_complexity(&introduced.after, complexity),
            delta: None,
        });
    }
    for edited in &analyzed.symbol_changes().edited {
        let before_key = FunctionKey::for_symbol(&edited.before);
        let after_key = FunctionKey::for_symbol(&edited.after);
        let Some(&after_complexity) = target_complexities.get(&after_key) else {
            continue;
        };
        let before_complexity = *base_complexities.get(&before_key).unwrap_or_else(|| {
            panic!(
                "paired function is missing from the base complexity map: {:?}",
                before_key
            )
        });
        functions.push(CyclomaticComplexityChange {
            change: CyclomaticComplexityChangeKind::Edited,
            before: Some(function_with_complexity(&edited.before, before_complexity)),
            after: function_with_complexity(&edited.after, after_complexity),
            delta: Some(i64::from(after_complexity) - i64::from(before_complexity)),
        });
    }
    functions.sort_by(|left, right| {
        (
            &left.after.path,
            left.after.start_line,
            left.after.end_line,
            &left.after.fqn,
            &left.after.signature,
        )
            .cmp(&(
                &right.after.path,
                right.after.start_line,
                right.after.end_line,
                &right.after.fqn,
                &right.after.signature,
            ))
    });

    let mut summary = CyclomaticComplexitySummary::default();
    for function in &functions {
        match function.change {
            CyclomaticComplexityChangeKind::Introduced => summary.introduced += 1,
            CyclomaticComplexityChangeKind::Edited => {
                summary.edited += 1;
                match function.delta.expect("edited functions have a delta") {
                    delta if delta > 0 => summary.increased += 1,
                    delta if delta < 0 => summary.decreased += 1,
                    _ => summary.unchanged += 1,
                }
            }
        }
    }
    debug_assert_eq!(
        summary.edited,
        summary.increased + summary.decreased + summary.unchanged
    );

    Ok(CyclomaticComplexityDiffResult {
        endpoints,
        summary,
        functions,
        analysis: CyclomaticComplexityAnalysis {
            paths_outside_analysis,
            unresolved_changed_paths: unresolved_changed_paths.into_iter().collect(),
        },
    })
}

fn complexity_paths(
    file_changes: &[FileChange],
) -> (BTreeSet<PathBuf>, BTreeSet<PathBuf>, Vec<String>) {
    let mut base_paths = BTreeSet::new();
    let mut target_paths = BTreeSet::new();
    let mut paths_outside_analysis = BTreeSet::new();
    for change in file_changes {
        let before_path = change.old_path.as_deref().or(change.path.as_deref());
        let after_path = change.path.as_deref();
        if !change.is_parseable {
            paths_outside_analysis.extend(before_path.into_iter().map(str::to_string));
            paths_outside_analysis.extend(after_path.into_iter().map(str::to_string));
            continue;
        }
        if change.status != "added"
            && let Some(path) = before_path
        {
            base_paths.insert(PathBuf::from(path));
        }
        if change.status != "deleted"
            && let Some(path) = after_path
        {
            target_paths.insert(PathBuf::from(path));
        }
    }
    (
        base_paths,
        target_paths,
        paths_outside_analysis.into_iter().collect(),
    )
}

fn complexity_map(
    analyzer: &dyn IAnalyzer,
    paths: &BTreeSet<PathBuf>,
) -> (BTreeMap<FunctionKey, u32>, BTreeSet<String>) {
    let mut complexities = BTreeMap::new();
    let mut unresolved = BTreeSet::new();
    for path in paths {
        let Some(file) = analyzer.project().file_by_rel_path(path) else {
            unresolved.insert(path.to_string_lossy().replace('\\', "/"));
            continue;
        };
        for (unit, complexity) in cyclomatic_complexities_for_file(analyzer, &file) {
            complexities.insert(FunctionKey::for_code_unit(&unit), complexity);
        }
    }
    (complexities, unresolved)
}

fn function_with_complexity(
    symbol: &CommitSymbol,
    complexity: u32,
) -> CyclomaticComplexityFunction {
    CyclomaticComplexityFunction {
        fqn: symbol.fqn.clone(),
        name: symbol.name.clone(),
        signature: symbol.signature.clone(),
        path: symbol.path.clone(),
        start_line: symbol.start_line,
        end_line: symbol.end_line,
        language: symbol.language.clone(),
        is_test: symbol.is_test,
        complexity,
    }
}

impl RenderText for CyclomaticComplexityDiffResult {
    fn render_text(&self, options: RenderOptions) -> String {
        let mut lines = vec![
            "# Cyclomatic complexity changes".to_string(),
            String::new(),
            format!(
                "- Endpoints: `{}` -> `{}`",
                self.endpoints.base, self.endpoints.target
            ),
            format!("- Introduced functions: {}", self.summary.introduced),
            format!(
                "- Edited functions: {} ({} increased, {} decreased, {} unchanged)",
                self.summary.edited,
                self.summary.increased,
                self.summary.decreased,
                self.summary.unchanged
            ),
        ];
        if !self.analysis.paths_outside_analysis.is_empty() {
            lines.push(format!(
                "- Changed paths outside analyzer support: `{:?}`",
                self.analysis.paths_outside_analysis
            ));
        }
        if !self.analysis.unresolved_changed_paths.is_empty() {
            lines.push(format!(
                "- Unresolved changed paths: `{:?}`",
                self.analysis.unresolved_changed_paths
            ));
        }
        if self.functions.is_empty() {
            lines.push(String::new());
            lines.push("No introduced or edited functions were found.".to_string());
            return lines.join("\n");
        }
        lines.push(String::new());
        lines.push("## Functions".to_string());
        lines.push(String::new());
        for function in &self.functions {
            let location = if options.render_line_numbers {
                format!("{}:{}", function.after.path, function.after.start_line)
            } else {
                function.after.path.clone()
            };
            match function.change {
                CyclomaticComplexityChangeKind::Introduced => lines.push(format!(
                    "- `{}`: introduced at `{location}` with complexity {}",
                    function.after.fqn, function.after.complexity
                )),
                CyclomaticComplexityChangeKind::Edited => {
                    let before = function
                        .before
                        .as_ref()
                        .expect("edited functions have a preimage");
                    let delta = function.delta.expect("edited functions have a delta");
                    lines.push(format!(
                        "- `{}` at `{location}`: {} -> {} ({delta:+})",
                        function.after.fqn, before.complexity, function.after.complexity
                    ));
                }
            }
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitblob::test_repo;
    use std::fs;

    #[test]
    fn reports_introduced_and_edited_functions_but_not_deleted_or_moved_functions() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::write(
            root.join("src/lib.rs"),
            concat!(
                "pub fn increased(x: i32) -> i32 { x + 1 }\n",
                "pub fn same(x: i32) -> i32 { x + 1 }\n",
                "pub fn deleted() -> i32 { 1 }\n",
            ),
        )
        .expect("base source");
        fs::write(
            root.join("src/moved.rs"),
            "pub fn moved(x: i32) -> i32 { if x > 0 { x } else { 0 } }\n",
        )
        .expect("base moved source");
        let repo = test_repo::init_repo(root);
        let base = test_repo::commit_all(&repo, "base");

        fs::write(
            root.join("src/lib.rs"),
            concat!(
                "pub fn increased(x: i32) -> i32 { if x > 0 { x } else { 0 } }\n",
                "pub fn same(x: i32) -> i32 { x + 2 }\n",
                "pub fn introduced(x: i32) -> i32 { if x > 0 && x < 10 { x } else { 0 } }\n",
            ),
        )
        .expect("target source");
        fs::rename(root.join("src/moved.rs"), root.join("src/relocated.rs")).expect("move source");
        fs::write(root.join("notes.md"), "changed documentation\n").expect("outside path");
        let target = test_repo::commit_all(&repo, "target");

        let result = cyclomatic_complexity_at_root(
            root,
            CyclomaticComplexityParams {
                base: None,
                target: Some(target.to_string()),
                include_tests: false,
            },
            &DiffAnalysisOptions::default(),
        )
        .expect("complexity diff");

        assert_eq!(base.to_string(), result.endpoints.base);
        assert_eq!(target.to_string(), result.endpoints.target);
        assert_eq!(
            CyclomaticComplexitySummary {
                introduced: 1,
                edited: 2,
                increased: 1,
                decreased: 0,
                unchanged: 1,
            },
            result.summary
        );
        assert_eq!(
            ["increased", "same", "introduced"],
            result
                .functions
                .iter()
                .map(|function| function.after.name.as_str())
                .collect::<Vec<_>>()
                .as_slice()
        );
        let increased = result
            .functions
            .iter()
            .find(|function| function.after.name == "increased")
            .expect("increased function");
        assert_eq!(Some(1), increased.delta);
        assert_eq!(1, increased.before.as_ref().unwrap().complexity);
        assert_eq!(2, increased.after.complexity);
        let introduced = result
            .functions
            .iter()
            .find(|function| function.after.name == "introduced")
            .expect("introduced function");
        assert_eq!(
            CyclomaticComplexityChangeKind::Introduced,
            introduced.change
        );
        assert_eq!(None, introduced.before);
        assert_eq!(None, introduced.delta);
        assert_eq!(3, introduced.after.complexity);
        let unchanged = result
            .functions
            .iter()
            .find(|function| function.after.name == "same")
            .expect("unchanged-complexity function");
        assert_eq!(Some(0), unchanged.delta);
        assert_eq!(vec!["notes.md"], result.analysis.paths_outside_analysis);
        assert!(result.analysis.unresolved_changed_paths.is_empty());
    }

    #[test]
    fn excludes_test_functions_by_default_and_includes_them_on_request() {
        let temp = tempfile::tempdir().expect("temporary repository");
        let root = temp.path();
        fs::create_dir_all(root.join("tests")).expect("test directory");
        fs::write(root.join("README.md"), "base\n").expect("base file");
        let repo = test_repo::init_repo(root);
        test_repo::commit_all(&repo, "base");
        fs::write(
            root.join("tests/changed.rs"),
            "fn test_behavior() { if true { assert!(true); } }\n",
        )
        .expect("test source");
        let target = test_repo::commit_all(&repo, "target");

        let excluded = cyclomatic_complexity_at_root(
            root,
            CyclomaticComplexityParams {
                target: Some(target.to_string()),
                ..CyclomaticComplexityParams::default()
            },
            &DiffAnalysisOptions::default(),
        )
        .expect("complexity diff without tests");
        assert!(excluded.functions.is_empty());

        let included = cyclomatic_complexity_at_root(
            root,
            CyclomaticComplexityParams {
                target: Some(target.to_string()),
                include_tests: true,
                ..CyclomaticComplexityParams::default()
            },
            &DiffAnalysisOptions::default(),
        )
        .expect("complexity diff with tests");
        assert_eq!(1, included.functions.len());
        assert!(included.functions[0].after.is_test);
    }

    #[test]
    fn text_rendering_can_omit_line_numbers() {
        let result = CyclomaticComplexityDiffResult {
            endpoints: CyclomaticComplexityEndpoints {
                base: "base".to_string(),
                target: "target".to_string(),
            },
            summary: CyclomaticComplexitySummary {
                introduced: 1,
                ..CyclomaticComplexitySummary::default()
            },
            functions: vec![CyclomaticComplexityChange {
                change: CyclomaticComplexityChangeKind::Introduced,
                before: None,
                after: CyclomaticComplexityFunction {
                    fqn: "sample".to_string(),
                    name: "sample".to_string(),
                    signature: String::new(),
                    path: "src/lib.rs".to_string(),
                    start_line: 7,
                    end_line: 9,
                    language: "rust".to_string(),
                    is_test: false,
                    complexity: 2,
                },
                delta: None,
            }],
            analysis: CyclomaticComplexityAnalysis::default(),
        };

        assert!(
            result
                .render_text(RenderOptions {
                    render_line_numbers: true,
                })
                .contains("`src/lib.rs:7`")
        );
        assert!(
            result
                .render_text(RenderOptions {
                    render_line_numbers: false,
                })
                .contains("`src/lib.rs`")
        );
    }
}
