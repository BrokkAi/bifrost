use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, Language};
use brokk_bifrost_rql::structural::CodeQuerySemanticLimits;

use super::workspace_scaled_query_limits;
use crate::budget::{SCALED_SCAN_HEADROOM, SCALED_SEMANTIC_SOURCE_BYTES_PER_SOURCE_BYTE};
use crate::inline_project::InlineTestProject;

#[test]
fn audited_file_count_widens_trusted_semantic_file_limit() {
    let mut builder = InlineTestProject::with_language(Language::TypeScript);
    let default_files = CodeQuerySemanticLimits::default().max_materialized_files;
    let file_scale = usize::try_from(SCALED_SCAN_HEADROOM).expect("file scale fits usize");
    // The first audited file count whose scaled allowance exceeds the floor.
    let file_count = default_files / file_scale + 1;
    for index in 0..file_count {
        builder = builder.file(format!("file-{index}.ts"), "export const value = 1;\n");
    }
    let project = builder.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    assert_eq!(workspace.analyzer().analyzed_files().len(), file_count);
    let limits = workspace_scaled_query_limits(&workspace);
    assert!(limits.semantic.max_materialized_files > default_files);
}

#[test]
fn audited_source_bytes_widen_trusted_semantic_source_limit() {
    // Keep each source below the analyzer's individual-file admission limit.
    let source = format!("export const value = 1;\n//{}\n", "a".repeat(10 * 1024));
    let default_bytes = CodeQuerySemanticLimits::default().max_source_bytes;
    let source_scale = usize::try_from(SCALED_SEMANTIC_SOURCE_BYTES_PER_SOURCE_BYTE)
        .expect("source-byte scale fits usize");
    // The first file count whose audited bytes, after scaling, exceed the floor.
    let file_count = default_bytes / (source.len() * source_scale) + 1;
    let mut builder = InlineTestProject::with_language(Language::TypeScript);
    for index in 0..file_count {
        builder = builder.file(format!("source-{index}.ts"), source.clone());
    }
    let project = builder.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    assert_eq!(workspace.analyzer().analyzed_files().len(), file_count);
    let limits = workspace_scaled_query_limits(&workspace);
    assert!(limits.semantic.max_source_bytes > default_bytes);
}
