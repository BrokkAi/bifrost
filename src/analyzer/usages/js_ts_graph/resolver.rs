use crate::analyzer::usages::common::language_for_target_filtered;
use crate::analyzer::usages::graph_core::ProjectUsageGraph;
use crate::analyzer::usages::js_ts_graph::extractor::{
    compute_export_index, compute_import_binder,
};
use crate::analyzer::usages::model::{ExportIndex, ImportBinder};
use crate::analyzer::{
    AliasResolver, CodeUnit, IAnalyzer, Language, ProjectFile, resolve_js_ts_module_specifier,
};
use crate::hash::{HashMap, map_with_capacity};
use rayon::prelude::*;
use std::sync::Arc;
use tree_sitter::{Parser, Tree};

/// Cached parse for one source file. `source` is held alongside the `Tree` so AST byte
/// ranges remain valid for the lifetime of the graph (and so the scan phase can reuse
/// the parse result without re-reading the file).
pub(super) struct ParsedFile {
    pub(super) source: Arc<String>,
    pub(super) tree: Tree,
    /// Byte offsets of each line start, computed once at parse time so the
    /// inverted edge scan can attribute references to lines without recomputing.
    pub(super) line_starts: Vec<usize>,
}

pub(crate) struct JsTsProjectGraph {
    /// Parsed source + tree per file. Reused by the scan phase to avoid double parsing.
    pub(super) parsed: HashMap<ProjectFile, ParsedFile>,
    pub(super) usage_graph: ProjectUsageGraph,
}

pub(super) fn build_js_ts_graph(analyzer: &dyn IAnalyzer, language: Language) -> JsTsProjectGraph {
    let files = collect_jsts_files(analyzer, language);
    let parser_language = match language {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        _ => {
            return JsTsProjectGraph {
                parsed: HashMap::default(),
                usage_graph: ProjectUsageGraph::empty(),
            };
        }
    };

    let parsed_files: Vec<(ProjectFile, ParsedFile, ExportIndex, ImportBinder)> = files
        .par_iter()
        .filter_map(|file| {
            let source = file.read_to_string().ok()?;
            let mut parser = Parser::new();
            parser.set_language(&parser_language).ok()?;
            let tree = parser.parse(source.as_str(), None)?;
            let exports = compute_export_index(&source, &tree);
            let binder = compute_import_binder(&source, &tree);
            let line_starts = crate::text_utils::compute_line_starts(&source);
            Some((
                file.clone(),
                ParsedFile {
                    source: Arc::new(source),
                    tree,
                    line_starts,
                },
                exports,
                binder,
            ))
        })
        .collect();

    let mut parsed: HashMap<ProjectFile, ParsedFile> = map_with_capacity(parsed_files.len());
    let mut exports_by_file: HashMap<ProjectFile, ExportIndex> =
        map_with_capacity(parsed_files.len());
    let mut binders_by_file: HashMap<ProjectFile, ImportBinder> =
        map_with_capacity(parsed_files.len());

    for (file, parsed_file, exports, binder) in parsed_files {
        parsed.insert(file.clone(), parsed_file);
        exports_by_file.insert(file.clone(), exports);
        binders_by_file.insert(file, binder);
    }

    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());
    let usage_graph = ProjectUsageGraph::build(
        files,
        exports_by_file,
        &binders_by_file,
        |file, module_specifier| {
            resolve_js_ts_module_specifier(file, module_specifier, language, Some(&aliases))
        },
    );

    JsTsProjectGraph {
        parsed,
        usage_graph,
    }
}

fn collect_jsts_files(analyzer: &dyn IAnalyzer, language: Language) -> Vec<ProjectFile> {
    let mut result: Vec<ProjectFile> = analyzer
        .project()
        .analyzable_files(language)
        .map(|set| set.into_iter().collect())
        .unwrap_or_default();
    result.sort();
    result.dedup();
    result
}

pub(super) fn target_language(target: &CodeUnit) -> Language {
    language_for_target_filtered(target, |lang| {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    })
}

pub(super) fn top_level_identifier(target: &CodeUnit) -> &str {
    // For nested members like `BaseClass.foo`, the top-level identifier is `BaseClass`.
    target
        .short_name()
        .split('.')
        .next()
        .unwrap_or(target.short_name())
}

pub(super) fn member_name(target: &CodeUnit) -> Option<String> {
    // Anything past the first dot is treated as the member chain. We strip TS-specific
    // `$static` suffix to align with the original syntactic name.
    let parts: Vec<&str> = target.short_name().split('.').collect();
    if parts.len() <= 1 {
        return None;
    }
    let last = parts.last().copied()?;
    Some(last.trim_end_matches("$static").to_string())
}

pub(super) fn is_static_member(target: &CodeUnit) -> bool {
    target.short_name().ends_with("$static")
}
