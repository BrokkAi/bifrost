use crate::analyzer::ProjectFile;
use crate::hash::HashMap;
use crate::text_utils::compute_line_starts;
use rayon::prelude::*;
use tree_sitter::{Language as TreeSitterLanguage, Parser, Tree};

pub(crate) struct ParsedTreeFile {
    pub(crate) source: String,
    pub(crate) tree: Tree,
    pub(crate) line_starts: Vec<usize>,
}

pub(crate) fn parse_kept_tree_sitter_files<F>(
    files: &[ProjectFile],
    keep_file: &F,
    language: &TreeSitterLanguage,
) -> HashMap<ProjectFile, ParsedTreeFile>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    files
        .par_iter()
        .filter(|file| keep_file(file))
        .filter_map(|file| parse_tree_sitter_file(file, language))
        .collect()
}

fn parse_tree_sitter_file(
    file: &ProjectFile,
    language: &TreeSitterLanguage,
) -> Option<(ProjectFile, ParsedTreeFile)> {
    let source = file.read_to_string().ok()?;
    if source.is_empty() {
        return None;
    }
    let mut parser = Parser::new();
    parser.set_language(language).ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let line_starts = compute_line_starts(&source);
    Some((
        file.clone(),
        ParsedTreeFile {
            source,
            tree,
            line_starts,
        },
    ))
}
