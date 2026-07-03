use crate::model_context;
use crate::path_utils::AmbiguousPathInput;
use crate::searchtools::{
    AmbiguousSymbol, MostRelevantFilesResult, SearchSymbolHit, SearchSymbolsFile,
    SearchSymbolsResult, SkimFile, SkimFilesResult, SourceBlock, SummaryBlock, SummaryElement,
    SummaryResult, SymbolAncestors, SymbolAncestorsResult, SymbolLocation, SymbolLocationsResult,
    SymbolSourcesResult,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderOptions {
    pub render_line_numbers: bool,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            render_line_numbers: true,
        }
    }
}

pub trait RenderText {
    fn render_text(&self, options: RenderOptions) -> String;
}

#[cfg(feature = "nlp")]
impl RenderText for crate::nlp::query::SemanticSearchResult {
    fn render_text(&self, _options: RenderOptions) -> String {
        use crate::nlp::query::{RankedFile, RankedSymbol};

        let mut blocks: Vec<String> = Vec::new();
        if !self.notes.is_empty() {
            blocks.push(
                self.notes
                    .iter()
                    .map(|note| format!("note: {note}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }

        let symbol_section = |title: &str, rows: &[RankedSymbol]| -> Option<String> {
            if rows.is_empty() {
                return None;
            }
            let mut block = format!("=== {title} ===");
            for row in rows {
                block.push_str(&format!("\n{} (score {:.3})", row.fqfn, row.score));
            }
            Some(block)
        };
        let file_section = |title: &str, rows: &[RankedFile]| -> Option<String> {
            if rows.is_empty() {
                return None;
            }
            let mut block = format!("=== {title} ===");
            for row in rows {
                block.push_str(&format!("\n{} (score {:.3})", row.path, row.score));
            }
            Some(block)
        };

        let sections = [
            symbol_section("vector", &self.vector_ranked),
            symbol_section("bm25", &self.bm25_ranked),
            file_section("co-edit", &self.coedit_ranked),
        ];
        let any_results = sections.iter().any(Option::is_some);
        blocks.extend(sections.into_iter().flatten());

        if !any_results {
            blocks.push("No semantically similar code found.".to_string());
        }
        blocks.join("\n\n")
    }
}

impl RenderText for SearchSymbolsResult {
    fn render_text(&self, options: RenderOptions) -> String {
        let blocks: Vec<String> = self
            .files
            .iter()
            .map(|file| file.render_text(options))
            .collect();
        if blocks.is_empty() {
            return "No matching symbols found.".to_string();
        }
        let mut lines = vec![
            "# Symbol search results".to_string(),
            String::new(),
            format!(
                "- Patterns: {}",
                render_inline_list(self.patterns.iter().map(String::as_str))
            ),
            format!("- Files: {} of {}", self.files.len(), self.total_files),
        ];
        if self.truncated {
            lines.push(
                "- Truncated: yes; files ranked by symbol relevance, with recent activity used only as a tie-breaker when available."
                    .to_string(),
            );
        }
        lines.push(String::new());
        lines.push(blocks.join("\n\n"));
        lines.join("\n")
    }
}

impl RenderText for SymbolLocationsResult {
    fn render_text(&self, options: RenderOptions) -> String {
        let mut lines: Vec<String> = self
            .locations
            .iter()
            .map(|location| location.render_text(options))
            .collect();
        if !self.not_found.is_empty() {
            lines.push(format!("Not found: {}", self.not_found.join(", ")));
        }
        if lines.is_empty() {
            "No matching symbols found.".to_string()
        } else {
            lines.join("\n")
        }
    }
}

impl RenderText for SymbolAncestorsResult {
    fn render_text(&self, _options: RenderOptions) -> String {
        let mut blocks: Vec<String> = self
            .ancestors
            .iter()
            .map(SymbolAncestors::render_text)
            .collect();
        if !self.not_found.is_empty() {
            blocks.push(render_not_found(&self.not_found));
        }
        if !self.ambiguous.is_empty() {
            blocks.push(render_ambiguous_symbols_table(&self.ambiguous));
        }
        if blocks.is_empty() {
            "No matching ancestors found.".to_string()
        } else {
            blocks.join("\n\n")
        }
    }
}

impl RenderText for SummaryResult {
    fn render_text(&self, options: RenderOptions) -> String {
        let mut blocks: Vec<String> = self
            .summaries
            .iter()
            .map(|summary| summary.render_text(options))
            .collect();
        if !self.not_found.is_empty() {
            blocks.push(format!("Not found: {}", self.not_found.join(", ")));
        }
        blocks.extend(self.ambiguous.iter().map(render_ambiguous_symbol));
        if !self.ambiguous_paths.is_empty() {
            blocks.push(render_ambiguous_paths(&self.ambiguous_paths));
        }
        if blocks.is_empty() {
            "No matching summaries found.".to_string()
        } else {
            blocks.join("\n\n")
        }
    }
}

impl RenderText for SymbolSourcesResult {
    fn render_text(&self, options: RenderOptions) -> String {
        let mut blocks: Vec<String> = self
            .sources
            .iter()
            .map(|source| source.render_text(options))
            .collect();
        if !self.not_found.is_empty() {
            blocks.push(render_not_found(&self.not_found));
        }
        if !self.ambiguous.is_empty() {
            blocks.push(render_ambiguous_symbols_table(&self.ambiguous));
        }
        if !self.ambiguous_paths.is_empty() {
            blocks.push(render_ambiguous_paths(&self.ambiguous_paths));
        }
        if blocks.is_empty() {
            "No matching sources found.".to_string()
        } else {
            blocks.join("\n\n")
        }
    }
}

impl RenderText for SkimFilesResult {
    fn render_text(&self, _options: RenderOptions) -> String {
        let blocks: Vec<String> = self.files.iter().map(render_skim_file).collect();
        if blocks.is_empty() {
            return "No matching files found.".to_string();
        }
        let mut text = blocks.join("\n\n");
        if self.truncated {
            text.push_str(&format!(
                "\n\nResults truncated: showing {} of {} files selected by recent activity when available. Results are displayed alphabetically.",
                self.files.len(),
                self.total_files
            ));
        }
        if !self.ambiguous_paths.is_empty() {
            text.push_str("\n\n");
            text.push_str(&render_ambiguous_paths(&self.ambiguous_paths));
        }
        text
    }
}

impl RenderText for MostRelevantFilesResult {
    fn render_text(&self, _options: RenderOptions) -> String {
        if self.files.is_empty()
            && self.not_found.is_empty()
            && self.duplicates.is_empty()
            && self.ambiguous_paths.is_empty()
        {
            return "No related files found.".to_string();
        }

        let mut lines = self.files.clone();
        if !self.not_found.is_empty() {
            lines.push(format!("Not found: {}", self.not_found.join(", ")));
        }
        if !self.duplicates.is_empty() {
            lines.push(format!("Duplicate seeds: {}", self.duplicates.join(", ")));
        }
        if !self.ambiguous_paths.is_empty() {
            lines.push(String::new());
            lines.push(render_ambiguous_paths(&self.ambiguous_paths));
        }
        lines.join("\n")
    }
}

fn render_search_symbol_file(file: &SearchSymbolsFile, options: RenderOptions) -> String {
    let mut lines = vec![
        format!(
            "## {} ({} lines)",
            escape_markdown_heading(&file.path),
            file.loc
        ),
        String::new(),
    ];
    append_symbol_hits(&mut lines, "Class", "Classes", &file.classes, options);
    append_symbol_hits(
        &mut lines,
        "Function",
        "Functions",
        &file.functions,
        options,
    );
    append_symbol_hits(&mut lines, "Field", "Fields", &file.fields, options);
    append_symbol_hits(&mut lines, "Module", "Modules", &file.modules, options);
    append_symbol_hits(&mut lines, "Macro", "Macros", &file.macros, options);
    lines.join("\n")
}

fn append_symbol_hits(
    lines: &mut Vec<String>,
    label: &str,
    heading: &str,
    hits: &[SearchSymbolHit],
    options: RenderOptions,
) {
    if hits.is_empty() {
        return;
    }
    if lines.last().is_some_and(|line| !line.is_empty()) {
        lines.push(String::new());
    }
    lines.push(format!("### {heading}"));
    lines.push(String::new());
    if options.render_line_numbers {
        lines.push("| Kind | Line | Symbol | Signature |".to_string());
        lines.push("| --- | ---: | --- | --- |".to_string());
        lines.extend(hits.iter().map(|hit| {
            format!(
                "| {} | {} | {} | {} |",
                label,
                render_symbol_line(hit.line),
                escape_markdown_table_cell(&hit.symbol),
                escape_markdown_table_cell(&hit.signature)
            )
        }));
    } else {
        lines.push("| Kind | Symbol | Signature |".to_string());
        lines.push("| --- | --- | --- |".to_string());
        lines.extend(hits.iter().map(|hit| {
            format!(
                "| {} | {} | {} |",
                label,
                escape_markdown_table_cell(&hit.symbol),
                escape_markdown_table_cell(&hit.signature)
            )
        }));
    }
}

fn render_summary_block(block: &SummaryBlock, options: RenderOptions) -> String {
    let mut chunks = vec![block.path.clone()];
    if let Some(fallback_reason) = &block.fallback_reason {
        chunks.push(format!("Note: {fallback_reason}"));
    }
    chunks.extend(
        block
            .elements
            .iter()
            .filter(|element| !element.text.is_empty())
            .map(|element| element.render_text(options)),
    );
    chunks.join("\n").trim().to_string()
}

fn render_ambiguous_symbol(symbol: &AmbiguousSymbol) -> String {
    format!("Ambiguous {}: {}", symbol.target, symbol.matches.join(", "))
}

fn render_ambiguous_paths(paths: &[AmbiguousPathInput]) -> String {
    let mut lines = vec!["Ambiguous paths:".to_string()];
    lines.extend(
        paths
            .iter()
            .map(|item| format!("- {} -> {}", item.input, item.matches.join(", "))),
    );
    lines.join("\n")
}

fn render_skim_file(file: &SkimFile) -> String {
    let mut lines = vec![format!("{} ({} lines)", file.path, file.loc)];
    lines.extend(file.lines.iter().cloned());
    lines.join("\n")
}

impl SearchSymbolsFile {
    fn render_text(&self, options: RenderOptions) -> String {
        render_search_symbol_file(self, options)
    }
}

impl SymbolLocation {
    fn render_text(&self, options: RenderOptions) -> String {
        if options.render_line_numbers {
            return format!(
                "{}: {}:{}..{}",
                self.symbol, self.path, self.start_line, self.end_line
            );
        }
        format!("{}: {}", self.symbol, self.path)
    }
}

impl SymbolAncestors {
    fn render_text(&self) -> String {
        let mut lines = vec![
            format!("## {}", escape_markdown_heading(&self.symbol)),
            String::new(),
        ];
        if self.ancestors.is_empty() {
            lines.push("No ancestors.".to_string());
        } else {
            lines.extend(
                self.ancestors
                    .iter()
                    .map(|ancestor| format!("- {}", escape_markdown_inline_code(ancestor))),
            );
        }
        lines.join("\n")
    }
}

impl SummaryBlock {
    fn render_text(&self, options: RenderOptions) -> String {
        render_summary_block(self, options)
    }
}

impl SummaryElement {
    fn render_text(&self, options: RenderOptions) -> String {
        let safe_text = model_context::cap_lines(&self.text);
        if self.presentation.as_deref() == Some("sampled_excerpt") {
            return safe_text;
        }
        let lines: Vec<&str> = safe_text.lines().collect();
        if lines.is_empty() {
            return String::new();
        }
        if !options.render_line_numbers {
            return safe_text;
        }
        let prefix = if self.start_line == self.end_line {
            format!("{}: {}", self.start_line, lines[0])
        } else {
            format!("{}..{}: {}", self.start_line, self.end_line, lines[0])
        };
        std::iter::once(prefix)
            .chain(lines.into_iter().skip(1).map(str::to_string))
            .collect::<Vec<String>>()
            .join("\n")
    }
}

impl SourceBlock {
    fn render_text(&self, options: RenderOptions) -> String {
        if self.presentation.as_deref() == Some("file_listing") {
            return format!(
                "## {}\n\n- Defining file: {}\n- Note: {}",
                escape_markdown_heading(&self.label),
                self.path,
                self.text
            );
        }
        let mut header = if options.render_line_numbers {
            format!(
                "## {}\n\n- Location: {}:{}..{}",
                escape_markdown_heading(&self.label),
                self.path,
                self.start_line,
                self.end_line
            )
        } else {
            format!(
                "## {}\n\n- Path: {}",
                escape_markdown_heading(&self.label),
                self.path
            )
        };
        if let Some(note) = &self.note {
            header.push_str(&format!("\n- Note: {note}"));
        }
        // A sampled excerpt is head+tail with an OMITTED delimiter in between, so
        // sequential numbering would fabricate line numbers after the gap.
        let body = if self.presentation.as_deref() == Some("sampled_excerpt") {
            model_context::cap_lines(&self.text)
        } else {
            render_source_body(&self.text, self.start_line, options)
        };
        format!("{header}\n\n{}", fenced_code_block(&body))
    }
}

fn render_source_body(text: &str, start_line: usize, options: RenderOptions) -> String {
    let safe_text = model_context::cap_lines(text);
    if !options.render_line_numbers {
        return safe_text;
    }
    safe_text
        .lines()
        .enumerate()
        .map(|(idx, line)| format!("{}: {}", start_line + idx, line))
        .collect::<Vec<String>>()
        .join("\n")
}

fn render_symbol_line(line: usize) -> String {
    if line > 0 {
        line.to_string()
    } else {
        String::new()
    }
}

fn render_inline_list<'a>(items: impl Iterator<Item = &'a str>) -> String {
    let rendered: Vec<_> = items.map(escape_markdown_inline_code).collect();
    if rendered.is_empty() {
        "`<none>`".to_string()
    } else {
        rendered.join(", ")
    }
}

fn render_not_found(items: &[String]) -> String {
    let mut lines = vec!["## Not found".to_string(), String::new()];
    lines.extend(
        items
            .iter()
            .map(|item| format!("- {}", escape_markdown_inline_code(item))),
    );
    lines.join("\n")
}

fn render_ambiguous_symbols_table(symbols: &[AmbiguousSymbol]) -> String {
    let mut lines = vec![
        "## Ambiguous symbols".to_string(),
        String::new(),
        "| Target | Matches |".to_string(),
        "| --- | --- |".to_string(),
    ];
    lines.extend(symbols.iter().map(|symbol| {
        format!(
            "| {} | {} |",
            escape_markdown_table_cell(&symbol.target),
            escape_markdown_table_cell(&symbol.matches.join(", "))
        )
    }));
    lines.join("\n")
}

fn fenced_code_block(text: &str) -> String {
    let fence = code_fence_for(text);
    format!("{fence}text\n{text}\n{fence}")
}

fn code_fence_for(text: &str) -> String {
    let mut longest_run = 0;
    let mut current_run = 0;
    for ch in text.chars() {
        if ch == '`' {
            current_run += 1;
            longest_run = longest_run.max(current_run);
        } else {
            current_run = 0;
        }
    }
    "`".repeat(longest_run.max(2) + 1)
}

fn escape_markdown_inline_code(text: &str) -> String {
    format!("`{}`", text.replace('`', "\\`"))
}

fn escape_markdown_heading(text: &str) -> String {
    text.replace(['\n', '\r'], " ")
}

fn escape_markdown_table_cell(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "<br>")
        .replace('\r', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_symbols_renders_markdown_with_structured_fields() {
        let result = SearchSymbolsResult {
            patterns: vec!["Foo".to_string()],
            truncated: true,
            total_files: 3,
            files: vec![SearchSymbolsFile {
                path: "src/foo.rs".to_string(),
                loc: 42,
                classes: vec![SearchSymbolHit {
                    symbol: "crate::foo::Foo".to_string(),
                    signature: "struct Foo".to_string(),
                    line: 7,
                }],
                functions: vec![SearchSymbolHit {
                    symbol: "crate::foo::Foo::bar".to_string(),
                    signature: "fn bar() -> A | B".to_string(),
                    line: 12,
                }],
                fields: Vec::new(),
                modules: Vec::new(),
                macros: Vec::new(),
            }],
        };

        let text = result.render_text(RenderOptions::default());

        assert!(text.starts_with("# Symbol search results"), "{text}");
        assert!(text.contains("- Patterns: `Foo`"), "{text}");
        assert!(text.contains("- Files: 1 of 3"), "{text}");
        assert!(text.contains("- Truncated: yes;"), "{text}");
        assert!(text.contains("ranked by symbol relevance"), "{text}");
        assert!(text.contains("## src/foo.rs (42 lines)"), "{text}");
        assert!(
            text.contains("| Kind | Line | Symbol | Signature |"),
            "{text}"
        );
        assert!(
            text.contains("| Class | 7 | crate::foo::Foo | struct Foo |"),
            "{text}"
        );
        assert!(
            text.contains("| Function | 12 | crate::foo::Foo::bar | fn bar() -> A \\| B |"),
            "{text}"
        );
    }

    #[test]
    fn symbol_sources_renders_markdown_with_ranges_and_auxiliary_data() {
        let result = SymbolSourcesResult {
            sources: vec![SourceBlock {
                label: "crate::foo::Foo::bar".to_string(),
                path: "src/foo.rs".to_string(),
                start_line: 12,
                end_line: 14,
                text: "fn bar() {\n    println!(\"hi\");\n}".to_string(),
                presentation: None,
                note: None,
            }],
            not_found: vec!["Missing".to_string()],
            ambiguous: vec![AmbiguousSymbol {
                target: "Foo".to_string(),
                matches: vec!["crate::foo::Foo".to_string(), "other::Foo".to_string()],
            }],
            ambiguous_paths: vec![AmbiguousPathInput {
                input: "Foo.java".to_string(),
                matches: vec!["app/Foo.java".to_string(), "lib/Foo.java".to_string()],
            }],
        };

        let text = result.render_text(RenderOptions::default());

        assert!(text.contains("## crate::foo::Foo::bar"), "{text}");
        assert!(text.contains("- Location: src/foo.rs:12..14"), "{text}");
        assert!(text.contains("```text\n12: fn bar() {"), "{text}");
        assert!(text.contains("13:     println!(\"hi\");"), "{text}");
        assert!(text.contains("## Not found\n\n- `Missing`"), "{text}");
        assert!(text.contains("Ambiguous paths:"), "{text}");
        assert!(
            text.contains("- Foo.java -> app/Foo.java, lib/Foo.java"),
            "{text}"
        );
        assert!(text.contains("## Ambiguous symbols"), "{text}");
        assert!(text.contains("| Target | Matches |"), "{text}");
        assert!(
            text.contains("| Foo | crate::foo::Foo, other::Foo |"),
            "{text}"
        );
    }

    #[test]
    fn summary_elements_truncate_very_long_lines_when_rendered() {
        let long = "x".repeat(2050);
        let element = SummaryElement {
            path: "a.rs".to_string(),
            symbol: "a".to_string(),
            kind: "excerpt".to_string(),
            start_line: 1,
            end_line: 1,
            text: long,
            parent_symbol: None,
            presentation: None,
        };

        let rendered = element.render_text(RenderOptions::default());
        assert!(rendered.contains("[TRUNCATED at 2048 chars]"), "{rendered}");
    }

    #[test]
    fn sampled_excerpt_rendering_preserves_omitted_delimiter_without_fake_ranges() {
        let element = SummaryElement {
            path: "a.rs".to_string(),
            symbol: "a.rs".to_string(),
            kind: "excerpt".to_string(),
            start_line: 1,
            end_line: 60,
            text: "// line 1\n\n----- OMITTED 10 LINES -----\n\n// line 60".to_string(),
            parent_symbol: None,
            presentation: Some("sampled_excerpt".to_string()),
        };

        let rendered = element.render_text(RenderOptions::default());
        assert_eq!(
            "// line 1\n\n----- OMITTED 10 LINES -----\n\n// line 60",
            rendered
        );
    }
}
