use crate::searchtools::{
    AmbiguousSymbol, MostRelevantFilesResult, SearchSymbolHit, SearchSymbolsFile,
    SearchSymbolsResult, SkimFile, SkimFilesResult, SourceBlock, SummaryBlock, SummaryElement,
    SummaryResult, SymbolLocation, SymbolLocationsResult, SymbolSourcesResult,
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
                "- Truncated: yes; files selected by recent activity when available and displayed alphabetically."
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

impl RenderText for SummaryResult {
    fn render_text(&self, options: RenderOptions) -> String {
        let mut blocks: Vec<String> = self
            .summaries
            .iter()
            .map(|summary| summary.render_text(options))
            .collect();
        if let Some(directory_symbols) = &self.directory_symbols {
            blocks.push(directory_symbols.render_text(options));
        }
        if !self.not_found.is_empty() {
            blocks.push(format!("Not found: {}", self.not_found.join(", ")));
        }
        blocks.extend(self.ambiguous.iter().map(render_ambiguous_symbol));
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
        text
    }
}

impl RenderText for MostRelevantFilesResult {
    fn render_text(&self, _options: RenderOptions) -> String {
        if self.files.is_empty() && self.not_found.is_empty() {
            return "No related files found.".to_string();
        }

        let mut lines = self.files.clone();
        if !self.not_found.is_empty() {
            lines.push(format!("Not found: {}", self.not_found.join(", ")));
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
    if !block.preamble.is_empty() {
        chunks.push(block.preamble.clone());
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

impl SummaryBlock {
    fn render_text(&self, options: RenderOptions) -> String {
        render_summary_block(self, options)
    }
}

impl SummaryElement {
    fn render_text(&self, options: RenderOptions) -> String {
        let lines: Vec<&str> = self.text.lines().collect();
        if lines.is_empty() {
            return String::new();
        }
        if !options.render_line_numbers {
            return self.text.clone();
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
        let header = if options.render_line_numbers {
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
        format!(
            "{header}\n\n{}",
            fenced_code_block(&render_source_body(&self.text, self.start_line, options))
        )
    }
}

fn render_source_body(text: &str, start_line: usize, options: RenderOptions) -> String {
    if !options.render_line_numbers {
        return text.to_string();
    }
    text.lines()
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
            }],
        };

        let text = result.render_text(RenderOptions::default());

        assert!(text.starts_with("# Symbol search results"), "{text}");
        assert!(text.contains("- Patterns: `Foo`"), "{text}");
        assert!(text.contains("- Files: 1 of 3"), "{text}");
        assert!(text.contains("- Truncated: yes;"), "{text}");
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
            }],
            not_found: vec!["Missing".to_string()],
            ambiguous: vec![AmbiguousSymbol {
                target: "Foo".to_string(),
                matches: vec!["crate::foo::Foo".to_string(), "other::Foo".to_string()],
            }],
        };

        let text = result.render_text(RenderOptions::default());

        assert!(text.contains("## crate::foo::Foo::bar"), "{text}");
        assert!(text.contains("- Location: src/foo.rs:12..14"), "{text}");
        assert!(text.contains("```text\n12: fn bar() {"), "{text}");
        assert!(text.contains("13:     println!(\"hi\");"), "{text}");
        assert!(text.contains("## Not found\n\n- `Missing`"), "{text}");
        assert!(text.contains("## Ambiguous symbols"), "{text}");
        assert!(text.contains("| Target | Matches |"), "{text}");
        assert!(
            text.contains("| Foo | crate::foo::Foo, other::Foo |"),
            "{text}"
        );
    }
}
