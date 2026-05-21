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
            blocks.push(format!("Not found: {}", self.not_found.join(", ")));
        }
        blocks.extend(self.ambiguous.iter().map(render_ambiguous_symbol));
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
    let mut lines = vec![format!("{} ({} lines)", file.path, file.loc)];
    append_symbol_hits(&mut lines, "classes", &file.classes, options);
    append_symbol_hits(&mut lines, "functions", &file.functions, options);
    append_symbol_hits(&mut lines, "fields", &file.fields, options);
    append_symbol_hits(&mut lines, "modules", &file.modules, options);
    lines.join("\n")
}

fn append_symbol_hits(
    lines: &mut Vec<String>,
    label: &str,
    hits: &[SearchSymbolHit],
    options: RenderOptions,
) {
    if hits.is_empty() {
        return;
    }
    lines.push(format!("  {label}:"));
    lines.extend(
        hits.iter()
            .map(|hit| format!("    {}", hit.render_text(options))),
    );
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

impl SearchSymbolHit {
    fn render_text(&self, options: RenderOptions) -> String {
        if options.render_line_numbers && self.line > 0 {
            return format!("{}: {}", self.line, self.signature);
        }
        self.signature.clone()
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
                "{} ({}:{}..{})",
                self.label, self.path, self.start_line, self.end_line
            )
        } else {
            format!("{} ({})", self.label, self.path)
        };
        format!(
            "{header}\n{}",
            render_source_body(&self.text, self.start_line, options)
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
