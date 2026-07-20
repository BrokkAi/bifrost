use crate::model_context;
use crate::path_utils::AmbiguousPathInput;
use crate::searchtools::{
    AmbiguousSymbol, ContainerKind, ContainerListing, ContainerListingEntry,
    MostRelevantFilesResult, NotFoundInput, ScanUsagesEntry, ScanUsagesInput, ScanUsagesResult,
    ScanUsagesStatus, SearchSymbolHit, SearchSymbolsFile, SearchSymbolsResult, SkimFile,
    SkimFilesResult, SourceBlock, SummaryBlock, SummaryElement, SummaryResult, SymbolAncestors,
    SymbolAncestorsResult, SymbolLocation, SymbolLocationsResult, SymbolSourcesResult,
    UsageFileGroup, UsageGraphResult, UsageLocation, scan_usages_target_label,
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
            return match self.note.as_deref() {
                Some(note) => format!("No matching symbols found.\n\nNote: {note}"),
                None => "No matching symbols found.".to_string(),
            };
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
        if let Some(note) = self.note.as_deref() {
            lines.push(format!("- Note: {note}"));
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
            lines.push(format!(
                "Not found: {}",
                render_not_found_inline(&self.not_found)
            ));
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
        blocks.extend(
            self.listings
                .iter()
                .map(|listing| render_container_listing(listing, options)),
        );
        if !self.not_found.is_empty() {
            blocks.push(format!(
                "Not found: {}",
                render_not_found_inline(&self.not_found)
            ));
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

fn render_container_listing(listing: &ContainerListing, options: RenderOptions) -> String {
    let label = match listing.kind {
        ContainerKind::Directory => "Directory",
        ContainerKind::Package => "Package",
    };
    let languages = if listing.languages.is_empty() {
        String::new()
    } else {
        format!(" ({})", listing.languages.join(", "))
    };
    let mut lines = vec![format!("{label} {}{languages}", listing.target)];
    lines.extend(
        listing
            .entries
            .iter()
            .map(|entry| render_container_listing_entry(entry, options)),
    );
    if listing.entries.is_empty() {
        lines.push("(empty)".to_string());
    }
    if listing.truncated {
        lines.push(format!(
            "[showing {} of {} entries]",
            listing.entries.len(),
            listing.total_entries
        ));
    }
    lines.join("\n")
}

fn render_container_listing_entry(entry: &ContainerListingEntry, options: RenderOptions) -> String {
    match entry {
        ContainerListingEntry::Directory { path, .. } => format!("[directory] {path}"),
        ContainerListingEntry::File { path, .. } => format!("[file] {path}"),
        ContainerListingEntry::Package {
            qualified_name,
            languages,
            ..
        } => {
            let languages = if languages.is_empty() {
                String::new()
            } else {
                format!("; {}", languages.join(", "))
            };
            format!("[package{languages}] {qualified_name}")
        }
        ContainerListingEntry::Type {
            symbol,
            language,
            path,
            start_line,
            end_line,
            ..
        } => {
            let location = if options.render_line_numbers {
                format!("{path}:{start_line}..{end_line}")
            } else {
                path.clone()
            };
            format!("[type; {language}] {symbol}: {location}")
        }
    }
}

impl RenderText for SymbolSourcesResult {
    fn render_text(&self, options: RenderOptions) -> String {
        let mut blocks = Vec::new();
        if !self.sources.is_empty()
            && (!self.not_found.is_empty()
                || !self.ambiguous.is_empty()
                || !self.ambiguous_paths.is_empty())
        {
            blocks.push(render_symbol_sources_mixed_status(self));
        }
        if !self.not_found.is_empty() {
            blocks.push(render_not_found(&self.not_found));
        }
        if !self.ambiguous.is_empty() {
            blocks.push(render_ambiguous_symbols_table(&self.ambiguous));
        }
        if !self.ambiguous_paths.is_empty() {
            blocks.push(render_ambiguous_paths(&self.ambiguous_paths));
        }
        blocks.extend(
            self.sources
                .iter()
                .map(|source| source.render_text(options)),
        );
        if blocks.is_empty() {
            "No matching sources found.".to_string()
        } else {
            blocks.join("\n\n")
        }
    }
}

fn render_symbol_sources_mixed_status(result: &SymbolSourcesResult) -> String {
    let unresolved = result
        .not_found
        .iter()
        .map(|item| item.input.as_str())
        .chain(result.ambiguous.iter().map(|item| item.target.as_str()))
        .chain(
            result
                .ambiguous_paths
                .iter()
                .map(|item| item.input.as_str()),
        );
    format!(
        "Some requested symbols were unresolved: {} (see recovery guidance below)",
        render_inline_list(unresolved)
    )
}

impl RenderText for SkimFilesResult {
    fn render_text(&self, _options: RenderOptions) -> String {
        let blocks: Vec<String> = self.files.iter().map(render_skim_file).collect();
        if blocks.is_empty() {
            return match self.note.as_deref() {
                Some(note) => format!("No matching files found.\n\nNote: {note}"),
                None => "No matching files found.".to_string(),
            };
        }
        let mut text = blocks.join("\n\n");
        if self.truncated {
            text.push_str(&format!(
                "\n\nResults truncated: showing {} of {} files selected by recent activity when available. Results are displayed alphabetically.",
                self.files.len(),
                self.total_files
            ));
        }
        if let Some(note) = self.note.as_deref() {
            text.push_str("\n\nNote: ");
            text.push_str(note);
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
            lines.push(format!(
                "Not found: {}",
                render_not_found_inline(&self.not_found)
            ));
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

impl RenderText for ScanUsagesResult {
    fn render_text(&self, _options: RenderOptions) -> String {
        if self.results.is_empty() {
            return format!("No {} requests were provided.", self.surface.tool_name());
        }
        let mut sections = Vec::new();
        if self.results.iter().any(|entry| {
            matches!(
                entry.status,
                ScanUsagesStatus::VerifiedAbsent | ScanUsagesStatus::UnverifiedAbsent
            )
        }) {
            let truncated_absence = self.results.iter().any(|entry| {
                entry.status == ScanUsagesStatus::UnverifiedAbsent
                    && entry.absence_caveats.iter().any(|caveat| {
                        *caveat
                            == crate::searchtools::ScanUsagesAbsenceCaveat::CandidateFilesTruncated
                    })
            });
            sections.push(render_scan_usages_scope(&self.scope, truncated_absence));
        }
        if self.results.len() > 1 {
            sections.push(render_scan_usages_summary_banner(self));
        }
        sections.extend(self.results.iter().map(render_scan_usages_entry_text));
        sections.join("\n\n")
    }
}

impl RenderText for UsageGraphResult {
    fn render_text(&self, options: RenderOptions) -> String {
        let mut lines = vec![format!(
            "{} nodes, {} edges",
            self.nodes.len(),
            self.edges.len()
        )];
        if !self.truncated_symbols.is_empty() {
            lines.push(format!(
                "{} truncated symbol(s); re-call {} with narrower paths for call-site detail:",
                self.truncated_symbols.len(),
                if options.render_line_numbers {
                    "scan_usages_by_location"
                } else {
                    "scan_usages_by_reference"
                }
            ));
            lines.extend(self.truncated_symbols.iter().map(|symbol| {
                format!(
                    "- {} ({}): {} callsites exceeded limit {}",
                    symbol.fqn, symbol.language, symbol.total_callsites, symbol.limit
                )
            }));
        }
        lines.join("\n")
    }
}

fn render_scan_usages_entry_text(entry: &ScanUsagesEntry) -> String {
    let label = render_scan_usages_input(&entry.input);
    let mut lines = vec![format!("{}: {}", label, entry.status.as_str())];
    if !entry.complete {
        lines.push("  note: incomplete result; narrow paths or use a more specific selector for exhaustive detail.".to_string());
    }
    if let Some(message) = &entry.message {
        lines.push(format!("  message: {message}"));
    }
    if let (Some(fq_name), Some(path), Some(line)) = (
        entry.fq_name.as_ref(),
        entry.definition_path.as_ref(),
        entry.definition_line,
    ) {
        lines.push(format!("  resolved: {fq_name} ({path}:{line})"));
    }
    for note in &entry.notes {
        lines.push(format!("  note: {note}"));
    }
    if let Some(total_hits) = entry.total_hits {
        lines.push(format!("  proven usage(s): {total_hits}"));
    }
    if let Some(unproven_hits) = entry.unproven_hits
        && unproven_hits > 0
    {
        lines.push(format!("  unproven match(es): {unproven_hits}"));
    }
    if !entry.absence_caveats.is_empty() {
        let caveats = entry
            .absence_caveats
            .iter()
            .map(|caveat| caveat.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("  absence caveat(s): {caveats}"));
    }
    if let Some(count) = entry.definition_sites_excluded {
        lines.push(format!(
            "  note: {count} definition-site hit(s) were excluded from external usages."
        ));
    }
    if let Some(count) = entry.files_truncated {
        lines.push(format!(
            "  note: {count} file group(s) omitted from rendered output; re-call with narrower paths for detail."
        ));
    }
    if !entry.candidate_targets.is_empty() {
        lines.push(format!(
            "  candidate target(s): {}",
            entry.candidate_targets.join(", ")
        ));
    }
    if let Some(total_callsites) = entry.total_callsites {
        let limit = entry
            .limit
            .map(|limit| limit.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        lines.push(format!(
            "  callsite cap: {total_callsites} callsites exceeded limit {limit}"
        ));
    }
    if let Some(sample) = &entry.candidate_files_sample {
        if !sample.scanned.is_empty() {
            lines.push(format!("  scanned: {}", sample.scanned.join(", ")));
        }
        if sample.omitted_count > 0 {
            lines.push(format!(
                "  omitted {} file(s): {}",
                sample.omitted_count,
                sample.omitted.join(", ")
            ));
        }
    }
    lines.extend(render_usage_file_groups_text(&entry.files, false));
    if !entry.unproven_files.is_empty() {
        lines.push("unproven matches:".to_string());
        lines.extend(render_usage_file_groups_text(&entry.unproven_files, true));
    }
    lines.join("\n")
}

fn render_scan_usages_scope(
    scope: &crate::searchtools::ScanUsagesScope,
    truncated_absence: bool,
) -> String {
    let source_scope = if scope.include_tests {
        "analyzed source including test files"
    } else {
        "production analyzed source only (include_tests=false)"
    };
    let path_scope = if scope.whole_workspace {
        "whole analyzed workspace".to_string()
    } else {
        let mut rendered = format!("effective paths: {}", scope.paths.join(", "));
        if let Some(omitted) = scope.paths_omitted {
            rendered.push_str(&format!(" (+{omitted} more)"));
        }
        rendered
    };
    let mut lines = vec![format!("Scope: {source_scope}; {path_scope}.")];
    if let Some(ignored) = scope.ignored_paths {
        let label = if ignored == 1 {
            "filter was ignored because it was"
        } else {
            "filters were ignored because they were"
        };
        lines.push(format!(
            "Note: {ignored} supplied path {label} blank or invalid."
        ));
    }
    if !scope.include_tests {
        lines.push(
            "Next step for absent results: retry with include_tests=true to include test usages."
                .to_string(),
        );
    }
    if !scope.whole_workspace && !truncated_absence {
        lines.push(
            "Next step for a broader absence check: drop or widen paths to search the whole analyzed workspace."
                .to_string(),
        );
    }
    lines.join("\n")
}

fn render_scan_usages_summary_banner(result: &ScanUsagesResult) -> String {
    let summary = &result.summary;
    let mut parts = Vec::new();
    push_scan_usages_status_count(&mut parts, summary.found, ScanUsagesStatus::Found);
    push_scan_usages_status_count(
        &mut parts,
        summary.verified_absent,
        ScanUsagesStatus::VerifiedAbsent,
    );
    push_scan_usages_status_count(
        &mut parts,
        summary.unverified_absent,
        ScanUsagesStatus::UnverifiedAbsent,
    );
    push_scan_usages_status_count(&mut parts, summary.not_found, ScanUsagesStatus::NotFound);
    push_scan_usages_status_count(&mut parts, summary.ambiguous, ScanUsagesStatus::Ambiguous);
    push_scan_usages_status_count(&mut parts, summary.failure, ScanUsagesStatus::Failure);
    push_scan_usages_status_count(
        &mut parts,
        summary.too_many_callsites,
        ScanUsagesStatus::TooManyCallsites,
    );
    let request_label = if summary.requested == 1 {
        "request"
    } else {
        "requests"
    };
    let mut lines = vec![format!(
        "{} {} {request_label}: {}; see per-request sections.",
        summary.requested,
        result.surface.tool_name(),
        parts.join("; ")
    )];

    let zero_members = result
        .results
        .iter()
        .filter(|entry| {
            matches!(
                entry.status,
                ScanUsagesStatus::VerifiedAbsent | ScanUsagesStatus::UnverifiedAbsent
            )
        })
        .map(|entry| {
            format!(
                "{} ({})",
                render_scan_usages_input(&entry.input),
                entry.status.as_str()
            )
        })
        .collect::<Vec<_>>();
    if !zero_members.is_empty() {
        lines.push(format!("No proven usages: {}.", zero_members.join(", ")));
    }

    let not_found = render_scan_usages_members_with_status(result, ScanUsagesStatus::NotFound);
    if !not_found.is_empty() {
        lines.push(format!("Not found: {}.", not_found.join(", ")));
    }

    let failures = render_scan_usages_members_with_status(result, ScanUsagesStatus::Failure);
    if !failures.is_empty() {
        lines.push(format!("Failures: {}.", failures.join(", ")));
    }

    lines.join("\n")
}

fn push_scan_usages_status_count(parts: &mut Vec<String>, count: usize, status: ScanUsagesStatus) {
    if count > 0 {
        parts.push(format!("{count} {}", status.as_str()));
    }
}

fn render_scan_usages_members_with_status(
    result: &ScanUsagesResult,
    status: ScanUsagesStatus,
) -> Vec<String> {
    result
        .results
        .iter()
        .filter(|entry| entry.status == status)
        .map(|entry| render_scan_usages_input(&entry.input))
        .collect()
}

fn render_scan_usages_input(input: &ScanUsagesInput) -> String {
    match input {
        ScanUsagesInput::Symbol(symbol) => symbol.clone(),
        ScanUsagesInput::Target(target) => scan_usages_target_label(target),
    }
}

fn render_usage_file_groups_text(files: &[UsageFileGroup], indent: bool) -> Vec<String> {
    let mut lines = Vec::new();
    let prefix = if indent { "  " } else { "" };
    for file in files {
        lines.push(format!("{prefix}{}", file.path));
        if file.hits.is_empty() {
            if let Some(hit_count) = file.hit_count {
                lines.push(format!("{prefix}  {hit_count} hit(s)"));
            }
            continue;
        }
        for hit in &file.hits {
            lines.extend(render_usage_location_text(hit, prefix));
        }
    }
    lines
}

fn render_usage_location_text(hit: &UsageLocation, prefix: &str) -> Vec<String> {
    let location = hit
        .line_range
        .as_ref()
        .cloned()
        .unwrap_or_else(|| hit.line.to_string());
    let mut line = format!("{prefix}  line {location}");
    if !hit.enclosing.is_empty() {
        line.push_str(&format!(" in {}", hit.enclosing));
    }
    if let Some(hit_count) = hit.hit_count {
        line.push_str(&format!(" ({hit_count} hit(s))"));
    }
    if let Some(kind) = &hit.kind {
        line.push_str(&format!(" [{kind}]"));
    }
    if hit.confidence < 1.0 {
        line.push_str(&format!(" [confidence {:.2}]", hit.confidence));
    }
    let mut lines = vec![line];
    if let Some(snippet) = &hit.snippet {
        lines.extend(
            model_context::cap_lines(snippet)
                .lines()
                .map(|snippet_line| format!("{prefix}    {snippet_line}")),
        );
    }
    lines
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
    let mut lines = vec![format!(
        "Ambiguous {}: {}",
        symbol.target,
        symbol.matches.join(", ")
    )];
    if let Some(note) = &symbol.note {
        lines.push(format!("Note: {note}"));
    }
    lines.join("\n")
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

fn render_not_found_inline(items: &[NotFoundInput]) -> String {
    items
        .iter()
        .map(render_not_found_item)
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_not_found_item(item: &NotFoundInput) -> String {
    let input = escape_markdown_inline_code(&item.input);
    match &item.note {
        Some(note) => format!("{input}: {note}"),
        None => input,
    }
}

fn render_not_found(items: &[NotFoundInput]) -> String {
    let mut lines = vec!["## Not found".to_string(), String::new()];
    lines.extend(
        items
            .iter()
            .map(|item| format!("- {}", render_not_found_item(item))),
    );
    lines.join("\n")
}

fn render_ambiguous_symbols_table(symbols: &[AmbiguousSymbol]) -> String {
    let mut lines = vec![
        "## Ambiguous symbols".to_string(),
        String::new(),
        "| Target | Matches | Note |".to_string(),
        "| --- | --- | --- |".to_string(),
    ];
    lines.extend(symbols.iter().map(|symbol| {
        format!(
            "| {} | {} | {} |",
            escape_markdown_table_cell(&symbol.target),
            escape_markdown_table_cell(&symbol.matches.join(", ")),
            escape_markdown_table_cell(symbol.note.as_deref().unwrap_or(""))
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
            note: Some(
                "Showing 1 of 3 matching files. Raise `limit` or use a more specific identifier, qualified, or regex-like pattern to see the rest."
                    .to_string(),
            ),
        };

        let text = result.render_text(RenderOptions::default());

        assert!(text.starts_with("# Symbol search results"), "{text}");
        assert!(text.contains("- Patterns: `Foo`"), "{text}");
        assert!(text.contains("- Files: 1 of 3"), "{text}");
        assert!(text.contains("- Truncated: yes;"), "{text}");
        assert!(
            text.contains("- Note: Showing 1 of 3 matching files. Raise `limit` or use a more specific identifier, qualified, or regex-like pattern to see the rest."),
            "{text}"
        );
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
            not_found: vec![NotFoundInput {
                input: "Missing".to_string(),
                note: Some(
                    "no symbol matched; try search_symbols with a substring or regex pattern"
                        .to_string(),
                ),
            }],
            ambiguous: vec![AmbiguousSymbol {
                target: "Foo".to_string(),
                matches: vec!["crate::foo::Foo".to_string(), "other::Foo".to_string()],
                note: Some(
                    "Ambiguous; re-call with one selector from `matches` (e.g. crate::foo::Foo)."
                        .to_string(),
                ),
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
        assert!(
            text.contains("## Not found\n\n- `Missing`: no symbol matched; try search_symbols with a substring or regex pattern"),
            "{text}"
        );
        assert!(text.contains("Ambiguous paths:"), "{text}");
        assert!(
            text.contains("- Foo.java -> app/Foo.java, lib/Foo.java"),
            "{text}"
        );
        assert!(text.contains("## Ambiguous symbols"), "{text}");
        assert!(text.contains("| Target | Matches | Note |"), "{text}");
        assert!(
            text.contains("| Foo | crate::foo::Foo, other::Foo | Ambiguous; re-call with one selector from `matches` (e.g. crate::foo::Foo). |"),
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

    #[test]
    fn truncated_absence_scope_does_not_recommend_widening_paths() {
        let scope = crate::searchtools::ScanUsagesScope {
            include_tests: true,
            whole_workspace: false,
            paths: vec!["src/**/*.rs".to_string()],
            paths_omitted: None,
            ignored_paths: None,
        };

        let ordinary = render_scan_usages_scope(&scope, false);
        assert!(ordinary.contains("drop or widen paths"), "{ordinary}");

        let truncated = render_scan_usages_scope(&scope, true);
        assert!(!truncated.contains("drop or widen paths"), "{truncated}");
    }
}
