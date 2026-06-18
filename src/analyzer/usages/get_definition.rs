use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::inverted_edges::{ClassRangeIndex, first_precise};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::php_graph::{
    FileContext, php_node_text, php_qualified_candidate_text, resolve_php_constant,
    resolve_php_function, resolve_php_type,
};
use crate::analyzer::{
    AliasResolver, CodeUnit, IAnalyzer, JavaAnalyzer, Language, PhpAnalyzer, ProjectFile, Range,
    parse_php_use_aliases_from_source,
};
use crate::hash::HashMap;
use crate::path_utils::rel_path_string;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use regex::Regex;
use std::sync::LazyLock;
use tree_sitter::{Node, Parser, Tree};

#[derive(Debug, Clone)]
pub(crate) struct DefinitionLookupRequest {
    pub(crate) file: ProjectFile,
    pub(crate) line: Option<usize>,
    pub(crate) column: Option<usize>,
    pub(crate) start_byte: Option<usize>,
    pub(crate) end_byte: Option<usize>,
    pub(crate) symbol: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct DefinitionLookupOutcome {
    pub(crate) status: DefinitionLookupStatus,
    pub(crate) reference: Option<ResolvedReferenceSite>,
    pub(crate) candidates: Vec<CodeUnit>,
    pub(crate) diagnostics: Vec<DefinitionLookupDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefinitionLookupStatus {
    Resolved,
    NoDefinition,
    UnresolvableImportBoundary,
    Ambiguous,
    UnsupportedLanguage,
    InvalidLocation,
    NotFound,
}

impl DefinitionLookupStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::NoDefinition => "no_definition",
            Self::UnresolvableImportBoundary => "unresolvable_import_boundary",
            Self::Ambiguous => "ambiguous",
            Self::UnsupportedLanguage => "unsupported_language",
            Self::InvalidLocation => "invalid_location",
            Self::NotFound => "not_found",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedReferenceSite {
    pub(crate) path: String,
    pub(crate) text: String,
    pub(crate) range: Range,
}

#[derive(Debug, Clone)]
pub(crate) struct DefinitionLookupDiagnostic {
    pub(crate) kind: String,
    pub(crate) message: String,
}

pub(crate) fn resolve_definition_batch(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    include_tests: bool,
) -> Vec<DefinitionLookupOutcome> {
    let support = DefinitionSupport::build(analyzer);
    requests
        .into_iter()
        .map(|request| resolve_one(analyzer, &support, request, include_tests))
        .collect()
}

struct DefinitionSupport {
    by_fqn: HashMap<String, Vec<CodeUnit>>,
    by_identifier: HashMap<String, Vec<CodeUnit>>,
    by_file_identifier: HashMap<(ProjectFile, String), Vec<CodeUnit>>,
}

impl DefinitionSupport {
    fn build(analyzer: &dyn IAnalyzer) -> Self {
        let mut by_fqn: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        let mut by_identifier: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        let mut by_file_identifier: HashMap<(ProjectFile, String), Vec<CodeUnit>> =
            HashMap::default();
        for unit in analyzer.all_declarations() {
            by_fqn.entry(unit.fq_name()).or_default().push(unit.clone());
            by_identifier
                .entry(unit.identifier().to_string())
                .or_default()
                .push(unit.clone());
            by_file_identifier
                .entry((unit.source().clone(), unit.identifier().to_string()))
                .or_default()
                .push(unit.clone());
        }
        for units in by_fqn.values_mut() {
            sort_units(units);
        }
        for units in by_file_identifier.values_mut() {
            sort_units(units);
        }
        for units in by_identifier.values_mut() {
            sort_units(units);
        }
        Self {
            by_fqn,
            by_identifier,
            by_file_identifier,
        }
    }

    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.by_fqn.get(fqn).cloned().unwrap_or_default()
    }

    fn fqn_or_identifier(&self, file: &ProjectFile, fqn: &str) -> Vec<CodeUnit> {
        let exact = self.fqn(fqn);
        if !exact.is_empty() {
            return exact;
        }
        let ident = fqn.rsplit('.').next().unwrap_or(fqn);
        let in_file = self.file_identifier(file, ident);
        if !in_file.is_empty() {
            return in_file;
        }
        self.by_identifier.get(ident).cloned().unwrap_or_default()
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        self.by_file_identifier
            .get(&(file.clone(), ident.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    fn file_identifier_in_files(&self, files: &[ProjectFile], ident: &str) -> Vec<CodeUnit> {
        let mut out = Vec::new();
        for file in files {
            out.extend(self.file_identifier(file, ident));
        }
        sort_units(&mut out);
        out.dedup();
        out
    }

    fn fqn_candidates(&self, fqns: impl IntoIterator<Item = String>) -> Vec<CodeUnit> {
        let mut out = Vec::new();
        for fqn in fqns {
            out.extend(self.fqn(&fqn));
        }
        sort_units(&mut out);
        out.dedup();
        out
    }
}

fn resolve_one(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionSupport,
    request: DefinitionLookupRequest,
    include_tests: bool,
) -> DefinitionLookupOutcome {
    if !include_tests && analyzer.contains_tests(&request.file) {
        return diagnostic_outcome(
            DefinitionLookupStatus::NotFound,
            "excluded_test_file",
            format!(
                "`{}` is a test file and include_tests is false",
                rel_path_string(&request.file)
            ),
        );
    }

    let source = match request.file.read_to_string() {
        Ok(source) => source,
        Err(err) => {
            return diagnostic_outcome(
                DefinitionLookupStatus::NotFound,
                "file_read_failed",
                format!("failed to read `{}`: {err}", rel_path_string(&request.file)),
            );
        }
    };

    let site = match resolve_reference_site(&request, &source) {
        Ok(site) => site,
        Err(message) => {
            return diagnostic_outcome(
                DefinitionLookupStatus::InvalidLocation,
                "invalid_location",
                message,
            );
        }
    };

    let language = language_for_file(&request.file);
    let resolved = match language {
        Language::Rust => resolve_rust(analyzer, support, &request.file, &site.text),
        Language::JavaScript | Language::TypeScript => {
            resolve_js_ts(analyzer, support, &request.file, language, &site.text)
        }
        Language::Go => resolve_go(analyzer, support, &request.file, &site.text),
        Language::Java => resolve_java(analyzer, support, &request.file, &source, &site),
        Language::Php => resolve_php(analyzer, support, &request.file, &source, &site),
        Language::Cpp | Language::Python | Language::Scala | Language::CSharp | Language::None => {
            return DefinitionLookupOutcome {
                status: DefinitionLookupStatus::UnsupportedLanguage,
                reference: Some(site),
                candidates: Vec::new(),
                diagnostics: vec![DefinitionLookupDiagnostic {
                    kind: "unsupported_language".to_string(),
                    message: format!("{language:?} get_definition is not implemented yet"),
                }],
            };
        }
    };

    finish_with_symbol_filter(resolved, site, request.symbol)
}

fn finish_with_symbol_filter(
    mut outcome: DefinitionLookupOutcome,
    site: ResolvedReferenceSite,
    symbol: Option<String>,
) -> DefinitionLookupOutcome {
    if let Some(symbol) = symbol.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let before = outcome.candidates.len();
        outcome.candidates.retain(|candidate| {
            candidate.fq_name() == symbol
                || candidate.identifier() == symbol
                || candidate.short_name() == symbol
                || candidate.fq_name().ends_with(&format!(".{symbol}"))
        });
        if before > 0 && outcome.candidates.is_empty() {
            outcome.status = DefinitionLookupStatus::NoDefinition;
            outcome.diagnostics.push(DefinitionLookupDiagnostic {
                kind: "symbol_filter_mismatch".to_string(),
                message: format!(
                    "resolved reference `{}` did not match symbol disambiguator `{symbol}`",
                    site.text
                ),
            });
        }
    }

    if !outcome.candidates.is_empty() {
        outcome.status = if outcome.candidates.len() == 1 {
            DefinitionLookupStatus::Resolved
        } else {
            DefinitionLookupStatus::Ambiguous
        };
    }
    outcome.reference = Some(site);
    outcome
}

fn resolve_reference_site(
    request: &DefinitionLookupRequest,
    source: &str,
) -> Result<ResolvedReferenceSite, String> {
    let line_starts = compute_line_starts(source);
    let (selection_start, selection_end) = match (
        request.start_byte,
        request.end_byte,
        request.line,
        request.column,
    ) {
        (Some(start), Some(end), _, _) => {
            if start >= end || end > source.len() {
                return Err(format!(
                    "invalid byte range [{start}, {end}) for {} byte file",
                    source.len()
                ));
            }
            (start, end)
        }
        (Some(start), None, _, _) => {
            if start >= source.len() {
                return Err(format!(
                    "start_byte {start} is outside {} byte file",
                    source.len()
                ));
            }
            token_bounds_at(source, start)
                .ok_or_else(|| format!("no reference token at byte {start}"))?
        }
        (_, _, Some(line), column) => {
            if line == 0 || line > line_starts.len() {
                return Err(format!(
                    "line {line} is outside 1..={} for this file",
                    line_starts.len()
                ));
            }
            let line_start = line_starts[line - 1];
            let line_end = line_starts.get(line).copied().unwrap_or(source.len());
            let column = column.unwrap_or(1);
            if column == 0 {
                return Err("column must be 1-based".to_string());
            }
            let point = line_start.saturating_add(column - 1);
            if point > line_end {
                return Err(format!("column {column} is outside line {line}"));
            }
            token_bounds_at(source, point.min(source.len().saturating_sub(1)))
                .ok_or_else(|| format!("no reference token at line {line}, column {column}"))?
        }
        _ => return Err("provide either start_byte or line/column".to_string()),
    };

    let (start, end) = expand_reference_expression(source, selection_start, selection_end);
    if start >= end {
        return Err("reference selection is empty".to_string());
    }
    let text = source[start..end].trim().to_string();
    if text.is_empty() {
        return Err("reference selection is blank".to_string());
    }
    let start_line = find_line_index_for_offset(&line_starts, start) + 1;
    let end_line = find_line_index_for_offset(&line_starts, end.saturating_sub(1)) + 1;
    Ok(ResolvedReferenceSite {
        path: rel_path_string(&request.file),
        text,
        range: Range {
            start_byte: start,
            end_byte: end,
            start_line,
            end_line,
        },
    })
}

fn token_bounds_at(source: &str, byte: usize) -> Option<(usize, usize)> {
    if source.is_empty() {
        return None;
    }
    let bytes = source.as_bytes();
    let mut idx = byte.min(bytes.len().saturating_sub(1));
    if !is_ident_byte(bytes[idx]) && idx > 0 && is_ident_byte(bytes[idx - 1]) {
        idx -= 1;
    }
    if !is_ident_byte(bytes[idx]) {
        return None;
    }
    let mut start = idx;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = idx + 1;
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    Some((start, end))
}

fn expand_reference_expression(source: &str, start: usize, end: usize) -> (usize, usize) {
    let bytes = source.as_bytes();
    let mut left = start;
    let mut right = end;
    loop {
        if left >= 2 && &source[left - 2..left] == "::" {
            left -= 2;
            while left > 0 && is_ident_byte(bytes[left - 1]) {
                left -= 1;
            }
            continue;
        }
        if left >= 1 && bytes[left - 1] == b'.' {
            left -= 1;
            while left > 0 && is_ident_byte(bytes[left - 1]) {
                left -= 1;
            }
            continue;
        }
        break;
    }
    loop {
        if right + 2 <= source.len() && &source[right..right + 2] == "::" {
            right += 2;
            while right < bytes.len() && is_ident_byte(bytes[right]) {
                right += 1;
            }
            continue;
        }
        if right < bytes.len() && bytes[right] == b'.' {
            right += 1;
            while right < bytes.len() && is_ident_byte(bytes[right]) {
                right += 1;
            }
            continue;
        }
        break;
    }
    (left, right)
}

fn is_ident_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn resolve_rust(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionSupport,
    file: &ProjectFile,
    reference: &str,
) -> DefinitionLookupOutcome {
    let Some(rust) = crate::analyzer::usages::rust_graph::resolve_rust_analyzer(analyzer) else {
        return no_definition("rust_analyzer_unavailable", "Rust analyzer is unavailable");
    };
    let refs = rust.reference_context_of(file);
    let candidates = if let Some((path, name)) = reference.rsplit_once("::") {
        refs.resolve_scoped(path, name)
            .map(|fqn| support.fqn(&fqn))
            .unwrap_or_else(|| {
                rust_import_fallback(file, path)
                    .map(|prefix| support.fqn_or_identifier(file, &format!("{prefix}.{name}")))
                    .unwrap_or_default()
            })
    } else {
        refs.resolve_bare(reference)
            .map(|fqn| support.fqn(fqn))
            .unwrap_or_else(|| {
                let imported = rust_import_fallback(file, reference)
                    .map(|fqn| support.fqn_or_identifier(file, &fqn))
                    .unwrap_or_default();
                if imported.is_empty() {
                    support.file_identifier(file, reference)
                } else {
                    imported
                }
            })
    };
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if rust_reference_looks_external(reference) {
        return boundary(format!(
            "`{reference}` appears to cross a Rust crate/module boundary not indexed in this workspace"
        ));
    }
    let mut searched: Vec<CodeUnit> = analyzer
        .search_definitions(
            reference.rsplit([':', '.']).next().unwrap_or(reference),
            true,
        )
        .into_iter()
        .collect();
    sort_units(&mut searched);
    if !searched.is_empty() {
        return candidates_outcome(searched);
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed Rust definition"),
    )
}

fn rust_import_fallback(file: &ProjectFile, local: &str) -> Option<String> {
    let source = file.read_to_string().ok()?;
    for line in source.lines() {
        let trimmed = line.trim();
        let Some(path) = trimmed
            .strip_prefix("use ")
            .and_then(|rest| rest.strip_suffix(';'))
            .map(str::trim)
        else {
            continue;
        };
        let path = path.strip_prefix("crate::").unwrap_or(path);
        let path = path.strip_prefix("self::").unwrap_or(path);
        if path.contains('{') {
            continue;
        }
        let dotted = path.replace("::", ".");
        if dotted.rsplit('.').next() == Some(local) {
            return Some(dotted);
        }
    }
    None
}

fn rust_reference_looks_external(reference: &str) -> bool {
    reference
        .split("::")
        .next()
        .is_some_and(|root| !matches!(root, "crate" | "self" | "super") && root != reference)
}

fn resolve_js_ts(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionSupport,
    file: &ProjectFile,
    language: Language,
    reference: &str,
) -> DefinitionLookupOutcome {
    let source = match file.read_to_string() {
        Ok(source) => source,
        Err(err) => {
            return diagnostic_outcome(
                DefinitionLookupStatus::NotFound,
                "file_read_failed",
                format!("failed to read `{}`: {err}", rel_path_string(file)),
            );
        }
    };
    let imports = parse_js_ts_imports(&source);
    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());

    if let Some((qualifier, name)) = reference.split_once('.') {
        if let Some(binding) = imports.namespace.get(qualifier) {
            return resolve_js_ts_module_binding(
                file,
                language,
                binding,
                name,
                analyzer,
                support,
                Some(&aliases),
            );
        }
        let candidates = support.file_identifier(file, name);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve to an indexed JS/TS definition"),
        );
    }

    if let Some(named) = imports.named.get(reference) {
        return resolve_js_ts_module_binding(
            file,
            language,
            &named.module,
            &named.imported,
            analyzer,
            support,
            Some(&aliases),
        );
    }
    if let Some(default_module) = imports.default.get(reference) {
        return resolve_js_ts_module_binding(
            file,
            language,
            default_module,
            "default",
            analyzer,
            support,
            Some(&aliases),
        );
    }

    let same_file = support.file_identifier(file, reference);
    if !same_file.is_empty() {
        return candidates_outcome(same_file);
    }

    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed JS/TS definition"),
    )
}

fn resolve_js_ts_module_binding(
    file: &ProjectFile,
    language: Language,
    module: &str,
    exported_name: &str,
    analyzer: &dyn IAnalyzer,
    support: &DefinitionSupport,
    aliases: Option<&AliasResolver>,
) -> DefinitionLookupOutcome {
    if is_bare_js_ts_specifier(module) {
        return boundary(format!(
            "`{module}` is a package import outside this partial workspace analysis"
        ));
    }
    let files = crate::analyzer::resolve_js_ts_module_specifier(file, module, language, aliases);
    if files.is_empty() {
        return boundary(format!(
            "`{module}` could not be resolved to a workspace JS/TS file"
        ));
    }

    let mut candidates = support.file_identifier_in_files(&files, exported_name);
    if candidates.is_empty() && exported_name == "default" {
        for file in &files {
            candidates.extend(
                analyzer
                    .declarations(file)
                    .filter(|unit| unit.identifier() == "default")
                    .cloned(),
            );
        }
        sort_units(&mut candidates);
        candidates.dedup();
    }
    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("`{exported_name}` is not indexed in `{module}`"),
        );
    }
    candidates_outcome(candidates)
}

fn is_bare_js_ts_specifier(module: &str) -> bool {
    !module.starts_with("./")
        && !module.starts_with("../")
        && !module.starts_with('/')
        && !module.starts_with("@/")
}

#[derive(Default)]
struct JsTsImports {
    named: HashMap<String, JsTsNamedImport>,
    namespace: HashMap<String, String>,
    default: HashMap<String, String>,
}

struct JsTsNamedImport {
    module: String,
    imported: String,
}

fn parse_js_ts_imports(source: &str) -> JsTsImports {
    static FROM_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?m)^\s*import\s+(.+?)\s+from\s+['"]([^'"]+)['"]"#).unwrap()
    });
    static REQUIRE_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?m)^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(['"]([^'"]+)['"]\)"#,
        )
        .unwrap()
    });

    let mut imports = JsTsImports::default();
    for captures in FROM_RE.captures_iter(source) {
        let clause = captures.get(1).map(|m| m.as_str().trim()).unwrap_or("");
        let module = captures
            .get(2)
            .map(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        parse_js_ts_import_clause(clause, &module, &mut imports);
    }
    for captures in REQUIRE_RE.captures_iter(source) {
        let local = captures
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        let module = captures
            .get(2)
            .map(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        if !local.is_empty() && !module.is_empty() {
            imports.namespace.insert(local, module);
        }
    }
    imports
}

fn parse_js_ts_import_clause(clause: &str, module: &str, imports: &mut JsTsImports) {
    let mut rest = clause.trim();
    if let Some(namespace) = rest.strip_prefix("* as ") {
        let local = namespace.trim();
        if is_identifier(local) {
            imports
                .namespace
                .insert(local.to_string(), module.to_string());
        }
        return;
    }

    if let Some(open) = rest.find('{') {
        let default_part = rest[..open].trim().trim_end_matches(',').trim();
        if is_identifier(default_part) {
            imports
                .default
                .insert(default_part.to_string(), module.to_string());
        }
        if let Some(close) = rest[open + 1..].find('}') {
            let names = &rest[open + 1..open + 1 + close];
            for part in names.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let (imported, local) = part
                    .split_once(" as ")
                    .map(|(imported, local)| (imported.trim(), local.trim()))
                    .unwrap_or((part, part));
                if is_identifier(imported) && is_identifier(local) {
                    imports.named.insert(
                        local.to_string(),
                        JsTsNamedImport {
                            module: module.to_string(),
                            imported: imported.to_string(),
                        },
                    );
                }
            }
        }
        return;
    }

    rest = rest.trim_end_matches(',');
    if is_identifier(rest) {
        imports.default.insert(rest.to_string(), module.to_string());
    }
}

fn resolve_go(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionSupport,
    file: &ProjectFile,
    reference: &str,
) -> DefinitionLookupOutcome {
    let package = go_package_name(file);
    if let Some((qualifier, name)) = reference.split_once('.') {
        let imports = parse_go_imports(file);
        if let Some(import_path) = imports.get(qualifier) {
            let candidates = support.fqn(&format!("{import_path}.{name}"));
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            if !go_import_path_is_workspace(analyzer, import_path) {
                return boundary(format!(
                    "`{import_path}` is outside this partial Go workspace analysis"
                ));
            }
            return no_definition(
                "no_indexed_definition",
                format!("`{name}` is not indexed in Go package `{import_path}`"),
            );
        }
        let candidates = support.fqn_candidates([
            format!("{package}.{qualifier}.{name}"),
            format!("{package}.{name}"),
        ]);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve to an indexed Go definition"),
        );
    }

    let candidates = support.fqn(&format!("{package}.{reference}"));
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    let same_file = support.file_identifier(file, reference);
    if !same_file.is_empty() {
        return candidates_outcome(same_file);
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed Go definition"),
    )
}

fn go_package_name(file: &ProjectFile) -> String {
    let source = file.read_to_string().unwrap_or_default();
    let declared = source
        .lines()
        .find_map(|line| line.trim().strip_prefix("package "))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or("");
    crate::analyzer::go::packages::canonical_go_package_name(file, declared)
}

fn parse_go_imports(file: &ProjectFile) -> HashMap<String, String> {
    let source = file.read_to_string().unwrap_or_default();
    let mut imports = HashMap::default();
    let lines: Vec<&str> = source.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        if let Some(rest) = trimmed.strip_prefix("import ") {
            let rest = rest.trim();
            if rest == "(" {
                index += 1;
                while index < lines.len() && lines[index].trim() != ")" {
                    parse_go_import_line(lines[index].trim(), &mut imports);
                    index += 1;
                }
            } else {
                parse_go_import_line(rest, &mut imports);
            }
        }
        index += 1;
    }
    imports
}

fn parse_go_import_line(line: &str, imports: &mut HashMap<String, String>) {
    let line = line.split("//").next().unwrap_or("").trim();
    if line.is_empty() {
        return;
    }
    let Some(first_quote) = line.find('"') else {
        return;
    };
    let Some(second_quote) = line[first_quote + 1..].find('"') else {
        return;
    };
    let import_path = &line[first_quote + 1..first_quote + 1 + second_quote];
    let alias = line[..first_quote].trim();
    if alias == "_" {
        return;
    }
    let local = if alias.is_empty() {
        import_path
            .rsplit('/')
            .next()
            .unwrap_or(import_path)
            .replace('-', "_")
    } else {
        alias.to_string()
    };
    imports.insert(local, import_path.to_string());
}

fn go_import_path_is_workspace(analyzer: &dyn IAnalyzer, import_path: &str) -> bool {
    analyzer
        .all_declarations()
        .any(|unit| unit.fq_name().starts_with(&format!("{import_path}.")))
}

fn resolve_java(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionSupport,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(java) = crate::analyzer::usages::java_graph::resolve_java_analyzer(analyzer) else {
        return no_definition("java_analyzer_unavailable", "Java analyzer is unavailable");
    };
    let Some(tree) = parse_java_tree(source) else {
        return no_definition("java_parse_failed", "Java source could not be parsed");
    };

    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.range.start_byte, site.range.end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Java definition",
                site.text
            ),
        );
    };

    if is_java_declaration_or_import_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Java reference site", site.text),
        );
    }

    match node.kind() {
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            resolve_java_type_reference(java, file, source, node)
        }
        "object_creation_expression" => node
            .child_by_field_name("type")
            .map(|type_node| resolve_java_type_reference(java, file, source, type_node))
            .unwrap_or_else(|| {
                no_definition(
                    "no_indexed_definition",
                    format!("`{}` did not resolve to an indexed Java type", site.text),
                )
            }),
        "method_invocation" => {
            resolve_java_method_invocation(analyzer, support, file, source, node)
        }
        "field_access" => resolve_java_field_access(analyzer, support, file, source, node),
        "identifier" => {
            if let Some(parent) = node.parent() {
                match parent.kind() {
                    "method_invocation" => {
                        return resolve_java_method_invocation(
                            analyzer, support, file, source, parent,
                        );
                    }
                    "field_access" => {
                        return resolve_java_field_access(analyzer, support, file, source, parent);
                    }
                    _ => {}
                }
            }
            resolve_java_bare_identifier(analyzer, java, support, file, source, node)
        }
        _ => no_definition(
            "unsupported_java_reference_shape",
            format!(
                "`{}` is a Java `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn parse_java_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn smallest_named_node_covering<'tree>(
    node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    if node.end_byte() < end || node.start_byte() > start {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() <= start
            && child.end_byte() >= end
            && let Some(found) = smallest_named_node_covering(child, start, end)
        {
            return Some(found);
        }
    }
    Some(node)
}

fn is_java_declaration_or_import_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "import_declaration" || parent.kind() == "package_declaration" {
        return true;
    }
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "method_declaration"
                | "constructor_declaration"
                | "field_declaration"
                | "variable_declarator"
                | "formal_parameter"
        )
}

fn resolve_java_type_reference(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let raw = java_node_text(node, source);
    let normalized = normalize_java_type_text(raw);
    if normalized.is_empty() {
        return no_definition("no_reference_text", "Java type reference is blank");
    }
    if let Some(unit) = java.resolve_type_name_in_file(file, normalized) {
        return candidates_outcome(vec![unit]);
    }
    if java_import_boundary_for_type(java, file, normalized) {
        return boundary(format!(
            "`{normalized}` appears to cross a Java import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{normalized}` did not resolve to an indexed Java type"),
    )
}

fn resolve_java_method_invocation(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionSupport,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(name_node) = node.child_by_field_name("name") else {
        return no_definition("no_method_name", "Java method invocation has no name");
    };
    let name = java_node_text(name_node, source);
    if name.is_empty() {
        return no_definition("no_method_name", "Java method invocation has a blank name");
    }

    if let Some(object) = node.child_by_field_name("object") {
        if let Some(owner) = java_receiver_type(analyzer, file, source, object) {
            return java_member_candidates(support, &owner.fq_name(), name);
        }
        return no_definition(
            "unsupported_java_receiver",
            format!("receiver for Java method `{name}` is not resolved"),
        );
    }

    let static_import = java_static_import_candidates(analyzer, support, file, name);
    if !static_import.candidates.is_empty()
        || static_import.status == DefinitionLookupStatus::UnresolvableImportBoundary
    {
        return static_import;
    }

    let class_ranges = ClassRangeIndex::build(analyzer, file);
    if let Some(owner_fqn) = class_ranges.enclosing(name_node.start_byte()) {
        return java_member_candidates(support, owner_fqn, name);
    }

    no_definition(
        "no_indexed_definition",
        format!("`{name}` did not resolve to an indexed Java method"),
    )
}

fn resolve_java_field_access(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionSupport,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(field_node) = node.child_by_field_name("field") else {
        return no_definition("no_field_name", "Java field access has no field name");
    };
    let field = java_node_text(field_node, source);
    let Some(object) = node.child_by_field_name("object") else {
        return no_definition("no_field_receiver", "Java field access has no receiver");
    };
    if let Some(owner) = java_receiver_type(analyzer, file, source, object) {
        return java_member_candidates(support, &owner.fq_name(), field);
    }
    no_definition(
        "unsupported_java_receiver",
        format!("receiver for Java field `{field}` is not resolved"),
    )
}

fn resolve_java_bare_identifier(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &DefinitionSupport,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let name = java_node_text(node, source);
    if let Some(unit) = java.resolve_type_name_in_file(file, name) {
        return candidates_outcome(vec![unit]);
    }
    let static_import = java_static_import_candidates(analyzer, support, file, name);
    if !static_import.candidates.is_empty()
        || static_import.status == DefinitionLookupStatus::UnresolvableImportBoundary
    {
        return static_import;
    }
    if java_import_boundary_for_type(java, file, name) {
        return boundary(format!(
            "`{name}` appears to cross a Java import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{name}` did not resolve to an indexed Java definition"),
    )
}

fn java_receiver_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    object: Node<'_>,
) -> Option<CodeUnit> {
    let java = crate::analyzer::usages::java_graph::resolve_java_analyzer(analyzer)?;
    java_receiver_type_for_java(java, file, source, object).or_else(|| {
        matches!(object.kind(), "this" | "super")
            .then(|| {
                ClassRangeIndex::build(analyzer, file)
                    .enclosing(object.start_byte())
                    .and_then(|fqn| analyzer.definitions(fqn).next().cloned())
            })
            .flatten()
    })
}

fn java_receiver_type_for_java(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    object: Node<'_>,
) -> Option<CodeUnit> {
    match object.kind() {
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            let raw = java_node_text(object, source);
            java.resolve_type_name_in_file(file, normalize_java_type_text(raw))
        }
        "identifier" => {
            let name = java_node_text(object, source);
            java_type_of_identifier_before(java, file, source, name, object.start_byte())
        }
        _ => None,
    }
}

fn java_type_of_identifier_before(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    name: &str,
    before_byte: usize,
) -> Option<CodeUnit> {
    let tree = parse_java_tree(source)?;
    let mut found = None;
    collect_java_typed_binding_before(
        java,
        file,
        source,
        tree.root_node(),
        name,
        before_byte,
        &mut found,
    );
    found
}

fn collect_java_typed_binding_before(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    name: &str,
    before_byte: usize,
    found: &mut Option<CodeUnit>,
) {
    if node.start_byte() >= before_byte {
        return;
    }
    match node.kind() {
        "local_variable_declaration" | "field_declaration" => {
            if let Some(resolved) = node
                .child_by_field_name("type")
                .and_then(|type_node| java_type_from_node(java, file, source, type_node))
            {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() == "variable_declarator"
                        && let Some(name_node) = child.child_by_field_name("name")
                        && name_node.start_byte() < before_byte
                        && java_node_text(name_node, source) == name
                    {
                        *found = Some(resolved.clone());
                    }
                }
            }
        }
        "formal_parameter" => {
            if let Some(name_node) = node.child_by_field_name("name")
                && name_node.start_byte() < before_byte
                && java_node_text(name_node, source) == name
                && let Some(resolved) = node
                    .child_by_field_name("type")
                    .and_then(|type_node| java_type_from_node(java, file, source, type_node))
            {
                *found = Some(resolved);
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_java_typed_binding_before(java, file, source, child, name, before_byte, found);
    }
}

fn java_type_from_node(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<CodeUnit> {
    java.resolve_type_name_in_file(
        file,
        normalize_java_type_text(java_node_text(type_node, source)),
    )
}

fn java_member_candidates(
    support: &DefinitionSupport,
    owner_fqn: &str,
    member: &str,
) -> DefinitionLookupOutcome {
    let candidates = support.fqn(&format!("{owner_fqn}.{member}"));
    if candidates.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!("`{owner_fqn}.{member}` is not indexed as a Java definition"),
        )
    } else {
        candidates_outcome(candidates)
    }
}

fn java_static_import_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionSupport,
    file: &ProjectFile,
    member: &str,
) -> DefinitionLookupOutcome {
    let mut candidates = Vec::new();
    let mut saw_external = false;
    for import in analyzer.import_statements(file) {
        let Some(path) = java_static_import_path(import) else {
            continue;
        };
        if let Some(owner) = path.strip_suffix(".*") {
            let owner_candidates = support.fqn(&format!("{owner}.{member}"));
            if owner_candidates.is_empty() && !java_workspace_fqn_exists(analyzer, owner) {
                saw_external = true;
            }
            candidates.extend(owner_candidates);
            continue;
        }
        let Some((owner, imported_member)) = path.rsplit_once('.') else {
            continue;
        };
        if imported_member != member {
            continue;
        }
        let imported = support.fqn(path);
        if imported.is_empty() && !java_workspace_fqn_exists(analyzer, owner) {
            saw_external = true;
        }
        candidates.extend(imported);
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if saw_external {
        return boundary(format!(
            "`{member}` appears to cross a Java static import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_static_import_match",
        format!("`{member}` did not match an indexed Java static import"),
    )
}

fn java_import_boundary_for_type(java: &JavaAnalyzer, file: &ProjectFile, name: &str) -> bool {
    for import in java.import_statements(file) {
        let trimmed = import.trim();
        if trimmed.starts_with("import static ") {
            continue;
        }
        let Some(path) = trimmed
            .strip_prefix("import ")
            .and_then(|rest| rest.strip_suffix(';'))
            .map(str::trim)
        else {
            continue;
        };
        if let Some(package) = path.strip_suffix(".*") {
            if !package.is_empty() && !java_workspace_package_exists(java, package) {
                return true;
            }
            continue;
        }
        if path.rsplit('.').next() == Some(name) {
            let package = path
                .rsplit_once('.')
                .map(|(package, _)| package)
                .unwrap_or("");
            return !java_workspace_package_exists(java, package);
        }
    }
    false
}

fn java_static_import_path(import: &str) -> Option<&str> {
    import
        .trim()
        .strip_prefix("import static ")
        .and_then(|rest| rest.strip_suffix(';'))
        .map(str::trim)
}

fn java_workspace_fqn_exists(analyzer: &dyn IAnalyzer, fqn: &str) -> bool {
    analyzer.definitions(fqn).next().is_some()
}

fn java_workspace_package_exists(java: &JavaAnalyzer, package: &str) -> bool {
    java.all_declarations().any(|unit| {
        unit.package_name() == package || unit.fq_name().starts_with(&format!("{package}."))
    })
}

fn java_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}

fn normalize_java_type_text(raw: &str) -> &str {
    raw.split('<')
        .next()
        .unwrap_or(raw)
        .trim()
        .trim_end_matches("[]")
        .trim()
}

fn resolve_php(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionSupport,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(php) = crate::analyzer::usages::php_graph::resolve_php_analyzer(analyzer) else {
        return no_definition("php_analyzer_unavailable", "PHP analyzer is unavailable");
    };
    let Some(tree) = parse_php_tree(source) else {
        return no_definition("php_parse_failed", "PHP source could not be parsed");
    };
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.range.start_byte, site.range.end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed PHP definition",
                site.text
            ),
        );
    };
    if php_is_non_reference_context(node) || php_is_declaration_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a PHP reference site", site.text),
        );
    }
    if php_is_variable_reference(node) {
        return no_definition(
            "local_variable_reference",
            format!(
                "`{}` is a PHP variable reference, not an indexed definition",
                site.text
            ),
        );
    }

    let ctx = FileContext {
        namespace: php.namespace_of_file(file),
        aliases: parse_php_use_aliases_from_source(source),
    };
    let class_ranges = ClassRangeIndex::build(analyzer, file);
    match php_reference_node(node) {
        Some(PhpReferenceNode::Type(type_node)) => {
            let raw = php_qualified_candidate_text(type_node, source);
            php_fqn_outcome(php, support, resolve_php_type(&raw, &ctx), &raw)
        }
        Some(PhpReferenceNode::Function(name_node)) => {
            let raw = php_qualified_candidate_text(name_node, source);
            php_fqn_outcome(php, support, resolve_php_function(&raw, &ctx), &raw)
        }
        Some(PhpReferenceNode::Constant(name_node)) => {
            let raw = php_qualified_candidate_text(name_node, source);
            php_fqn_outcome(php, support, resolve_php_constant(&raw, &ctx), &raw)
        }
        Some(PhpReferenceNode::StaticMember { scope, name }) => {
            let member = php_node_text(name, source).trim_start_matches('$');
            let owner = php_static_scope_fqn(php, support, scope, source, &ctx, &class_ranges);
            php_member_outcome(php, support, owner, member)
        }
        Some(PhpReferenceNode::InstanceMember { object, name }) => {
            let member = php_node_text(name, source).trim_start_matches('$');
            let bindings =
                php_bindings_before(php, file, source, root, site.range.start_byte, &ctx);
            let owner = php_instance_receiver_fqn(object, source, &class_ranges, &bindings);
            php_member_outcome(php, support, owner, member)
        }
        None => no_definition(
            "unsupported_php_reference_shape",
            format!(
                "`{}` is a PHP `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn parse_php_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    parser.parse(source, None)
}

enum PhpReferenceNode<'tree> {
    Type(Node<'tree>),
    Function(Node<'tree>),
    Constant(Node<'tree>),
    StaticMember {
        scope: Node<'tree>,
        name: Node<'tree>,
    },
    InstanceMember {
        object: Node<'tree>,
        name: Node<'tree>,
    },
}

fn php_reference_node(node: Node<'_>) -> Option<PhpReferenceNode<'_>> {
    let node = php_qualified_reference_node(node);
    match node.kind() {
        "object_creation_expression" => php_object_creation_type(node).map(PhpReferenceNode::Type),
        "named_type" => (!php_is_in_object_creation(node)).then_some(PhpReferenceNode::Type(node)),
        "function_call_expression" => node
            .child_by_field_name("function")
            .filter(|name| matches!(name.kind(), "name" | "qualified_name"))
            .map(PhpReferenceNode::Function),
        "scoped_call_expression" | "class_constant_access_expression" => {
            let scope = node.child_by_field_name("scope")?;
            let name = node.child_by_field_name("name")?;
            Some(PhpReferenceNode::StaticMember { scope, name })
        }
        "member_call_expression" | "member_access_expression" => {
            let object = node.child_by_field_name("object")?;
            let name = node.child_by_field_name("name")?;
            Some(PhpReferenceNode::InstanceMember { object, name })
        }
        "name" | "qualified_name" => {
            let parent = node.parent()?;
            match parent.kind() {
                "object_creation_expression" | "named_type" => Some(PhpReferenceNode::Type(node)),
                "function_call_expression"
                    if parent.child_by_field_name("function") == Some(node) =>
                {
                    Some(PhpReferenceNode::Function(node))
                }
                "scoped_call_expression" | "class_constant_access_expression"
                    if parent.child_by_field_name("name") == Some(node) =>
                {
                    let scope = parent.child_by_field_name("scope")?;
                    Some(PhpReferenceNode::StaticMember { scope, name: node })
                }
                "member_call_expression" | "member_access_expression"
                    if parent.child_by_field_name("name") == Some(node) =>
                {
                    let object = parent.child_by_field_name("object")?;
                    Some(PhpReferenceNode::InstanceMember { object, name: node })
                }
                _ if php_is_bare_constant_reference(node) => Some(PhpReferenceNode::Constant(node)),
                _ => None,
            }
        }
        _ => {
            let parent = node.parent()?;
            php_reference_node(parent)
        }
    }
}

fn php_qualified_reference_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "namespace_name" | "qualified_name") {
            node = parent;
        } else {
            break;
        }
    }
    node
}

fn php_fqn_outcome(
    php: &PhpAnalyzer,
    support: &DefinitionSupport,
    fqn: Option<String>,
    raw: &str,
) -> DefinitionLookupOutcome {
    let Some(fqn) = fqn else {
        return no_definition(
            "no_indexed_definition",
            format!("`{raw}` did not resolve to a PHP definition name"),
        );
    };
    let candidates = support.fqn(&fqn);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if php_crosses_unindexed_boundary(php, &fqn) {
        return boundary(format!(
            "`{raw}` resolves to `{fqn}`, which is outside this partial PHP workspace analysis"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{raw}` resolved to `{fqn}`, but no indexed PHP definition was found"),
    )
}

fn php_member_outcome(
    php: &PhpAnalyzer,
    support: &DefinitionSupport,
    owner: Option<String>,
    member: &str,
) -> DefinitionLookupOutcome {
    let Some(owner) = owner else {
        return no_definition(
            "unsupported_php_receiver",
            format!("receiver for PHP member `{member}` is not resolved"),
        );
    };
    let fqn = format!("{owner}.{member}");
    let candidates = support.fqn(&fqn);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if php_crosses_unindexed_boundary(php, &owner) {
        return boundary(format!(
            "`{member}` appears to cross a PHP boundary at `{owner}` not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{fqn}` is not indexed as a PHP definition"),
    )
}

fn php_crosses_unindexed_boundary(php: &PhpAnalyzer, fqn: &str) -> bool {
    let Some((namespace, _)) = fqn.rsplit_once('.') else {
        return !php_workspace_exact_namespace_exists(php, "");
    };
    !php_workspace_exact_namespace_exists(php, namespace)
}

fn php_workspace_exact_namespace_exists(php: &PhpAnalyzer, namespace: &str) -> bool {
    php.all_declarations()
        .any(|unit| unit.package_name() == namespace)
}

fn php_static_scope_fqn(
    php: &PhpAnalyzer,
    support: &DefinitionSupport,
    scope: Node<'_>,
    source: &str,
    ctx: &FileContext,
    class_ranges: &ClassRangeIndex,
) -> Option<String> {
    let text = php_node_text(scope, source);
    match text {
        "self" | "static" => class_ranges
            .enclosing(scope.start_byte())
            .map(str::to_string),
        "parent" => php_parent_fqn(php, support, class_ranges.enclosing(scope.start_byte())?),
        _ => resolve_php_type(text, ctx),
    }
}

fn php_parent_fqn(
    php: &PhpAnalyzer,
    support: &DefinitionSupport,
    enclosing_fqn: &str,
) -> Option<String> {
    let child = support.fqn(enclosing_fqn).into_iter().next()?;
    let source = child.source();
    let raw_source = source.read_to_string().ok()?;
    let tree = parse_php_tree(&raw_source)?;
    let ctx = FileContext {
        namespace: php.namespace_of_file(source),
        aliases: parse_php_use_aliases_from_source(&raw_source),
    };
    let ranges = php.ranges(&child);
    let class_range = ranges.first()?;
    php_declared_parent_type(
        tree.root_node(),
        &raw_source,
        &ctx,
        class_range.start_byte,
        class_range.end_byte,
    )
}

fn php_declared_parent_type(
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    start: usize,
    end: usize,
) -> Option<String> {
    if node.start_byte() <= start
        && node.end_byte() >= end
        && matches!(
            node.kind(),
            "class_declaration" | "interface_declaration" | "trait_declaration"
        )
    {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if matches!(child.kind(), "base_clause" | "class_interface_clause") {
                let mut clause_cursor = child.walk();
                for clause_child in child.named_children(&mut clause_cursor) {
                    if matches!(
                        clause_child.kind(),
                        "name" | "qualified_name" | "namespace_name"
                    ) {
                        return resolve_php_type(
                            &php_qualified_candidate_text(clause_child, source),
                            ctx,
                        );
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() <= start
            && child.end_byte() >= end
            && let Some(parent) = php_declared_parent_type(child, source, ctx, start, end)
        {
            return Some(parent);
        }
    }
    None
}

fn php_instance_receiver_fqn(
    object: Node<'_>,
    source: &str,
    class_ranges: &ClassRangeIndex,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    match object.kind() {
        "variable_name" => {
            let name = php_variable_identifier(object, source);
            if name == "this" {
                return class_ranges
                    .enclosing(object.start_byte())
                    .map(str::to_string);
            }
            first_precise(bindings, name)
        }
        _ => None,
    }
}

fn php_bindings_before(
    php: &PhpAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    byte: usize,
    ctx: &FileContext,
) -> LocalInferenceEngine<String> {
    let scope = php_enclosing_scope(root, byte).unwrap_or(root);
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= byte {
            continue;
        }
        if node != scope && PHP_SCOPE_NODES.contains(&node.kind()) {
            continue;
        }
        php_seed_parameters(node, source, ctx, &mut bindings);
        if node.end_byte() <= byte {
            php_seed_assignment(php, file, node, source, ctx, &mut bindings);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            if child.start_byte() < byte {
                stack.push(child);
            }
        }
    }
    bindings
}

const PHP_SCOPE_NODES: &[&str] = &[
    "function_definition",
    "method_declaration",
    "anonymous_function",
    "arrow_function",
];

fn php_enclosing_scope<'tree>(root: Node<'tree>, byte: usize) -> Option<Node<'tree>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() <= byte && byte < node.end_byte() {
            if PHP_SCOPE_NODES.contains(&node.kind()) {
                best = Some(node);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    best
}

fn php_seed_parameters(
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if !matches!(
            child.kind(),
            "simple_parameter" | "property_promotion_parameter"
        ) {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let name = php_variable_identifier(name_node, source);
        if name.is_empty() {
            continue;
        }
        match child
            .child_by_field_name("type")
            .and_then(|type_node| resolve_php_type(php_node_text(type_node, source), ctx))
        {
            Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
            None => bindings.declare_shadow(name.to_string()),
        }
    }
}

fn php_seed_assignment(
    _php: &PhpAnalyzer,
    _file: &ProjectFile,
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if node.kind() != "assignment_expression" {
        return;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    if left.kind() != "variable_name" {
        return;
    }
    let name = php_variable_identifier(left, source);
    if name.is_empty() {
        return;
    }
    let resolved = (right.kind() == "object_creation_expression")
        .then(|| php_object_creation_type(right))
        .flatten()
        .and_then(|type_node| resolve_php_type(php_node_text(type_node, source), ctx));
    match resolved {
        Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
        None => bindings.declare_shadow(name.to_string()),
    }
}

fn php_object_creation_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
}

fn php_is_in_object_creation(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "object_creation_expression")
}

fn php_is_bare_constant_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    !matches!(
        parent.kind(),
        "function_call_expression"
            | "member_access_expression"
            | "member_call_expression"
            | "scoped_call_expression"
            | "class_constant_access_expression"
            | "named_type"
            | "object_creation_expression"
            | "function_definition"
            | "method_declaration"
            | "const_element"
            | "namespace_use_clause"
            | "namespace_definition"
            | "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "qualified_name"
            | "base_clause"
            | "class_interface_clause"
    )
}

fn php_variable_identifier<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    php_node_text(node, source).trim_start_matches('$')
}

fn php_is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "trait_declaration"
                | "function_definition"
                | "method_declaration"
                | "const_element"
                | "property_element"
                | "simple_parameter"
                | "property_promotion_parameter"
        )
}

fn php_is_variable_reference(node: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "variable_name" {
            return true;
        }
        current = candidate.parent();
    }
    false
}

fn php_is_non_reference_context(node: Node<'_>) -> bool {
    let mut parent = Some(node);
    while let Some(current) = parent {
        if matches!(
            current.kind(),
            "namespace_use_declaration"
                | "namespace_use_clause"
                | "comment"
                | "string"
                | "encapsed_string"
                | "string_value"
                | "heredoc"
                | "nowdoc"
        ) {
            return true;
        }
        parent = current.parent();
    }
    false
}

fn candidates_outcome(candidates: Vec<CodeUnit>) -> DefinitionLookupOutcome {
    let status = if candidates.len() == 1 {
        DefinitionLookupStatus::Resolved
    } else {
        DefinitionLookupStatus::Ambiguous
    };
    DefinitionLookupOutcome {
        status,
        reference: None,
        candidates,
        diagnostics: Vec::new(),
    }
}

fn boundary(message: String) -> DefinitionLookupOutcome {
    diagnostic_outcome(
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "unresolvable_import_boundary",
        message,
    )
}

fn no_definition(kind: impl Into<String>, message: impl Into<String>) -> DefinitionLookupOutcome {
    diagnostic_outcome(DefinitionLookupStatus::NoDefinition, kind, message)
}

fn diagnostic_outcome(
    status: DefinitionLookupStatus,
    kind: impl Into<String>,
    message: impl Into<String>,
) -> DefinitionLookupOutcome {
    DefinitionLookupOutcome {
        status,
        reference: None,
        candidates: Vec::new(),
        diagnostics: vec![DefinitionLookupDiagnostic {
            kind: kind.into(),
            message: message.into(),
        }],
    }
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first == '$' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())
}

fn sort_units(units: &mut [CodeUnit]) {
    units.sort_by(|left, right| {
        rel_path_string(left.source())
            .cmp(&rel_path_string(right.source()))
            .then_with(|| left.fq_name().cmp(&right.fq_name()))
            .then_with(|| left.signature().cmp(&right.signature()))
    });
}
