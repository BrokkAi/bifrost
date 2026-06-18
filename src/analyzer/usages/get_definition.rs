use crate::analyzer::common::language_for_file;
use crate::analyzer::{AliasResolver, CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::hash::HashMap;
use crate::path_utils::rel_path_string;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use regex::Regex;
use std::sync::LazyLock;

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
        Language::Java
        | Language::Cpp
        | Language::Python
        | Language::Php
        | Language::Scala
        | Language::CSharp
        | Language::None => {
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
