use super::navigation::*;
use super::*;
use crate::analyzer::{
    CallableLinkage, CppCallableUnitRole, cpp_callable_definitions_share_identity_evidence,
    cpp_callable_unit_role, cpp_indexed_callable_linkage,
};

pub(super) type DefinitionCandidateKey = (
    String,
    Option<String>,
    String,
    usize,
    Option<usize>,
    usize,
    Option<usize>,
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
);

pub(super) type DefinitionOutcomeKey = (String, Vec<DefinitionCandidateKey>);

#[derive(Debug, Clone, Serialize)]
pub struct DefinitionCandidate {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fqn: Option<String>,
    pub path: String,
    pub start_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<usize>,
    pub end_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurrence_role: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefinitionDiagnostic {
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotFoundInput {
    pub input: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub(super) const SYMBOL_NOT_FOUND_NOTE: &str =
    "no symbol matched; try search_symbols with a substring or regex pattern";

pub(super) const FILE_NOT_FOUND_NOTE: &str =
    "no workspace file matched this path; check the relative path or pass a glob pattern";

#[derive(Debug, Clone, Copy)]
pub(super) enum PathLikeSymbolGuidanceContext {
    DefinitionByReference,
    ScanUsages,
    SymbolLookup,
}

pub(super) fn not_found_input(input: impl Into<String>, note: Option<String>) -> NotFoundInput {
    NotFoundInput {
        input: input.into(),
        note,
    }
}

pub(super) fn symbol_not_found_input(input: impl Into<String>) -> NotFoundInput {
    not_found_input(input, Some(SYMBOL_NOT_FOUND_NOTE.to_string()))
}

pub(super) fn unsupported_selector_shape_not_found_input(
    analyzer: &dyn IAnalyzer,
    input: &str,
) -> Option<NotFoundInput> {
    unsupported_selector_shape_guidance(analyzer, input)
        .map(|note| not_found_input(input.to_string(), Some(note)))
}

pub(super) fn path_like_symbol_not_found_input(
    input: impl Into<String>,
    context: PathLikeSymbolGuidanceContext,
) -> NotFoundInput {
    let input = input.into();
    let note = path_like_symbol_guidance(&input, context)
        .unwrap_or_else(|| SYMBOL_NOT_FOUND_NOTE.to_string());
    not_found_input(input, Some(note))
}

pub(super) fn path_like_symbol_guidance(
    input: &str,
    context: PathLikeSymbolGuidanceContext,
) -> Option<String> {
    if !looks_like_file_target(input) {
        return None;
    }
    Some(match context {
        PathLikeSymbolGuidanceContext::DefinitionByReference => {
            "`symbol` must be an enclosing workspace symbol, not a file path. `context` must be exact source text copied from inside that symbol. If you already have exact context, use get_summaries on the file to identify the enclosing symbol, then retry with the same context and a single-token target. If you do not have exact context, identify the enclosing symbol first, then call get_symbol_sources for that symbol and copy context from the returned source."
                .to_string()
        }
        PathLikeSymbolGuidanceContext::ScanUsages => {
            "`symbols` expects workspace symbols, not file paths. Use list_symbols or search_symbols to identify the declaration, then call scan_usages_by_reference with that symbol; use `paths` only to narrow where usages are searched."
                .to_string()
        }
        PathLikeSymbolGuidanceContext::SymbolLookup => {
            "this field expects a workspace symbol, not a file path; use list_symbols on the file to discover symbols, then retry with the symbol"
                .to_string()
        }
    })
}

pub(super) fn file_not_found_input(input: impl Into<String>) -> NotFoundInput {
    not_found_input(input, Some(FILE_NOT_FOUND_NOTE.to_string()))
}

pub(super) fn anchor_not_found_input(
    input: impl Into<String>,
    anchor: &str,
    name: &str,
) -> NotFoundInput {
    not_found_input(
        input,
        Some(format!(
            "`{name}` resolved, but no definition is in `{anchor}`; re-call with the bare name to list valid selectors"
        )),
    )
}

pub(super) fn symbol_source_anchor_not_found_input(
    input: impl Into<String>,
    anchor: &str,
    name: &str,
    candidate_names: &[String],
) -> NotFoundInput {
    if looks_like_extensionless_path_anchor(anchor)
        && let [canonical] = candidate_names
    {
        return not_found_input(
            input,
            Some(format!(
                "`{anchor}` looks like a source path missing its extension; retry with the canonical workspace symbol `{canonical}`"
            )),
        );
    }
    anchor_not_found_input(input, anchor, name)
}

pub(super) fn renderable_not_found_input(input: impl Into<String>) -> NotFoundInput {
    not_found_input(input, None)
}

#[derive(Debug, Clone, Serialize)]
pub struct AmbiguousSymbol {
    pub target: String,
    pub matches: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub(super) fn external_location_diagnostic_message(kind: &str, message: String) -> String {
    if kind == "invalid_location" && (message.contains("byte") || message.contains("offset")) {
        "provide a positive line and, when needed, a positive character column".to_string()
    } else {
        message
    }
}

pub(super) fn definition_candidate_key(candidate: &DefinitionCandidate) -> DefinitionCandidateKey {
    (
        candidate.name.clone(),
        candidate.fqn.clone(),
        candidate.path.clone(),
        candidate.start_line,
        candidate.start_column,
        candidate.end_line,
        candidate.end_column,
        candidate.kind.clone(),
        candidate.signature.clone(),
        candidate.language.clone(),
        candidate.canonical_selector.clone(),
        candidate.occurrence_role.clone(),
    )
}

pub(super) fn lexical_definition_candidate(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    definition: &LexicalDefinition,
) -> Option<DefinitionCandidate> {
    let source = analyzer.project().read_source(file).ok()?;
    let line_starts = compute_line_starts(&source);
    let signature = source
        .get(definition.declaration_range.start_byte..definition.declaration_range.end_byte)?
        .trim()
        .to_string();
    Some(DefinitionCandidate {
        name: definition.identifier.clone(),
        fqn: None,
        path: rel_path_string(file),
        start_line: definition.name_range.start_line,
        start_column: Some(
            crate::text_utils::line_column_for_offset(
                &source,
                &line_starts,
                definition.name_range.start_byte,
            )
            .1,
        ),
        end_line: definition.name_range.end_line,
        end_column: Some(
            crate::text_utils::line_column_for_offset(
                &source,
                &line_starts,
                definition.name_range.end_byte,
            )
            .1,
        ),
        kind: declaration_kind_name(definition.kind).to_string(),
        signature: (!signature.is_empty()).then_some(signature),
        canonical_selector: None,
        occurrence_role: None,
        language: language_name(language_for_file(file)),
    })
}

pub(super) fn declaration_kind_name(kind: DeclarationKind) -> &'static str {
    match kind {
        DeclarationKind::Parameter => "parameter",
        DeclarationKind::ReceiverParameter => "receiver_parameter",
        DeclarationKind::LambdaParameter => "lambda_parameter",
        DeclarationKind::LocalVariable
        | DeclarationKind::CatchParameter
        | DeclarationKind::EnhancedForVariable
        | DeclarationKind::PatternVariable
        | DeclarationKind::ResourceVariable => "local_variable",
    }
}

#[derive(Default)]
pub(super) struct CppIdentityRenderCache {
    cpp_classifiers: HashMap<ProjectFile, Option<crate::analyzer::CppOccurrenceClassifier>>,
    canonical_selectors: HashMap<CodeUnit, String>,
    loaded_fqns: HashSet<String>,
}

impl CppIdentityRenderCache {
    pub(super) fn canonical_selector(
        &mut self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Option<String> {
        if language_for_target(unit) != Language::Cpp || !unit.is_callable() {
            return None;
        }
        let fqn = unit.fq_name();
        if self.loaded_fqns.insert(fqn.clone()) {
            let definitions: Vec<_> = analyzer
                .definitions(&fqn)
                .filter(|candidate| language_for_target(candidate) == Language::Cpp)
                .collect();
            self.canonical_selectors
                .extend(cpp_canonical_selectors(analyzer, &definitions));
        }
        self.canonical_selectors
            .get(unit)
            .cloned()
            .or_else(|| Some(file_anchored_definition_selector(unit)))
    }

    fn classifier(
        &mut self,
        analyzer: &dyn IAnalyzer,
        source: &ProjectFile,
    ) -> Option<&crate::analyzer::CppOccurrenceClassifier> {
        self.cpp_classifiers
            .entry(source.clone())
            .or_insert_with(|| {
                analyzer
                    .indexed_source(source)
                    .and_then(|content| crate::analyzer::CppOccurrenceClassifier::new(&content))
            })
            .as_ref()
    }

    pub(super) fn primary_range(
        &mut self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Option<Range> {
        let classifier = if language_for_target(unit) == Language::Cpp && unit.is_callable() {
            self.classifier(analyzer, unit.source())
        } else {
            None
        };
        primary_range_with_cpp_classifier(analyzer, unit, classifier)
    }

    pub(super) fn occurrence_role(
        &mut self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        range: &Range,
    ) -> Option<String> {
        if language_for_target(unit) != Language::Cpp || !unit.is_callable() {
            return None;
        }
        self.classifier(analyzer, unit.source())
            .and_then(|classifier| classifier.classify(unit, range).api_label())
            .map(str::to_string)
    }
}

#[derive(Default)]
pub(super) struct DefinitionCandidateRenderCache {
    contexts: HashMap<ProjectFile, Option<DeclarationNameRangeContext>>,
    cpp_identity: CppIdentityRenderCache,
}

impl DefinitionCandidateRenderCache {
    fn exact_display_range(
        context: &DeclarationNameRangeContext,
        mut name_range: Range,
    ) -> (Range, (usize, usize)) {
        let start_column = crate::text_utils::line_column_for_offset(
            context.content(),
            context.line_starts(),
            name_range.start_byte,
        )
        .1;
        let end_column = crate::text_utils::line_column_for_offset(
            context.content(),
            context.line_starts(),
            name_range.end_byte,
        )
        .1;
        name_range.start_line += 1;
        name_range.end_line += 1;
        (name_range, (start_column, end_column))
    }

    fn display_range(
        &mut self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Option<(Range, Option<(usize, usize)>)> {
        let context = self
            .contexts
            .entry(unit.source().clone())
            .or_insert_with(|| load_declaration_name_context(analyzer, unit.source()));
        let name_range = context.as_ref().and_then(|context| {
            if language_for_target(unit) == Language::Cpp && unit.is_callable() {
                self.cpp_identity
                    .primary_range(analyzer, unit)
                    .and_then(|range| context.name_range_for_declaration(unit, range))
            } else {
                context.name_range(analyzer, unit)
            }
        });
        if let (Some(context), Some(name_range)) = (context.as_ref(), name_range) {
            let (name_range, columns) = Self::exact_display_range(context, name_range);
            return Some((name_range, Some(columns)));
        }
        Some((self.cpp_identity.primary_range(analyzer, unit)?, None))
    }

    pub(super) fn navigation_display_range(
        &mut self,
        analyzer: &dyn IAnalyzer,
        target: &crate::analyzer::usages::get_definition::NavigationTarget,
    ) -> Option<(Range, Option<(usize, usize)>)> {
        let Some(declaration_range) = target.declaration_range else {
            return self.display_range(analyzer, &target.code_unit);
        };
        let context = self
            .contexts
            .entry(target.code_unit.source().clone())
            .or_insert_with(|| load_declaration_name_context(analyzer, target.code_unit.source()));
        let name_range = context.as_ref().and_then(|context| {
            context.name_range_for_declaration(&target.code_unit, declaration_range)
        });
        if let (Some(context), Some(name_range)) = (context.as_ref(), name_range) {
            let (name_range, columns) = Self::exact_display_range(context, name_range);
            return Some((name_range, Some(columns)));
        }
        Some((declaration_range, None))
    }

    fn identity_metadata(
        &mut self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        range: &Range,
    ) -> (Option<String>, Option<String>) {
        if language_for_target(unit) != Language::Cpp || !unit.is_callable() {
            return (None, None);
        }
        let canonical_selector = self.cpp_identity.canonical_selector(analyzer, unit);
        let occurrence_role = self.cpp_identity.occurrence_role(analyzer, unit, range);
        (canonical_selector, occurrence_role)
    }

    fn candidate_from_range(
        &mut self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        range: Range,
        identity_range: &Range,
        columns: Option<(usize, usize)>,
    ) -> DefinitionCandidate {
        let (canonical_selector, occurrence_role) =
            self.identity_metadata(analyzer, unit, identity_range);
        let mut candidate = definition_candidate_from_range_base(analyzer, unit, range, columns);
        candidate.canonical_selector = canonical_selector;
        candidate.occurrence_role = occurrence_role;
        candidate
    }
}

pub(super) fn definition_candidates(
    analyzer: &dyn IAnalyzer,
    units: &[CodeUnit],
) -> Vec<DefinitionCandidate> {
    let mut render_cache = DefinitionCandidateRenderCache::default();
    definition_candidates_with_cache(analyzer, units, &mut render_cache)
}

pub(super) fn definition_candidates_with_cache(
    analyzer: &dyn IAnalyzer,
    units: &[CodeUnit],
    render_cache: &mut DefinitionCandidateRenderCache,
) -> Vec<DefinitionCandidate> {
    units
        .iter()
        .filter_map(|unit| definition_candidate_with_cache(analyzer, unit, render_cache))
        .collect()
}

pub(super) fn navigation_candidates_with_cache(
    analyzer: &dyn IAnalyzer,
    targets: &[crate::analyzer::usages::get_definition::NavigationTarget],
    render_cache: &mut DefinitionCandidateRenderCache,
) -> Vec<DefinitionCandidate> {
    targets
        .iter()
        .filter_map(|target| {
            let (range, columns) = render_cache.navigation_display_range(analyzer, target)?;
            let identity_range = target.declaration_range.as_ref().cloned().or_else(|| {
                render_cache
                    .cpp_identity
                    .primary_range(analyzer, &target.code_unit)
            })?;
            Some(render_cache.candidate_from_range(
                analyzer,
                &target.code_unit,
                range,
                &identity_range,
                columns,
            ))
        })
        .collect()
}

pub(super) fn definition_candidate(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Option<DefinitionCandidate> {
    definition_candidate_with_cache(
        analyzer,
        unit,
        &mut DefinitionCandidateRenderCache::default(),
    )
}

pub(super) fn definition_candidate_with_cache(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    render_cache: &mut DefinitionCandidateRenderCache,
) -> Option<DefinitionCandidate> {
    let (range, columns) = render_cache.display_range(analyzer, unit)?;
    let identity_range = render_cache.cpp_identity.primary_range(analyzer, unit)?;
    Some(render_cache.candidate_from_range(analyzer, unit, range, &identity_range, columns))
}

#[cfg(test)]
pub(super) fn definition_candidate_from_range(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    range: Range,
    columns: Option<(usize, usize)>,
) -> DefinitionCandidate {
    DefinitionCandidateRenderCache::default()
        .candidate_from_range(analyzer, unit, range, &range, columns)
}

fn definition_candidate_from_range_base(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    range: Range,
    columns: Option<(usize, usize)>,
) -> DefinitionCandidate {
    let language = language_for_target(unit);
    let name = if language == Language::CSharp {
        crate::analyzer::common::display_identifier_for_target(unit)
    } else {
        unit.identifier().to_string()
    };
    DefinitionCandidate {
        name,
        fqn: Some(unit.fq_name()),
        path: rel_path_string(unit.source()),
        start_line: range.start_line,
        start_column: columns.map(|(start, _)| start),
        end_line: range.end_line,
        end_column: columns.map(|(_, end)| end),
        kind: code_unit_kind_name(unit.kind()).to_string(),
        signature: unit
            .signature()
            .map(str::to_string)
            .or_else(|| analyzer.signatures(unit).first().cloned()),
        language: language_name(language),
        canonical_selector: None,
        occurrence_role: None,
    }
}

#[derive(Debug)]
pub(super) enum SelectableDefinitionResolution {
    Resolved(Vec<CodeUnit>),
    Ambiguous(AmbiguousSymbol),
    NotFound(NotFoundInput),
}

pub(super) enum DefinitionSelector<'a> {
    Name(&'a str),
    FileAnchored { anchor: String, lookup: &'a str },
}

pub(super) enum PathQualifiedSelector<'a> {
    Resolved { anchor: String, lookup: &'a str },
    AmbiguousPath(AmbiguousPathInput),
}

pub(super) fn exact_codeunit_resolution(
    analyzer: &dyn IAnalyzer,
    input: &str,
) -> CodeUnitResolution {
    // A bare terminal name must see same-named members so a lone top-level
    // namesake cannot silently win over a hidden member (#1057). The member-aware
    // fuzzy resolver unions the exact top-level hit with identifier-indexed
    // members and decides Resolved vs Ambiguous; qualified/multi-segment names
    // keep the exact-first path so canonical `/`- or `::`-bearing symbols (Go
    // import paths, `fmt::formatter`) are never misrouted as file patterns.
    if is_bare_symbol_query(analyzer, input) {
        return resolve_codeunit_fuzzy(analyzer, input);
    }
    let units = resolve_codeunit_exact(analyzer, input);
    if units.is_empty() {
        CodeUnitResolution::NotFound
    } else {
        CodeUnitResolution::Resolved(units)
    }
}

pub(super) fn exact_then_fuzzy_codeunit_resolution(
    analyzer: &dyn IAnalyzer,
    input: &str,
) -> CodeUnitResolution {
    let exact = resolve_codeunit_exact(analyzer, input);
    if exact.is_empty() {
        resolve_codeunit_fuzzy(analyzer, input)
    } else {
        CodeUnitResolution::Resolved(exact)
    }
}

/// Resolve `lookup` with every resolution stage scoped to the anchor file of
/// a `path#symbol` selector. Global-first resolution short-circuits on a
/// top-level namesake anywhere in the workspace, and members are invisible
/// to the exact/short-name stages (their short names are owner-qualified),
/// so an in-file member was hidden whenever a same-named top-level symbol
/// existed elsewhere — `path#terminal` reported not_found on the very file
/// it named (issue #1056). Scoping every stage to the anchor file resolves
/// members by terminal name while preserving top-level-wins priority within
/// the file; `path#qualified` behavior is unchanged.
pub(super) fn anchor_scoped_codeunit_resolution(
    analyzer: &dyn IAnalyzer,
    anchor: &str,
    lookup: &str,
) -> CodeUnitResolution {
    resolve_codeunit_fuzzy_with(analyzer, lookup, |unit| {
        rel_path_string(unit.source()) == anchor
    })
}

/// Resolve a symbol input into one selectable definition group. A file anchor
/// (`src/plugin/relativeTime/index.js#default`) narrows same-name module-scoped
/// definitions to the exact relative path before grouping; a bare name that
/// spans multiple selectors is ambiguous and returns requestable selectors.
pub(super) fn resolve_selectable_definitions(
    analyzer: &dyn IAnalyzer,
    input: &str,
    resolve: impl Fn(&dyn IAnalyzer, &str) -> CodeUnitResolution,
) -> SelectableDefinitionResolution {
    let selector = split_definition_selector_with_resolver(input, |anchor| {
        matches!(
            WorkspaceFileResolver::new(analyzer.project()).resolve_literal(anchor),
            ResolvedFileInput::File(_)
        )
    });
    let (mut anchor, mut lookup) = match selector {
        DefinitionSelector::Name(name) => (None, name),
        DefinitionSelector::FileAnchored { anchor, lookup } => (Some(anchor), lookup),
    };
    let mut resolution = match &anchor {
        Some(anchor) => anchor_scoped_codeunit_resolution(analyzer, anchor, lookup),
        None => resolve(analyzer, lookup),
    };
    if matches!(resolution, CodeUnitResolution::NotFound)
        && anchor.is_none()
        && let Some(path_selector) = split_path_qualified_definition_selector(analyzer, input)
    {
        match path_selector {
            PathQualifiedSelector::Resolved {
                anchor: path_anchor,
                lookup: path_lookup,
            } => {
                resolution = anchor_scoped_codeunit_resolution(analyzer, &path_anchor, path_lookup);
                anchor = Some(path_anchor);
                lookup = path_lookup;
            }
            PathQualifiedSelector::AmbiguousPath(item) => {
                return SelectableDefinitionResolution::NotFound(not_found_input(
                    input,
                    Some(format!(
                        "path is ambiguous; retry with one of: {}",
                        item.matches.join(", ")
                    )),
                ));
            }
        }
    }
    let code_units = match resolution {
        CodeUnitResolution::Resolved(code_units) => code_units,
        CodeUnitResolution::Ambiguous(matches) => matches,
        CodeUnitResolution::NotFound => {
            let Some(anchor) = &anchor else {
                return SelectableDefinitionResolution::NotFound(symbol_not_found_input(input));
            };
            // Nothing resolved in the anchor file. Resolve globally once
            // for diagnostics: candidates elsewhere mean the symbol exists
            // but not here (the anchor recovery note's case); nothing
            // anywhere is a genuine not-found.
            let global_candidates = match resolve(analyzer, lookup) {
                CodeUnitResolution::Resolved(units) | CodeUnitResolution::Ambiguous(units) => units,
                CodeUnitResolution::NotFound => Vec::new(),
            };
            if global_candidates.is_empty() {
                return SelectableDefinitionResolution::NotFound(symbol_not_found_input(input));
            }
            let candidate_names = if looks_like_extensionless_path_anchor(anchor) {
                code_unit_match_names(analyzer, &global_candidates)
            } else {
                Vec::new()
            };
            return SelectableDefinitionResolution::NotFound(symbol_source_anchor_not_found_input(
                input,
                anchor,
                lookup,
                &candidate_names,
            ));
        }
    };

    // Anchored resolution is already scoped to the anchor file; the filter is
    // a no-op safeguard and keeps the unanchored path untouched.
    let code_units = match anchor {
        Some(anchor) => code_units
            .into_iter()
            .filter(|unit| rel_path_string(unit.source()) == anchor)
            .collect(),
        None => code_units,
    };

    let groups = distinct_definitions(analyzer, code_units);
    match groups.as_slice() {
        [] => SelectableDefinitionResolution::NotFound(symbol_not_found_input(input)),
        [(_, _)] => SelectableDefinitionResolution::Resolved(
            groups.into_iter().flat_map(|(_, units)| units).collect(),
        ),
        _ => {
            let matches: Vec<String> = groups.into_iter().map(|(selector, _)| selector).collect();
            SelectableDefinitionResolution::Ambiguous(capped_ambiguous_symbol(input, matches))
        }
    }
}

pub(super) fn ambiguous_symbol_selector_note(matches: &[String]) -> Option<String> {
    matches.first().map(|example| {
        format!("Ambiguous; re-call with one selector from `matches` (e.g. {example}).")
    })
}

/// Build an [`AmbiguousSymbol`] from every distinct selector a bare name
/// resolved to, capping the rendered `matches` list at
/// [`AMBIGUOUS_SYMBOL_MATCH_LIMIT`]. The note always states the true total so
/// a truncated response is never mistaken for the complete candidate set.
pub(super) fn capped_ambiguous_symbol(target: &str, mut matches: Vec<String>) -> AmbiguousSymbol {
    let total = matches.len();
    let note = if total > AMBIGUOUS_SYMBOL_MATCH_LIMIT {
        matches.truncate(AMBIGUOUS_SYMBOL_MATCH_LIMIT);
        Some(format!(
            "Ambiguous ({total} candidates, showing {AMBIGUOUS_SYMBOL_MATCH_LIMIT}); refine with path#name or a qualified spelling."
        ))
    } else {
        ambiguous_symbol_selector_note(&matches)
    };
    AmbiguousSymbol {
        target: target.to_string(),
        matches,
        note,
    }
}

/// Split a definition selector into an optional file anchor and the name to
/// resolve. A plain input (`Anchor`) has no anchor; a file-anchored selector
/// (`charts/Anchor.ts#Anchor`), returned in a prior ambiguity result, picks one
/// of several same-named definitions.
pub(super) fn split_definition_selector(input: &str) -> DefinitionSelector<'_> {
    split_definition_selector_with_resolver(input, looks_like_path_selector_anchor)
}

/// File-aware split: `#`-bearing paths (marked's fixture
/// `bin-config#hash.js`) mean the first `#` is not always the anchor
/// boundary. Walk every split point and prefer the first whose anchor is a
/// real file; fall back to the plain parse when none checks out (the
/// `file.rs#r#type` raw-identifier case keeps its first-`#` split because
/// `file.rs` resolves).
pub(super) fn split_definition_selector_with_resolver<'a>(
    input: &'a str,
    anchor_is_file: impl Fn(&str) -> bool,
) -> DefinitionSelector<'a> {
    if input.matches('#').count() > 1 {
        for (index, _) in input.match_indices('#') {
            let (anchor, name) = input.split_at(index);
            let name = &name[1..];
            if !anchor.is_empty()
                && !name.is_empty()
                && looks_like_path_selector_anchor(anchor)
                && anchor_is_file(anchor)
            {
                return DefinitionSelector::FileAnchored {
                    anchor: anchor.to_string(),
                    lookup: name,
                };
            }
        }
    }
    match input.split_once('#') {
        Some((anchor, name))
            if !anchor.is_empty()
                && !name.is_empty()
                && looks_like_path_selector_anchor(anchor) =>
        {
            DefinitionSelector::FileAnchored {
                anchor: anchor.to_string(),
                lookup: name,
            }
        }
        _ => DefinitionSelector::Name(input),
    }
}

pub(super) fn split_path_qualified_definition_selector<'a>(
    analyzer: &dyn IAnalyzer,
    input: &'a str,
) -> Option<PathQualifiedSelector<'a>> {
    let resolver = WorkspaceFileResolver::new(analyzer.project());
    for separator in ["::", ":"] {
        let Some((path, name)) = input.split_once(separator) else {
            continue;
        };
        let path = path.trim();
        let name = name.trim();
        if path.is_empty() || name.is_empty() {
            continue;
        }
        if !looks_like_path_selector_anchor(path) {
            continue;
        }
        return Some(match resolver.resolve_literal(path) {
            ResolvedFileInput::File(file) => PathQualifiedSelector::Resolved {
                anchor: rel_path_string(&file),
                lookup: name,
            },
            ResolvedFileInput::Ambiguous(item) => PathQualifiedSelector::AmbiguousPath(item),
            ResolvedFileInput::NotFound(_) => continue,
        });
    }

    if let Some(selector) = dotted_file_symbol_selector(analyzer, input) {
        return Some(selector);
    }

    None
}

pub(super) fn looks_like_path_selector_anchor(path: &str) -> bool {
    if path.contains('/') || path.contains('\\') {
        return true;
    }
    let Some(rel) = workspace_rel_path(path) else {
        return false;
    };
    rel.file_name()
        .and_then(|name| std::path::Path::new(name).extension())
        .is_some_and(|extension| !extension.is_empty())
}

pub(super) fn unsupported_path_qualified_scan_symbol(
    resolver: &WorkspaceFileResolver,
    input: &str,
) -> Option<NotFoundInput> {
    let (path, symbol) = input.trim().split_once("::")?;
    let path = path.trim();
    let symbol = symbol.trim();
    if path.is_empty() || symbol.is_empty() {
        return None;
    }

    match resolver.resolve_literal(path) {
        ResolvedFileInput::File(file) => {
            let path = rel_path_string(&file);
            Some(not_found_input(
                input,
                Some(format!(
                    "unsupported path::symbol selector; re-call scan_usages_by_reference with symbols:[\"{symbol}\"] and paths:[\"{path}\"]"
                )),
            ))
        }
        ResolvedFileInput::Ambiguous(item) => Some(not_found_input(
            input,
            Some(format!(
                "unsupported path::symbol selector; `{}` is ambiguous; choose one path from {} and re-call scan_usages_by_reference with symbols:[\"{symbol}\"] and paths:[\"chosen/path\"]",
                item.input,
                path_match_sample(&item.matches)
            )),
        )),
        ResolvedFileInput::NotFound(_) => None,
    }
}

pub(super) fn path_match_sample(matches: &[String]) -> String {
    let sample = matches
        .iter()
        .take(SCAN_USAGES_PATH_SELECTOR_MATCH_LIMIT)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if matches.len() > SCAN_USAGES_PATH_SELECTOR_MATCH_LIMIT {
        format!(
            "{sample} (showing first {SCAN_USAGES_PATH_SELECTOR_MATCH_LIMIT} of {})",
            matches.len()
        )
    } else {
        sample
    }
}

/// The preferred selector for one definition. Module-scoped ecosystems (JS/TS)
/// are always file-anchored. [`distinct_definitions`] also anchors other
/// ecosystems when the same FQN spans multiple language/file domains.
pub(super) fn definition_selector(unit: &CodeUnit) -> String {
    if UsageEcosystem::of(language_for_target(unit)).is_module_scoped() {
        file_anchored_definition_selector(unit)
    } else {
        unit.fq_name()
    }
}

pub(super) fn file_anchored_definition_selector(unit: &CodeUnit) -> String {
    format!("{}#{}", rel_path_string(unit.source()), unit.fq_name())
}

fn cpp_callable_family_selectors(
    analyzer: &dyn IAnalyzer,
    same_signature: &[CodeUnit],
) -> HashMap<CodeUnit, String> {
    let roles: HashMap<_, _> = same_signature
        .iter()
        .map(|unit| (unit.clone(), cpp_callable_unit_role(analyzer, unit)))
        .collect();
    let declarations: Vec<_> = same_signature
        .iter()
        .filter(|unit| {
            matches!(roles.get(*unit), Some(CppCallableUnitRole::DeclarationOnly))
                && matches!(
                    cpp_indexed_callable_linkage(analyzer, unit),
                    Some(CallableLinkage::External)
                )
        })
        .collect();
    let definitions: Vec<_> = same_signature
        .iter()
        .filter(|unit| {
            matches!(
                roles.get(*unit),
                Some(CppCallableUnitRole::Definition | CppCallableUnitRole::Both)
            ) && matches!(
                cpp_indexed_callable_linkage(analyzer, unit),
                Some(CallableLinkage::External)
            )
        })
        .collect();

    let mut definitions_by_declaration: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
    for declaration in declarations {
        let related = definitions
            .iter()
            .filter(|definition| {
                cpp_callable_definitions_share_identity_evidence(analyzer, declaration, definition)
            })
            .map(|definition| (*definition).clone())
            .collect();
        definitions_by_declaration.insert(declaration.clone(), related);
    }

    let mut canonical_declaration_by_definition: HashMap<CodeUnit, CodeUnit> = HashMap::default();
    for definition in definitions {
        let mut declarations: Vec<_> = definitions_by_declaration
            .iter()
            .filter(|(_, related)| related.as_slice() == [(*definition).clone()])
            .map(|(declaration, _)| declaration.clone())
            .collect();
        declarations.sort_by_key(|candidate| {
            (
                rel_path_string(candidate.source()),
                analyzer
                    .ranges(candidate)
                    .into_iter()
                    .map(|range| range.start_byte)
                    .min()
                    .unwrap_or(usize::MAX),
            )
        });
        if let Some(declaration) = declarations.into_iter().next() {
            canonical_declaration_by_definition.insert((*definition).clone(), declaration);
        }
    }

    same_signature
        .iter()
        .map(|unit| {
            let canonical = match roles.get(unit) {
                Some(CppCallableUnitRole::Definition) => canonical_declaration_by_definition
                    .get(unit)
                    .map(file_anchored_definition_selector),
                Some(CppCallableUnitRole::DeclarationOnly) => {
                    definitions_by_declaration.get(unit).and_then(|related| {
                        let [definition] = related.as_slice() else {
                            return None;
                        };
                        canonical_declaration_by_definition
                            .get(definition)
                            .map(file_anchored_definition_selector)
                    })
                }
                Some(CppCallableUnitRole::Both | CppCallableUnitRole::Unknown) | None => None,
            }
            .unwrap_or_else(|| file_anchored_definition_selector(unit));
            (unit.clone(), canonical)
        })
        .collect()
}

fn cpp_canonical_selectors(
    analyzer: &dyn IAnalyzer,
    units: &[CodeUnit],
) -> HashMap<CodeUnit, String> {
    let mut by_fqn_signature: HashMap<(String, Option<String>), Vec<CodeUnit>> = HashMap::default();
    for unit in units {
        if language_for_target(unit) == Language::Cpp && unit.is_callable() {
            by_fqn_signature
                .entry((unit.fq_name(), unit.signature().map(str::to_string)))
                .or_default()
                .push(unit.clone());
        }
    }

    let mut family_by_unit = HashMap::default();
    let mut families_by_fqn_signature: HashMap<(String, Option<String>), HashSet<String>> =
        HashMap::default();
    for ((fqn, signature), members) in &by_fqn_signature {
        for (member, family) in cpp_callable_family_selectors(analyzer, members) {
            family_by_unit.insert(member, family.clone());
            families_by_fqn_signature
                .entry((fqn.clone(), signature.clone()))
                .or_default()
                .insert(family);
        }
    }

    let mut collision_fqns = HashSet::default();
    for ((fqn, _), families) in &families_by_fqn_signature {
        if families.len() > 1 {
            collision_fqns.insert(fqn.clone());
        }
    }

    let mut canonical_by_fqn = HashMap::default();
    for unit in units {
        if language_for_target(unit) != Language::Cpp
            || !unit.is_callable()
            || collision_fqns.contains(&unit.fq_name())
        {
            continue;
        }
        let family = family_by_unit
            .get(unit)
            .cloned()
            .unwrap_or_else(|| file_anchored_definition_selector(unit));
        let prefer = matches!(
            cpp_callable_unit_role(analyzer, unit),
            CppCallableUnitRole::DeclarationOnly
        );
        let entry = canonical_by_fqn
            .entry(unit.fq_name())
            .or_insert_with(|| (prefer, family.clone()));
        if (prefer && !entry.0) || (prefer == entry.0 && family < entry.1) {
            *entry = (prefer, family);
        }
    }

    let mut out = HashMap::default();
    for unit in units {
        if language_for_target(unit) != Language::Cpp || !unit.is_callable() {
            continue;
        }
        let canonical = if collision_fqns.contains(&unit.fq_name()) {
            family_by_unit
                .get(unit)
                .cloned()
                .unwrap_or_else(|| file_anchored_definition_selector(unit))
        } else {
            canonical_by_fqn
                .get(&unit.fq_name())
                .map(|(_, selector)| selector.clone())
                .unwrap_or_else(|| file_anchored_definition_selector(unit))
        };
        out.insert(unit.clone(), canonical);
    }
    out
}

/// Partition resolved overloads into distinct selectable definitions, preserving
/// first-seen order. Overloads of one symbol share a selector and scan together.
/// An FQN present in multiple language/file domains is file-anchored in every
/// domain so each ambiguity candidate can be re-queried without looping.
pub(super) fn distinct_definitions(
    analyzer: &dyn IAnalyzer,
    overloads: Vec<CodeUnit>,
) -> Vec<(String, Vec<CodeUnit>)> {
    // An FQN's units are file-anchored into distinct `path#fqn` candidates for
    // either of two reasons:
    //
    //  1. Cross-domain: the FQN spans more than one (language, module-scoped
    //     file) domain — the pre-existing module-scoped/cross-language rule.
    //
    //  2. Genuine cross-file duplicate (#1057): within one FQN, some *callable
    //     signature* is declared in more than one distinct file. That is the
    //     duplicate shape — scala-2/scala-3 twins, Go build-tag twins, C#
    //     partial-class parts (which share an empty signature key). Pure
    //     overload sets — each *differing* signature living in a single file —
    //     are deliberately NOT split: the codebase models overloads under one
    //     FQN, and every surface (get_symbol_sources / get_summaries /
    //     scan_usages) keeps merging their call sites under one selector.
    //
    // The signature key is `IAnalyzer::signatures(unit)` (the parameter-bearing
    // overload label list), NOT `CodeUnit::signature()`: the latter is `None`
    // for the top-level functions and classes that reach this grouping, so it
    // cannot tell an arity overload apart from a twin. `signatures(unit)`
    // returns distinct labels for overloads (`compute(value: Int)` vs
    // `compute(left: Int, right: Int)`) and an identical label (or empty list)
    // for twins/partial parts, which is exactly the discriminator we need.
    //
    // A unique FQN in one file, and same-file overloads, satisfy neither reason
    // and keep their existing `definition_selector` rendering (module-scoped
    // languages still render file-anchored there).
    let mut domains_by_fqn: HashMap<String, HashSet<(Language, Option<String>)>> =
        HashMap::default();
    let cpp_canonical = cpp_canonical_selectors(analyzer, &overloads);
    let mut files_by_fqn_signature: HashMap<(String, Vec<String>), HashSet<String>> =
        HashMap::default();
    for unit in &overloads {
        let language = language_for_target(unit);
        let module_path = UsageEcosystem::of(language)
            .is_module_scoped()
            .then(|| rel_path_string(unit.source()));
        domains_by_fqn
            .entry(unit.fq_name())
            .or_default()
            .insert((language, module_path));
        let signature = if language == Language::Cpp && unit.is_callable() {
            unit.signature()
                .map(|signature| vec![signature.to_string()])
                .unwrap_or_default()
        } else {
            analyzer.signatures(unit)
        };
        files_by_fqn_signature
            .entry((unit.fq_name(), signature))
            .or_default()
            .insert(
                cpp_canonical
                    .get(unit)
                    .cloned()
                    .unwrap_or_else(|| rel_path_string(unit.source())),
            );
    }

    // FQNs where some (identical) signature is declared in more than one file.
    let mut collision_split_fqns: HashSet<String> = HashSet::default();
    for ((fqn, _signature), files) in &files_by_fqn_signature {
        if files.len() > 1 {
            collision_split_fqns.insert(fqn.clone());
        }
    }

    let mut groups: Vec<(String, Vec<CodeUnit>)> = Vec::new();
    for unit in overloads {
        let fqn = unit.fq_name();
        let cross_domain = domains_by_fqn
            .get(&fqn)
            .is_some_and(|domains| domains.len() > 1);
        let selector = if cross_domain || collision_split_fqns.contains(&fqn) {
            cpp_canonical
                .get(&unit)
                .cloned()
                .unwrap_or_else(|| file_anchored_definition_selector(&unit))
        } else {
            definition_selector(&unit)
        };
        match groups
            .iter_mut()
            .find(|(existing, _)| *existing == selector)
        {
            Some((_, units)) => units.push(unit),
            None => groups.push((selector, vec![unit])),
        }
    }
    groups
}

pub(super) fn prefer_exact_lookup_matches(overloads: Vec<CodeUnit>, lookup: &str) -> Vec<CodeUnit> {
    if overloads.iter().any(|unit| unit.fq_name() == lookup) {
        overloads
            .into_iter()
            .filter(|unit| unit.fq_name() == lookup)
            .collect()
    } else {
        overloads
    }
}

pub(super) fn code_unit_match_names(analyzer: &dyn IAnalyzer, matches: &[CodeUnit]) -> Vec<String> {
    distinct_definitions(analyzer, matches.to_vec())
        .into_iter()
        .map(|(selector, _)| selector)
        .collect()
}

pub(super) fn unsupported_selector_shape_guidance(
    analyzer: &dyn IAnalyzer,
    input: &str,
) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(anchor) = line_range_anchor_selector(trimmed) {
        return Some(format!(
            "`{}` is a line/range anchor, not a symbol selector. Use get_summaries or `{}` as a file target for an outline, or retry as path#symbol with a real symbol name.",
            anchor.anchor, anchor.file_path
        ));
    }
    let decoded = percent_decode(trimmed);
    if decoded != trimmed
        && let Some(anchor) = line_range_anchor_selector(&decoded)
    {
        return Some(format!(
            "`{trimmed}` contains a URL-encoded line/range anchor; decode it to `{decoded}`. Line/range anchors are not symbol selectors; use get_summaries or `{}` as a file target for an outline, or retry as path#symbol with a real symbol name.",
            anchor.file_path
        ));
    }
    if let Some(note) = invalid_file_anchored_selector_guidance(analyzer, trimmed) {
        return Some(note);
    }
    if selector_ends_with_go_module_scope_segment(trimmed) {
        return Some(format!(
            "`{GO_MODULE_SCOPE_SEGMENT}` is an outline grouping for Go module-scope declarations, not a selectable symbol. Use a file path as a file target for an outline, or select a member as `pkg.{GO_MODULE_SCOPE_SEGMENT}.<name>` or `pkg.<name>`."
        ));
    }
    if let Some(name) = signature_string_selector_name(trimmed) {
        return Some(format!(
            "signature strings are not supported as symbol selectors; retry with the bare function name `{name}`"
        ));
    }
    if let Some((symbol, path)) = malformed_at_joined_selector(trimmed) {
        return Some(format!(
            "`symbol@path` selectors are not supported; retry with the bare symbol `{symbol}` plus the `paths` parameter `{path}`, or use `{path}#{symbol}`"
        ));
    }
    if let Some(PathQualifiedSelector::Resolved {
        anchor: path,
        lookup: symbol,
    }) = dotted_file_symbol_selector(analyzer, trimmed)
    {
        return Some(format!(
            "`{symbol}` is not a symbol in `{path}`; use `{path}` as a file target for an outline, or call get_summaries on `{path}`"
        ));
    }
    if looks_like_absolute_path(trimmed) {
        return Some(absolute_path_selector_guidance(analyzer, trimmed));
    }
    None
}

pub(super) fn selector_ends_with_go_module_scope_segment(input: &str) -> bool {
    input
        .rsplit_once('.')
        .is_some_and(|(_, segment)| segment == GO_MODULE_SCOPE_SEGMENT)
}

pub(super) struct LineRangeAnchorSelector<'a> {
    file_path: &'a str,
    anchor: &'a str,
}

pub(super) fn line_range_anchor_selector(input: &str) -> Option<LineRangeAnchorSelector<'_>> {
    let (file_path, anchor) = input
        .rsplit_once("::")
        .or_else(|| input.rsplit_once('#'))
        .or_else(|| input.rsplit_once(':'))?;
    if file_path.is_empty() || anchor.is_empty() {
        return None;
    }
    is_line_range_anchor(anchor).then_some(LineRangeAnchorSelector { file_path, anchor })
}

pub(super) fn is_line_range_anchor(anchor: &str) -> bool {
    if let Some(line) = anchor
        .strip_prefix("line ")
        .or_else(|| anchor.strip_prefix("Line "))
    {
        return !line.is_empty() && line.chars().all(|ch| ch.is_ascii_digit());
    }
    let Some((start, end)) = anchor.split_once('-') else {
        return is_line_anchor_part(anchor);
    };
    is_line_anchor_part(start) && is_line_anchor_part(end)
}

pub(super) fn invalid_file_anchored_selector_guidance(
    analyzer: &dyn IAnalyzer,
    input: &str,
) -> Option<String> {
    let (path, selector) = input.split_once('#')?;
    if path.is_empty() || selector.is_empty() {
        return None;
    }
    let file = match WorkspaceFileResolver::new(analyzer.project()).resolve_literal(path) {
        ResolvedFileInput::File(file) => file,
        ResolvedFileInput::Ambiguous(_) | ResolvedFileInput::NotFound(_) => return None,
    };
    let path = rel_path_string(&file);
    if let Some(shorter) = redundant_filename_selector(&file, selector) {
        return Some(format!(
            "`{selector}` redundantly repeats the file name; retry `{path}#{shorter}`"
        ));
    }
    Some(format!(
        "`{selector}` is not a symbol selector for existing file `{path}`; use `{path}` as a file target for an outline, or retry `{path}#<symbol>` with a real symbol name"
    ))
}

pub(super) fn redundant_filename_selector<'a>(
    file: &ProjectFile,
    selector: &'a str,
) -> Option<&'a str> {
    let filename = file.rel_path().file_name()?.to_str()?;
    selector
        .strip_prefix(filename)?
        .strip_prefix('.')
        .filter(|shorter| !shorter.is_empty())
}

pub(super) fn looks_like_extensionless_path_anchor(anchor: &str) -> bool {
    let Some(path) = workspace_rel_path(anchor) else {
        return false;
    };
    (anchor.contains('/') || anchor.contains('\\'))
        && path
            .file_name()
            .is_some_and(|name| std::path::Path::new(name).extension().is_none())
}

pub(super) fn is_line_anchor_part(part: &str) -> bool {
    let digits = part
        .strip_prefix('L')
        .or_else(|| part.strip_prefix('l'))
        .unwrap_or(part);
    !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit())
}

pub(super) fn signature_string_selector_name(input: &str) -> Option<&str> {
    if !input.contains('(') || !input.contains(')') || !input.chars().any(char::is_whitespace) {
        return None;
    }
    let before_paren = input.split_once('(')?.0.trim_end();
    let name_start = before_paren
        .char_indices()
        .rev()
        .find_map(|(index, ch)| (!is_symbol_identifier_char(ch)).then_some(index + ch.len_utf8()))
        .unwrap_or(0);
    let name = before_paren[name_start..].trim();
    (!name.is_empty()).then_some(name)
}

pub(super) fn is_symbol_identifier_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'
}

pub(super) fn malformed_at_joined_selector(input: &str) -> Option<(&str, &str)> {
    let (symbol, path) = input.split_once('@')?;
    if symbol.is_empty() || path.is_empty() || path.contains('@') {
        return None;
    }
    (looks_like_file_target(path) || path.contains('/') || path.contains('\\'))
        .then_some((symbol, path))
}

pub(super) fn dotted_file_symbol_selector<'a>(
    analyzer: &dyn IAnalyzer,
    input: &'a str,
) -> Option<PathQualifiedSelector<'a>> {
    let resolver = WorkspaceFileResolver::new(analyzer.project());
    for (separator, _) in input.rmatch_indices('.') {
        let path_candidate = &input[..separator];
        let symbol = &input[separator + 1..];
        if path_candidate.is_empty() || symbol.is_empty() || likely_file_target_extension(symbol) {
            continue;
        }
        match resolver.resolve_literal(path_candidate) {
            ResolvedFileInput::File(file) => {
                return Some(PathQualifiedSelector::Resolved {
                    anchor: rel_path_string(&file),
                    lookup: symbol,
                });
            }
            ResolvedFileInput::Ambiguous(item) => {
                return Some(PathQualifiedSelector::AmbiguousPath(item));
            }
            ResolvedFileInput::NotFound(_) => {}
        }
    }
    None
}

pub(super) fn looks_like_absolute_path(input: &str) -> bool {
    input.starts_with('/') || input.starts_with('\\') || has_drive_letter_prefix(input)
}

pub(super) fn absolute_path_selector_guidance(analyzer: &dyn IAnalyzer, input: &str) -> String {
    if let Some(relative_path) = unique_absolute_suffix_match(analyzer, input) {
        return format!(
            "this looks like an absolute path; strip the workspace-root prefix and retry `{relative_path}`"
        );
    }
    "this looks like an absolute path; strip the workspace-root prefix and retry the workspace-relative path".to_string()
}

pub(super) fn unique_absolute_suffix_match(
    analyzer: &dyn IAnalyzer,
    input: &str,
) -> Option<String> {
    let normalized = normalize_pattern(input);
    let matches: Vec<_> = analyzer
        .analyzed_files()
        .into_iter()
        .map(|file| rel_path_string(&file))
        .filter(|relative| normalized.ends_with(relative))
        .collect();
    match matches.as_slice() {
        [relative] => Some(relative.clone()),
        _ => None,
    }
}

pub(super) fn looks_like_go_receiver_selector(target: &str) -> bool {
    let trimmed = target.trim();
    trimmed.starts_with('(') || trimmed.contains(".(")
}

pub(super) fn likely_file_target_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "c" | "cc"
            | "cpp"
            | "cs"
            | "css"
            | "cxx"
            | "dart"
            | "go"
            | "gradle"
            | "groovy"
            | "h"
            | "hpp"
            | "htm"
            | "html"
            | "java"
            | "js"
            | "json"
            | "jsx"
            | "kt"
            | "kts"
            | "less"
            | "m"
            | "md"
            | "mm"
            | "php"
            | "properties"
            | "py"
            | "rb"
            | "rs"
            | "sass"
            | "scala"
            | "scss"
            | "sh"
            | "sql"
            | "svelte"
            | "swift"
            | "toml"
            | "ts"
            | "tsx"
            | "txt"
            | "vue"
            | "xml"
            | "yaml"
            | "yml"
    )
}

pub(super) fn language_name(language: Language) -> String {
    match language {
        Language::None => "none",
        Language::Java => "java",
        Language::Go => "go",
        Language::Cpp => "cpp",
        Language::JavaScript => "javascript",
        Language::TypeScript => "typescript",
        Language::Python => "python",
        Language::Rust => "rust",
        Language::Php => "php",
        Language::Scala => "scala",
        Language::CSharp => "csharp",
        Language::Ruby => "ruby",
    }
    .to_string()
}
