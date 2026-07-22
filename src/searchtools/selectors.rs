use super::navigation::*;
use super::*;

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
pub(super) struct DefinitionCandidateRenderCache {
    contexts: HashMap<ProjectFile, Option<DeclarationNameRangeContext>>,
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
        let name_range = context
            .as_ref()
            .and_then(|context| context.name_range(analyzer, unit));
        if let (Some(context), Some(name_range)) = (context.as_ref(), name_range) {
            let (name_range, columns) = Self::exact_display_range(context, name_range);
            return Some((name_range, Some(columns)));
        }
        Some((primary_range(analyzer, unit)?, None))
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
            Some(definition_candidate_from_range(
                analyzer,
                &target.code_unit,
                range,
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
    Some(definition_candidate_from_range(
        analyzer, unit, range, columns,
    ))
}

pub(super) fn definition_candidate_from_range(
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
    let selector = split_definition_selector(input);
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
            SelectableDefinitionResolution::Ambiguous(AmbiguousSymbol {
                target: input.to_string(),
                note: ambiguous_symbol_selector_note(&matches),
                matches,
            })
        }
    }
}

pub(super) fn ambiguous_symbol_selector_note(matches: &[String]) -> Option<String> {
    matches.first().map(|example| {
        format!("Ambiguous; re-call with one selector from `matches` (e.g. {example}).")
    })
}

/// Split a definition selector into an optional file anchor and the name to
/// resolve. A plain input (`Anchor`) has no anchor; a file-anchored selector
/// (`charts/Anchor.ts#Anchor`), returned in a prior ambiguity result, picks one
/// of several same-named definitions.
pub(super) fn split_definition_selector(input: &str) -> DefinitionSelector<'_> {
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
        files_by_fqn_signature
            .entry((unit.fq_name(), analyzer.signatures(unit)))
            .or_default()
            .insert(rel_path_string(unit.source()));
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
            file_anchored_definition_selector(&unit)
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
