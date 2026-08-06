use super::navigation::*;
use super::selectors::*;
use super::summaries::*;
use super::*;

#[derive(Debug, Clone, Serialize)]
pub struct SymbolSourcesResult {
    pub sources: Vec<SourceBlock>,
    pub not_found: Vec<NotFoundInput>,
    pub ambiguous: Vec<AmbiguousSymbol>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ambiguous_paths: Vec<AmbiguousPathInput>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub too_broad: Vec<TooBroadScope>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceBlock {
    pub label: String,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurrence_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_model: Option<crate::analyzer::semantic_model::SemanticModelProvenance>,
}

pub(super) enum SourceLookupOutcome {
    Found(Vec<SourceBlock>),
    NotFound(NotFoundInput),
    Ambiguous(AmbiguousSymbol),
    AmbiguousPath(AmbiguousPathInput),
    TooBroad(TooBroadScope),
}

pub(super) fn source_blocks_for_resolved_units(
    analyzer: &dyn IAnalyzer,
    code_units: &[CodeUnit],
) -> Vec<SourceBlock> {
    let mut blocks = Vec::new();
    let mut module_units = Vec::new();
    let mut cpp_identity = CppIdentityRenderCache::default();

    for code_unit in code_units {
        if is_file_listing_target(code_unit) {
            module_units.push(code_unit.clone());
            continue;
        }

        let source_blocks =
            source_blocks_for_code_unit_with_cache(analyzer, code_unit, true, &mut cpp_identity);
        if source_blocks.is_empty() && is_scala_object_like(code_unit) {
            module_units.push(code_unit.clone());
        } else {
            blocks.extend(source_blocks);
        }
    }

    blocks.extend(module_file_listing_blocks(analyzer, &module_units));
    blocks
}

fn prefer_definition_source_blocks(blocks: Vec<SourceBlock>) -> Vec<SourceBlock> {
    let definition_groups: HashSet<_> = blocks
        .iter()
        .filter(|block| block.occurrence_role.as_deref() == Some("definition"))
        .filter_map(|block| block.canonical_selector.clone())
        .collect();
    blocks
        .into_iter()
        .filter(|block| {
            block.canonical_selector.as_ref().is_none_or(|selector| {
                !definition_groups.contains(selector)
                    || block.occurrence_role.as_deref() == Some("definition")
            })
        })
        .collect()
}

fn preferred_source_blocks_for_resolved_units(
    analyzer: &dyn IAnalyzer,
    code_units: &[CodeUnit],
) -> Vec<SourceBlock> {
    prefer_definition_source_blocks(source_blocks_for_resolved_units(analyzer, code_units))
}

pub fn symbol_source_candidate_files(
    analyzer: &dyn IAnalyzer,
    result: &SymbolSourcesResult,
) -> BTreeSet<ProjectFile> {
    let resolver = WorkspaceFileResolver::for_analyzer(analyzer);
    let mut files = BTreeSet::new();

    for source in &result.sources {
        if let Some(rel_path) = workspace_rel_path(&source.path) {
            files.insert(ProjectFile::new(
                analyzer.project().root().to_path_buf(),
                rel_path,
            ));
        }
    }

    for selector in result.ambiguous.iter().flat_map(|item| item.matches.iter()) {
        if let SelectableDefinitionResolution::Resolved(units) =
            resolve_selectable_definitions(analyzer, selector, exact_then_fuzzy_codeunit_resolution)
        {
            extend_candidate_unit_files(&mut files, units, None);
        }
    }

    for symbol in result
        .not_found
        .iter()
        .map(|item| item.input.trim())
        .filter(|symbol| !symbol.is_empty())
    {
        let (mut anchor, mut lookup) =
            match split_definition_selector_with_workspace_files(&resolver, symbol) {
                DefinitionSelector::Name(name) => (None, name),
                DefinitionSelector::FileAnchored { anchor, lookup } => {
                    if let ResolvedFileInput::File(file) = resolver.resolve_literal(&anchor) {
                        files.insert(file);
                    }
                    (Some(anchor), lookup)
                }
            };

        if anchor.is_none()
            && let Some(PathQualifiedSelector::Resolved {
                anchor: path_anchor,
                lookup: path_lookup,
            }) = split_path_qualified_definition_selector(analyzer, symbol)
        {
            if let ResolvedFileInput::File(file) = resolver.resolve_literal(&path_anchor) {
                files.insert(file);
            }
            anchor = Some(path_anchor);
            lookup = path_lookup;
        }

        let resolved = resolve_enclosing_codeunits(analyzer, lookup);
        extend_candidate_unit_files(&mut files, resolved, anchor.as_deref());
    }

    files
}

pub(super) fn extend_candidate_unit_files(
    files: &mut BTreeSet<ProjectFile>,
    units: Vec<CodeUnit>,
    anchor: Option<&str>,
) {
    files.extend(units.into_iter().filter_map(|unit| {
        anchor
            .is_none_or(|anchor| rel_path_string(unit.source()) == anchor)
            .then(|| unit.source().clone())
    }));
}

pub(super) fn resolve_file_anchored_symbol_sources(
    analyzer: &dyn IAnalyzer,
    input: &str,
    anchor: String,
    lookup: &str,
) -> SourceLookupOutcome {
    let code_units = match anchor_scoped_codeunit_resolution(analyzer, &anchor, lookup) {
        CodeUnitResolution::Resolved(code_units) | CodeUnitResolution::Ambiguous(code_units) => {
            code_units
        }
        CodeUnitResolution::NotFound => {
            // Nothing resolved in the anchor file. Check globally once for
            // diagnostics: candidates elsewhere mean the symbol exists but
            // not here (the anchor recovery note's case); nothing anywhere
            // falls through to the generated/unsupported/generic not-found
            // handling, as before.
            let global_candidates = match exact_then_fuzzy_codeunit_resolution(analyzer, lookup) {
                CodeUnitResolution::Resolved(units) | CodeUnitResolution::Ambiguous(units) => units,
                CodeUnitResolution::NotFound => Vec::new(),
            };
            if !global_candidates.is_empty() {
                return SourceLookupOutcome::NotFound(anchor_not_found_input(
                    input, &anchor, lookup,
                ));
            }
            if let Some(outcome) =
                semantic_model_source_outcome_with_anchor(analyzer, lookup, Some(&anchor))
            {
                return outcome;
            }
            if let Some(item) = unsupported_selector_shape_not_found_input(analyzer, input) {
                return SourceLookupOutcome::NotFound(item);
            }
            return SourceLookupOutcome::NotFound(symbol_not_found_input(input));
        }
    };
    let narrowed: Vec<_> = code_units
        .into_iter()
        .filter(|unit| rel_path_string(unit.source()) == anchor)
        .collect();

    let groups = distinct_definitions(analyzer, narrowed);
    match groups.as_slice() {
        [] => SourceLookupOutcome::NotFound(symbol_not_found_input(input)),
        [(_, _)] => {
            let code_units: Vec<_> = groups.into_iter().flat_map(|(_, units)| units).collect();
            let sources = source_blocks_for_resolved_units(analyzer, &code_units);
            if sources.is_empty() {
                SourceLookupOutcome::NotFound(renderable_not_found_input(input))
            } else {
                SourceLookupOutcome::Found(sources)
            }
        }
        _ => {
            let matches: Vec<_> = groups.into_iter().map(|(selector, _)| selector).collect();
            SourceLookupOutcome::Ambiguous(capped_ambiguous_symbol(input, matches))
        }
    }
}

pub fn get_symbol_sources(
    analyzer: &dyn IAnalyzer,
    params: SymbolLookupParams,
) -> SymbolSourcesResult {
    get_symbol_sources_with_cap(analyzer, params, GET_SYMBOL_SOURCES_MAX_FILES_PER_TARGET)
}

/// `max_files_per_target` bounds how many files one glob-shaped symbol argument
/// may expand to; a target over the bound is reported through `too_broad` and
/// contributes no source blocks at all, because the full text of an arbitrary
/// subset of a huge match looks complete while meaning nothing.
fn get_symbol_sources_with_cap(
    analyzer: &dyn IAnalyzer,
    params: SymbolLookupParams,
    max_files_per_target: usize,
) -> SymbolSourcesResult {
    // One tool call is one read-only analyzer request. The scope is what lets
    // every `WorkspaceFileResolver` built below -- one per call site, times one
    // per symbol in the parallel loop -- share a single workspace listing
    // instead of each walking the repository (#1334), and it lets the per-symbol
    // fan-out reuse hydrated file states the way every other batched tool
    // already does. Nested scopes opened by callees do not clear the cache
    // while this outer scope is active.
    let _analyzer_query = AnalyzerQueryScope::new(analyzer);

    let selected_symbols: Vec<_> = params
        .symbols
        .into_iter()
        .filter(|symbol| !symbol.trim().is_empty())
        .collect();

    let mut outcomes: Vec<_> = selected_symbols
        .into_par_iter()
        .enumerate()
        .map(|(index, symbol)| {
            if symbol.starts_with("bifrost-model://")
                && let Some(outcome) = semantic_model_source_outcome(analyzer, &symbol)
            {
                return (index, outcome);
            }
            let file_anchored = matches!(
                split_workspace_definition_selector(analyzer, &symbol),
                DefinitionSelector::FileAnchored { .. }
            );
            // Exact fully-qualified lookup wins before file patterns, so a
            // canonical symbol containing `/` (e.g. a Go import path) is never
            // misrouted as a filesystem path, and real namespace symbols like
            // `fmt::formatter` are never stolen by path-selector parsing.
            let exact_scope =
                crate::profiling::scope(format!("get_symbol_sources.exact[{symbol}]"));
            match resolve_selectable_definitions(analyzer, &symbol, exact_codeunit_resolution) {
                SelectableDefinitionResolution::Resolved(code_units) => {
                    let sources = if file_anchored {
                        source_blocks_for_resolved_units(analyzer, &code_units)
                    } else {
                        preferred_source_blocks_for_resolved_units(analyzer, &code_units)
                    };
                    return if sources.is_empty() {
                        (
                            index,
                            SourceLookupOutcome::NotFound(renderable_not_found_input(symbol)),
                        )
                    } else {
                        (index, SourceLookupOutcome::Found(sources))
                    };
                }
                SelectableDefinitionResolution::Ambiguous(item) => {
                    return (index, SourceLookupOutcome::Ambiguous(item));
                }
                SelectableDefinitionResolution::NotFound(_) => {
                    if let DefinitionSelector::FileAnchored { anchor, lookup } =
                        split_workspace_definition_selector(analyzer, &symbol)
                        && let Some(outcome) = semantic_model_source_outcome_with_anchor(
                            analyzer,
                            lookup,
                            Some(&anchor),
                        )
                    {
                        return (index, outcome);
                    }
                }
            }

            drop(exact_scope);

            let path_scope =
                crate::profiling::scope(format!("get_symbol_sources.path_qualified[{symbol}]"));
            match split_path_qualified_definition_selector(analyzer, &symbol) {
                Some(PathQualifiedSelector::Resolved { anchor, lookup }) => {
                    return (
                        index,
                        resolve_file_anchored_symbol_sources(analyzer, &symbol, anchor, lookup),
                    );
                }
                Some(PathQualifiedSelector::AmbiguousPath(item)) => {
                    return (index, SourceLookupOutcome::AmbiguousPath(item));
                }
                None => {}
            }

            if analyzer.languages().contains(&Language::Go)
                && looks_like_go_receiver_selector(&symbol)
            {
                match resolve_selectable_definitions(
                    analyzer,
                    &symbol,
                    exact_then_fuzzy_codeunit_resolution,
                ) {
                    SelectableDefinitionResolution::Resolved(code_units) => {
                        let sources = source_blocks_for_resolved_units(analyzer, &code_units);
                        return if sources.is_empty() {
                            (
                                index,
                                SourceLookupOutcome::NotFound(renderable_not_found_input(symbol)),
                            )
                        } else {
                            (index, SourceLookupOutcome::Found(sources))
                        };
                    }
                    SelectableDefinitionResolution::Ambiguous(item) => {
                        return (index, SourceLookupOutcome::Ambiguous(item));
                    }
                    SelectableDefinitionResolution::NotFound(_) => {}
                }
            }

            drop(path_scope);

            let file_pattern_scope =
                crate::profiling::scope(format!("get_symbol_sources.file_patterns[{symbol}]"));
            let file_matches = resolve_file_patterns(analyzer, std::slice::from_ref(&symbol));
            if let Some(item) = file_matches.ambiguous_paths.first() {
                return (index, SourceLookupOutcome::AmbiguousPath(item.clone()));
            }
            if !file_matches.files.is_empty() {
                if file_matches.files.len() > max_files_per_target {
                    return (
                        index,
                        SourceLookupOutcome::TooBroad(too_broad_scope(
                            &symbol,
                            &file_matches.files,
                            max_files_per_target,
                        )),
                    );
                }
                let sources = source_blocks_for_files(analyzer, file_matches.files);
                return if sources.is_empty() {
                    (
                        index,
                        SourceLookupOutcome::NotFound(renderable_not_found_input(symbol)),
                    )
                } else {
                    (index, SourceLookupOutcome::Found(sources))
                };
            }

            // Exact symbol lookup and literal/file-pattern resolution have
            // already had precedence. An explicit source path that survived
            // both cannot resolve, so do not send it through the workspace-wide
            // fuzzy symbol fallback. Dotted symbol spellings such as
            // `MetadataConfiguration.Properties` deliberately do not qualify;
            // they still need fuzzy resolution (#1196).
            if looks_like_explicit_source_file_target(&symbol) {
                if let Some(item) = unsupported_selector_shape_not_found_input(analyzer, &symbol) {
                    return (index, SourceLookupOutcome::NotFound(item));
                }
                return (
                    index,
                    SourceLookupOutcome::NotFound(file_not_found_input(symbol)),
                );
            }

            // File *shape* only decides how an unresolvable target is
            // reported; it must never gate symbol resolution. A real member
            // name can end in a segment that also spells a file extension --
            // Autofac's `Autofac.Builder.MetadataConfiguration.Properties`
            // reads as a `.properties` file to `looks_like_file_target` -- so
            // short-circuiting here reported "no workspace file matched" for a
            // symbol that resolves perfectly well, and the strictly more
            // specific spelling failed where the bare name was ambiguous
            // (#1196). The file-shaped diagnostics now live in the not-found
            // arm below, after resolution has had its say; `resolve_file_patterns`
            // above has already ruled out every real file for this input, so
            // the file reading is dead by the time we get here anyway.
            drop(file_pattern_scope);

            let _fuzzy_scope =
                crate::profiling::scope(format!("get_symbol_sources.fuzzy[{symbol}]"));
            match resolve_selectable_definitions(analyzer, &symbol, resolve_codeunit_fuzzy) {
                SelectableDefinitionResolution::Resolved(code_units) => {
                    let sources = preferred_source_blocks_for_resolved_units(analyzer, &code_units);
                    if sources.is_empty() {
                        (
                            index,
                            SourceLookupOutcome::NotFound(renderable_not_found_input(symbol)),
                        )
                    } else {
                        (index, SourceLookupOutcome::Found(sources))
                    }
                }
                SelectableDefinitionResolution::Ambiguous(item) => {
                    (index, SourceLookupOutcome::Ambiguous(item))
                }
                SelectableDefinitionResolution::NotFound(target) => {
                    let _diagnostics_scope = crate::profiling::scope(format!(
                        "get_symbol_sources.not_found_diagnostics[{symbol}]"
                    ));
                    if let Some(outcome) = semantic_model_source_outcome(analyzer, &symbol) {
                        return (index, outcome);
                    }
                    if let Some(item) =
                        unsupported_selector_shape_not_found_input(analyzer, &symbol)
                    {
                        return (index, SourceLookupOutcome::NotFound(item));
                    }
                    if looks_like_file_target(&symbol) {
                        return (
                            index,
                            SourceLookupOutcome::NotFound(file_not_found_input(symbol)),
                        );
                    }
                    (index, SourceLookupOutcome::NotFound(target))
                }
            }
        })
        .collect();
    outcomes.sort_by_key(|(index, _)| *index);

    let mut sources = Vec::new();
    let mut not_found = Vec::new();
    let mut ambiguous = Vec::new();
    let mut ambiguous_paths = Vec::new();
    let mut too_broad = Vec::new();
    for (_, outcome) in outcomes {
        match outcome {
            SourceLookupOutcome::Found(blocks) => sources.extend(dedup_source_blocks(blocks)),
            SourceLookupOutcome::NotFound(symbol) => not_found.push(symbol),
            SourceLookupOutcome::Ambiguous(item) => ambiguous.push(item),
            SourceLookupOutcome::AmbiguousPath(item) => ambiguous_paths.push(item),
            SourceLookupOutcome::TooBroad(item) => too_broad.push(item),
        }
    }

    SymbolSourcesResult {
        sources,
        not_found,
        ambiguous,
        ambiguous_paths,
        too_broad,
    }
}

fn semantic_model_source_outcome(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
) -> Option<SourceLookupOutcome> {
    semantic_model_source_outcome_with_anchor(analyzer, symbol, None)
}

fn semantic_model_source_outcome_with_anchor(
    analyzer: &dyn IAnalyzer,
    symbol: &str,
    required_path: Option<&str>,
) -> Option<SourceLookupOutcome> {
    let overlay = analyzer.semantic_model_overlay()?;
    let mut records = if symbol.starts_with("bifrost-model://") {
        overlay.symbols_at_uri(symbol)
    } else {
        overlay.symbols_with_id(symbol)
    }
    .records;
    if records.is_empty() {
        records = overlay.symbols_named(symbol).records;
    }
    if records.is_empty() {
        records = overlay
            .symbols()
            .iter()
            .filter(|model| model.qualified_name == symbol)
            .collect();
    }
    if let Some(required_path) = required_path {
        records.retain(|model| {
            matches!(
                &model.location,
                crate::analyzer::semantic_model::SemanticModelLocation::Authored(anchor)
                    if anchor.path == required_path
            )
        });
    }
    let disposition = match records.len() {
        0 => crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Empty,
        1 if !records[0].provenance.ambiguous => {
            crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        }
        _ => crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Conflict,
    };
    match disposition {
        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique => {
            let model = records[0];
            match &model.location {
                crate::analyzer::semantic_model::SemanticModelLocation::Model(_) => {
                    Some(SourceLookupOutcome::Found(vec![
                        semantic_model_source_block(model),
                    ]))
                }
                crate::analyzer::semantic_model::SemanticModelLocation::Authored(anchor) => {
                    let units = analyzer
                        .definitions(&anchor.symbol)
                        .filter(|unit| {
                            unit.source()
                                .rel_path()
                                .to_string_lossy()
                                .replace('\\', "/")
                                == anchor.path
                        })
                        .collect::<Vec<_>>();
                    let sources = preferred_source_blocks_for_resolved_units(analyzer, &units);
                    Some(SourceLookupOutcome::Found(if sources.is_empty() {
                        vec![semantic_model_source_block(model)]
                    } else {
                        sources
                    }))
                }
            }
        }
        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Conflict => {
            Some(SourceLookupOutcome::Ambiguous(AmbiguousSymbol {
                target: symbol.to_string(),
                matches: records
                    .iter()
                    .map(|record| record.location.identity().to_string())
                    .collect(),
                note: Some(
                    "conflicting active semantic-model declarations have no authoritative source"
                        .to_string(),
                ),
            }))
        }
        crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Empty => None,
    }
}

fn source_blocks_for_code_unit_with_cache(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
    include_comments: bool,
    cpp_identity: &mut CppIdentityRenderCache,
) -> Vec<SourceBlock> {
    let Some(content) = analyzer.indexed_source(code_unit.source()) else {
        return Vec::new();
    };

    let language = language_for_target(code_unit);
    let canonical_selector = cpp_identity.canonical_selector(analyzer, code_unit);

    let mut ranges = if code_unit.is_function() {
        let mut grouped = Vec::new();
        for candidate in analyzer.definitions(&code_unit.fq_name()) {
            if candidate.source() == code_unit.source() {
                grouped.extend(analyzer.ranges(&candidate));
            }
        }
        grouped
    } else {
        analyzer.ranges(code_unit).to_vec()
    };
    ranges.sort_by_key(|range| range.start_byte);

    ranges
        .into_iter()
        .filter_map(|range| {
            let occurrence_role = cpp_identity.occurrence_role(analyzer, code_unit, &range);
            let start_byte = if include_comments {
                expanded_comment_start(language, &content, range.start_byte)
            } else {
                range.start_byte
            };
            let text = content.get(start_byte..range.end_byte)?.to_string();
            if text.is_empty() {
                return None;
            }
            let text = analyzer.render_source_fragment(
                code_unit,
                text,
                range.start_byte.saturating_sub(start_byte),
            );
            let start_line = line_number_at_offset(&content, start_byte);
            Some(SourceBlock {
                label: display_symbol_for_target(code_unit),
                path: rel_path_string(code_unit.source()),
                start_line,
                // Same CR-aware line table as start_line: text.lines() counts
                // only \n, which undercounts rows on CR-only files (#1431).
                end_line: line_number_at_offset(&content, range.end_byte.saturating_sub(1)),
                text,
                canonical_selector: canonical_selector.clone(),
                occurrence_role,
                presentation: None,
                note: None,
                semantic_model: None,
            })
        })
        .collect()
}

pub(super) fn source_blocks_for_files(
    analyzer: &dyn IAnalyzer,
    files: Vec<ProjectFile>,
) -> Vec<SourceBlock> {
    files
        .into_iter()
        .filter_map(|file| {
            if let Some(block) = file_outline_source_block(
                analyzer,
                &file,
                file_outline_source_note(&file),
                None,
                None,
            ) {
                return Some(block);
            }

            if let Some(block) = include_fallback_source_block(analyzer, &file) {
                return Some(block);
            }

            excerpt_fallback_source_block(analyzer, &file)
        })
        .collect()
}

pub(super) fn file_outline_source_block(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    note: String,
    label: Option<String>,
    presentation: Option<String>,
) -> Option<SourceBlock> {
    let text = analyzer.list_top_level_symbols(file);
    if text.trim().is_empty() {
        return None;
    }
    let end_line = text.lines().count().max(1);
    let path = rel_path_string(file);
    Some(SourceBlock {
        label: label.unwrap_or_else(|| path.clone()),
        path,
        start_line: 1,
        end_line,
        text,
        canonical_selector: None,
        occurrence_role: None,
        presentation,
        note: Some(note),
        semantic_model: None,
    })
}

pub(super) fn file_outline_source_note(file: &ProjectFile) -> String {
    if UsageEcosystem::of(language_for_file(file)).is_module_scoped() {
        "file target: showing a flat outline of top-level symbols, not the full source; pass a symbol name for its full body (for JS/TS module-scoped symbols, use the full relative path selector such as src/plugin/relativeTime/index.js#default), or use get_summaries for structured summaries"
            .to_string()
    } else {
        "file target: showing a flat outline of top-level symbols, not the full source; pass a symbol name for its full body, or use get_summaries for structured summaries"
            .to_string()
    }
}

pub(super) fn include_fallback_source_block(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<SourceBlock> {
    let elements = include_fallback_elements(analyzer, file);
    if elements.is_empty() {
        return None;
    }
    let start_line = elements
        .iter()
        .map(|element| element.start_line)
        .min()
        .unwrap_or(1);
    let end_line = elements
        .iter()
        .map(|element| element.end_line)
        .max()
        .unwrap_or(start_line);
    let text = elements
        .into_iter()
        .map(|element| element.text)
        .collect::<Vec<_>>()
        .join("\n");
    let path = rel_path_string(file);
    Some(SourceBlock {
        label: path.clone(),
        path,
        start_line,
        end_line,
        text,
        canonical_selector: None,
        occurrence_role: None,
        presentation: None,
        note: Some(
            "no indexed declarations found in this file; showing its top-level #include lines, not the full source"
                .to_string(),
        ),
        semantic_model: None,
    })
}

pub(super) fn excerpt_fallback_source_block(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<SourceBlock> {
    let (elements, note) = excerpt_fallback_elements(analyzer, file)?;
    let sampled = elements.into_iter().next()?;
    Some(SourceBlock {
        label: sampled.path.clone(),
        path: sampled.path,
        start_line: sampled.start_line,
        end_line: sampled.end_line,
        text: sampled.text,
        canonical_selector: None,
        occurrence_role: None,
        presentation: sampled.presentation,
        note: Some(note),
        semantic_model: None,
    })
}

pub(super) const MAX_MODULE_OUTLINE_FILES: usize = 10;

pub(super) fn module_file_listing_blocks(
    analyzer: &dyn IAnalyzer,
    code_units: &[CodeUnit],
) -> Vec<SourceBlock> {
    let mut seen = BTreeSet::new();
    let mut files = Vec::new();
    for code_unit in code_units {
        let mut definitions = analyzer
            .all_declarations()
            .filter(|definition| {
                (definition.is_module() || is_scala_object_like(definition))
                    && definition.fq_name() == code_unit.fq_name()
            })
            .collect::<Vec<_>>();
        if definitions.is_empty() {
            definitions.push(code_unit.clone());
        }
        for definition in definitions {
            let file = definition.source().clone();
            if seen.insert(file.clone()) {
                files.push((file, display_symbol_for_target(code_unit)));
            }
        }
    }

    let omitted = files.len().saturating_sub(MAX_MODULE_OUTLINE_FILES);
    files
        .into_iter()
        .take(MAX_MODULE_OUTLINE_FILES)
        .map(|(file, label)| {
            let note = module_outline_source_note(&file, omitted);
            file_outline_source_block(
                analyzer,
                &file,
                note.clone(),
                Some(label.clone()),
                Some("file_listing".to_string()),
            )
            .unwrap_or_else(|| {
                let path = rel_path_string(&file);
                SourceBlock {
                    label,
                    path,
                    start_line: 1,
                    end_line: 1,
                    text: String::new(),
                    canonical_selector: None,
                    occurrence_role: None,
                    presentation: Some("file_listing".to_string()),
                    note: Some(note),
                    semantic_model: None,
                }
            })
        })
        .collect()
}

fn semantic_model_source_block(
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> SourceBlock {
    let (heading, locator, note) = match &symbol.location {
        crate::analyzer::semantic_model::SemanticModelLocation::Model(_) => (
            "Modeled declaration (not authored source)",
            String::new(),
            "This is a typed semantic-model description, not generated or authored source text.",
        ),
        crate::analyzer::semantic_model::SemanticModelLocation::Authored(anchor) => (
            "External authored declaration",
            format!("\nSource locator: {}#{}", anchor.path, anchor.symbol),
            "The pack preserves an authored external source locator, but that archive entry is not a workspace file; showing its typed semantic description.",
        ),
    };
    let signature = symbol
        .signature
        .as_deref()
        .map(|signature| format!("\nSignature: {signature}"))
        .unwrap_or_default();
    let text = format!(
        "{heading}\nSymbol: {}\nKind: {:?}{}{locator}\nOrigin: {:?}\nPack: {}@{}\nProducer: {}@{}\nRecord: {}\nRule: {}\nProof: {:?}\nCompleteness: {:?}\nAmbiguous: {}\nActivation: {}\nMatched evidence: {:?}",
        symbol.qualified_name,
        symbol.kind,
        signature,
        symbol.provenance.origin,
        symbol.provenance.pack_id,
        symbol.provenance.pack_version,
        symbol.provenance.producer,
        symbol.provenance.producer_version,
        symbol.provenance.record_id,
        symbol.provenance.rule_id.as_deref().unwrap_or("none"),
        symbol.provenance.proof,
        symbol.provenance.completeness,
        symbol.provenance.ambiguous,
        symbol.provenance.activation.reason,
        symbol.provenance.activation.matched_evidence,
    );
    let range = symbol.location.range();
    SourceBlock {
        label: symbol.qualified_name.clone(),
        path: symbol.location.identity().to_string(),
        start_line: range.start_line,
        end_line: range.end_line,
        text,
        canonical_selector: Some(symbol.location.identity().to_string()),
        occurrence_role: None,
        presentation: Some("semantic_model".to_string()),
        note: Some(note.to_string()),
        semantic_model: Some(symbol.provenance.clone()),
    }
}

pub(super) fn module_outline_source_note(
    file: &ProjectFile,
    omitted_defining_files: usize,
) -> String {
    let mut note = if UsageEcosystem::of(language_for_file(file)).is_module_scoped() {
        "module target: showing an outline of top-level symbols, not a full source body; pass a member symbol using path#symbol for module-scoped JS/TS, or use get_summaries for structured summaries"
            .to_string()
    } else {
        "module target: showing an outline of top-level symbols, not a full source body; pass a member symbol for its full body, or use get_summaries for structured summaries"
            .to_string()
    };
    if omitted_defining_files > 0 {
        note.push_str(&format!(
            "; omitted {omitted_defining_files} additional defining files, so pass a more specific member symbol or file path to target them"
        ));
    }
    note
}

pub(super) fn dedup_source_blocks(blocks: Vec<SourceBlock>) -> Vec<SourceBlock> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for block in blocks {
        let key = (
            block.label.clone(),
            block.path.clone(),
            block.start_line,
            block.end_line,
            block.text.clone(),
            block.canonical_selector.clone(),
            block.occurrence_role.clone(),
            block.presentation.clone(),
        );
        if seen.insert(key) {
            deduped.push(block);
        }
    }
    deduped
}

pub(super) fn is_file_listing_target(code_unit: &CodeUnit) -> bool {
    code_unit.is_module()
}

pub(super) fn is_ancestor_target(code_unit: &CodeUnit) -> bool {
    code_unit.is_class() || code_unit.is_module()
}

pub(super) fn line_number_at_offset(content: &str, offset: usize) -> usize {
    let bounded = offset.min(content.len());
    find_line_index_for_offset(&compute_line_starts(content), bounded) + 1
}

pub(super) fn expanded_comment_start(language: Language, source: &str, start_byte: usize) -> usize {
    if language == Language::Python {
        return python_expanded_comment_start(source, start_byte);
    }
    // Share the analyzer's comment-walk so both source-rendering paths agree on
    // what counts as a declaration's attached comment block (and inherit fixes
    // like the blank-line terminator that excludes file-level license headers).
    crate::analyzer::tree_sitter_analyzer::expanded_comment_start(source, start_byte)
}

pub(super) fn python_expanded_comment_start(source: &str, start_byte: usize) -> usize {
    let line_starts = line_starts(source);
    let line_index = find_line_index_for_offset(&line_starts, start_byte);

    let mut comment_start = start_byte;
    for line_idx in (0..line_index).rev() {
        let line_start = line_starts[line_idx];
        let line_end = line_starts
            .get(line_idx + 1)
            .copied()
            .unwrap_or(source.len());
        let line = &source[line_start..line_end];
        let trimmed = line.trim_start();

        if trimmed.trim().is_empty() {
            continue;
        }

        if trimmed.starts_with('#') {
            comment_start = line_start;
            continue;
        }

        break;
    }

    comment_start
}

pub(super) fn line_starts(source: &str) -> Vec<usize> {
    compute_line_starts(source)
}
