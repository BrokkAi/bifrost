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
}

pub(super) enum SourceLookupOutcome {
    Found(Vec<SourceBlock>),
    NotFound(NotFoundInput),
    Ambiguous(AmbiguousSymbol),
    AmbiguousPath(AmbiguousPathInput),
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

pub(super) fn java_generated_accessor_source_blocks(
    analyzer: &dyn IAnalyzer,
    input: &str,
    anchor: Option<&str>,
) -> Vec<SourceBlock> {
    let lookup = strip_trailing_call_suffix(input.trim());
    let Some(member) = symbol_selector_leaf(Language::Java, &lookup) else {
        return Vec::new();
    };

    let owners: Vec<_> = resolve_enclosing_codeunits(analyzer, &lookup)
        .into_iter()
        .filter(|owner| language_for_target(owner) == Language::Java && owner.is_class())
        .collect();
    let owner_names: BTreeSet<_> = owners.iter().map(CodeUnit::fq_name).collect();
    if owner_names.len() != 1 {
        return Vec::new();
    }

    let mut fields: Vec<_> = owners
        .iter()
        .flat_map(|owner| {
            java_lombok_accessor_field_candidates(
                analyzer,
                analyzer.global_usage_definition_index(),
                owner,
                &member,
            )
        })
        .filter(|field| anchor.is_none_or(|anchor| rel_path_string(field.source()) == anchor))
        .collect();
    fields.sort();
    fields.dedup();
    source_blocks_for_resolved_units(analyzer, &fields)
}

pub(crate) fn symbol_source_candidate_files(
    analyzer: &dyn IAnalyzer,
    result: &SymbolSourcesResult,
) -> BTreeSet<ProjectFile> {
    let resolver = WorkspaceFileResolver::new(analyzer.project());
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
            match split_definition_selector_with_resolver(symbol, |anchor| {
                matches!(resolver.resolve_literal(anchor), ResolvedFileInput::File(_))
            }) {
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
            let generated = java_generated_accessor_source_blocks(analyzer, lookup, Some(&anchor));
            if !generated.is_empty() {
                return SourceLookupOutcome::Found(generated);
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
    let selected_symbols: Vec<_> = params
        .symbols
        .into_iter()
        .filter(|symbol| !symbol.trim().is_empty())
        .collect();

    let mut outcomes: Vec<_> = selected_symbols
        .into_par_iter()
        .enumerate()
        .map(|(index, symbol)| {
            let file_anchored = matches!(
                split_definition_selector_with_resolver(&symbol, |anchor| {
                    matches!(
                        WorkspaceFileResolver::new(analyzer.project()).resolve_literal(anchor),
                        ResolvedFileInput::File(_)
                    )
                }),
                DefinitionSelector::FileAnchored { .. }
            );
            // Exact fully-qualified lookup wins before file patterns, so a
            // canonical symbol containing `/` (e.g. a Go import path) is never
            // misrouted as a filesystem path, and real namespace symbols like
            // `fmt::formatter` are never stolen by path-selector parsing.
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
                        split_definition_selector_with_resolver(&symbol, |anchor| {
                            matches!(
                                WorkspaceFileResolver::new(analyzer.project())
                                    .resolve_literal(anchor),
                                ResolvedFileInput::File(_)
                            )
                        })
                    {
                        let generated =
                            java_generated_accessor_source_blocks(analyzer, lookup, Some(&anchor));
                        if !generated.is_empty() {
                            return (index, SourceLookupOutcome::Found(generated));
                        }
                    }
                }
            }

            match split_path_qualified_definition_selector(analyzer, &symbol) {
                Some(PathQualifiedSelector::Resolved { anchor, lookup }) => {
                    return match resolve_file_anchored_symbol_sources(
                        analyzer, &symbol, anchor, lookup,
                    ) {
                        SourceLookupOutcome::Found(blocks) => {
                            (index, SourceLookupOutcome::Found(blocks))
                        }
                        SourceLookupOutcome::NotFound(item) => {
                            (index, SourceLookupOutcome::NotFound(item))
                        }
                        SourceLookupOutcome::Ambiguous(item) => {
                            (index, SourceLookupOutcome::Ambiguous(item))
                        }
                        SourceLookupOutcome::AmbiguousPath(item) => {
                            (index, SourceLookupOutcome::AmbiguousPath(item))
                        }
                    };
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

            let file_matches = resolve_file_patterns(analyzer, std::slice::from_ref(&symbol));
            if let Some(item) = file_matches.ambiguous_paths.first() {
                return (index, SourceLookupOutcome::AmbiguousPath(item.clone()));
            }
            if !file_matches.files.is_empty() {
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

            if looks_like_file_target(&symbol) {
                if let Some(item) = unsupported_selector_shape_not_found_input(analyzer, &symbol) {
                    return (index, SourceLookupOutcome::NotFound(item));
                }
                return (
                    index,
                    SourceLookupOutcome::NotFound(file_not_found_input(symbol)),
                );
            }

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
                    let generated = java_generated_accessor_source_blocks(analyzer, &symbol, None);
                    if !generated.is_empty() {
                        return (index, SourceLookupOutcome::Found(generated));
                    }
                    let target = unsupported_selector_shape_not_found_input(analyzer, &symbol)
                        .unwrap_or(target);
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
    for (_, outcome) in outcomes {
        match outcome {
            SourceLookupOutcome::Found(blocks) => sources.extend(dedup_source_blocks(blocks)),
            SourceLookupOutcome::NotFound(symbol) => not_found.push(symbol),
            SourceLookupOutcome::Ambiguous(item) => ambiguous.push(item),
            SourceLookupOutcome::AmbiguousPath(item) => ambiguous_paths.push(item),
        }
    }

    SymbolSourcesResult {
        sources,
        not_found,
        ambiguous,
        ambiguous_paths,
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
                end_line: start_line + text.lines().count().saturating_sub(1),
                text,
                canonical_selector: canonical_selector.clone(),
                occurrence_role,
                presentation: None,
                note: None,
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
                }
            })
        })
        .collect()
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

#[cfg(test)]
pub(super) fn split_logical_lines(content: &str) -> Vec<&str> {
    model_context::logical_lines(content)
}
