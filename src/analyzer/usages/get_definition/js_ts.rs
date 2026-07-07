use super::*;

#[derive(Debug, PartialEq, Eq, Hash)]
struct JsTsAliasCandidateKey {
    source: ProjectFile,
    kind: crate::analyzer::CodeUnitType,
    signature: Option<String>,
    ranges: Vec<Range>,
}

fn js_ts_candidates_outcome(
    analyzer: &dyn IAnalyzer,
    candidates: Vec<CodeUnit>,
) -> DefinitionLookupOutcome {
    candidates_outcome(prefer_js_ts_alias_representatives(analyzer, candidates))
}

fn prefer_js_ts_alias_representatives(
    analyzer: &dyn IAnalyzer,
    candidates: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    let mut representatives: HashMap<JsTsAliasCandidateKey, CodeUnit> = HashMap::default();
    for candidate in candidates {
        let key = JsTsAliasCandidateKey {
            source: candidate.source().clone(),
            kind: candidate.kind(),
            signature: candidate.signature().map(str::to_string),
            ranges: analyzer.ranges(&candidate).to_vec(),
        };
        representatives
            .entry(key)
            .and_modify(|current| {
                if js_ts_alias_preference(&candidate) < js_ts_alias_preference(current) {
                    *current = candidate.clone();
                }
            })
            .or_insert(candidate);
    }
    representatives.into_values().collect()
}

fn js_ts_alias_preference(unit: &CodeUnit) -> (usize, String) {
    let fq_name = unit.fq_name();
    (fq_name.matches('.').count(), fq_name)
}

pub(super) fn resolve_js_ts(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    language: Language,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(tree) = tree else {
        return no_definition("jsts_parse_failed", "JS/TS source could not be parsed");
    };
    let reference = site.text.as_str();
    let value_position = jsts_reference_is_value_position(tree, site);
    let imports = compute_jsts_import_binder(source, tree);
    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());

    if language == Language::TypeScript {
        let contextual_members = ts_contextual_object_literal_key_candidates(
            analyzer, support, file, source, tree, site, &imports, &aliases,
        );
        if !contextual_members.is_empty() {
            return js_ts_candidates_outcome(analyzer, contextual_members);
        }
    }

    // AST path for an inline construction receiver `new Foo().member` — the
    // text-split path below cannot express `new Foo()` as a qualifier.
    if let Some(members) =
        jsts_construction_receiver_members(analyzer, support, file, language, source, tree, site)
    {
        return js_ts_candidates_outcome(analyzer, members);
    }

    if let Some((qualifier, name)) = reference.split_once('.') {
        if let Some(binding) = imports.bindings.get(qualifier)
            && matches!(
                binding.kind,
                ImportKind::Namespace | ImportKind::CommonJsRequire
            )
        {
            return resolve_js_ts_module_binding(
                file,
                language,
                &binding.module_specifier,
                name,
                analyzer,
                support,
                Some(&aliases),
                value_position,
            );
        }
        let receiver_candidates = if let Some(binding) = imports.bindings.get(qualifier)
            && matches!(binding.kind, ImportKind::Named | ImportKind::Default)
        {
            let exported_name = match binding.kind {
                ImportKind::Named => binding.imported_name.as_deref().unwrap_or(qualifier),
                ImportKind::Default => "default",
                _ => qualifier,
            };
            resolve_js_ts_module_binding_candidates(
                analyzer,
                support,
                language,
                file,
                &binding.module_specifier,
                exported_name,
                Some(&aliases),
                value_position,
            )
        } else {
            let mut same_file = support.file_identifier(file, qualifier);
            if value_position {
                same_file = jsts_value_space_candidates(analyzer, same_file);
            } else {
                same_file = jsts_type_space_candidates(analyzer, same_file);
            }
            same_file
        };
        let member_candidates = if language == Language::TypeScript {
            ts_member_candidates(analyzer, support, receiver_candidates, name, value_position)
        } else {
            jsts_member_candidates(analyzer, support, receiver_candidates, name, value_position)
        };
        if !member_candidates.is_empty() {
            return js_ts_candidates_outcome(analyzer, member_candidates);
        }
        match jsts_receiver_provider_member_candidates(
            analyzer, support, file, language, source, tree, site, name,
        ) {
            ReceiverAnalysisOutcome::Precise(candidates) if !candidates.is_empty() => {
                return js_ts_candidates_outcome(
                    analyzer,
                    if language == Language::TypeScript {
                        if value_position {
                            jsts_value_space_candidates(analyzer, candidates)
                        } else {
                            jsts_type_space_candidates(analyzer, candidates)
                        }
                    } else {
                        jsts_value_space_candidates(analyzer, candidates)
                    },
                );
            }
            ReceiverAnalysisOutcome::Ambiguous(_)
            | ReceiverAnalysisOutcome::Unsupported { .. }
            | ReceiverAnalysisOutcome::ExceededBudget { .. } => {
                return no_definition(
                    "receiver_analysis_not_precise",
                    format!("`{reference}` did not resolve to a precise JS/TS receiver"),
                );
            }
            ReceiverAnalysisOutcome::Precise(_) | ReceiverAnalysisOutcome::Unknown => {}
        }
        let new_receiver_candidates = jsts_local_new_receiver_owner_candidates(
            analyzer,
            support,
            file,
            language,
            source,
            tree.root_node(),
            &imports,
            &aliases,
            qualifier,
            site.range.start_byte,
            0,
        );
        let new_receiver_member_candidates = if language == Language::TypeScript {
            ts_member_candidates(
                analyzer,
                support,
                new_receiver_candidates,
                name,
                value_position,
            )
        } else {
            jsts_member_candidates(
                analyzer,
                support,
                new_receiver_candidates,
                name,
                value_position,
            )
        };
        if !new_receiver_member_candidates.is_empty() {
            return js_ts_candidates_outcome(analyzer, new_receiver_member_candidates);
        }
        let local_receiver_binding = (language == Language::JavaScript)
            .then(|| {
                jsts_visible_receiver_binding_scope(
                    tree.root_node(),
                    source,
                    qualifier,
                    site.range.start_byte,
                )
            })
            .flatten();
        if let Some(binding_scope) = local_receiver_binding {
            let scoped_lookup = JstsScopedDottedLookup {
                analyzer,
                support,
                file,
                root: tree.root_node(),
                source,
                reference,
                receiver: qualifier,
                value_position,
                binding_scope,
                before_byte: site.range.start_byte,
            };
            let scoped = jsts_exact_scoped_dotted_candidates(scoped_lookup);
            if !scoped.is_empty() {
                return js_ts_candidates_outcome(analyzer, scoped);
            }
            return no_definition(
                "no_indexed_definition",
                format!("`{reference}` did not resolve to an indexed JS/TS definition"),
            );
        }
        let exact_same_file = jsts_exact_same_file_dotted_candidates(
            analyzer,
            support,
            file,
            reference,
            value_position,
        );
        if !exact_same_file.is_empty() {
            return js_ts_candidates_outcome(analyzer, exact_same_file);
        }
        if language == Language::TypeScript {
            let inferred_receivers = ts_local_receiver_owner_candidates(
                analyzer, support, file, source, tree, site, &imports, &aliases, qualifier,
            );
            let mut inferred_member_candidates =
                ts_member_candidates(analyzer, support, inferred_receivers, name, value_position);
            if inferred_member_candidates.is_empty() {
                let inferred_receivers = ts_local_receiver_owner_candidates(
                    analyzer, support, file, source, tree, site, &imports, &aliases, qualifier,
                );
                inferred_member_candidates = jsts_member_candidates(
                    analyzer,
                    support,
                    inferred_receivers,
                    name,
                    value_position,
                );
            }
            if !inferred_member_candidates.is_empty() {
                return js_ts_candidates_outcome(analyzer, inferred_member_candidates);
            }
            if let Some(receiver_type) = ts_global_object_receiver_type(qualifier) {
                let global_receivers = support
                    .fqn(receiver_type)
                    .into_iter()
                    .filter(|unit| jsts_unit_is_type_only(analyzer, unit))
                    .collect();
                let global_member_candidates =
                    ts_member_candidates(analyzer, support, global_receivers, name, value_position);
                if !global_member_candidates.is_empty() {
                    return js_ts_candidates_outcome(analyzer, global_member_candidates);
                }
            }
        }
        let exact_project =
            jsts_exact_dotted_candidates(analyzer, support, file, reference, value_position);
        if !exact_project.is_empty() {
            return js_ts_candidates_outcome(analyzer, exact_project);
        }
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve to an indexed JS/TS definition"),
        );
    }

    if let Some(binding) = imports.bindings.get(reference) {
        let exported_name = match binding.kind {
            ImportKind::Named => binding.imported_name.as_deref().unwrap_or(reference),
            ImportKind::Default => "default",
            ImportKind::Namespace | ImportKind::CommonJsRequire | ImportKind::Glob => reference,
        };
        if matches!(binding.kind, ImportKind::Named | ImportKind::Default) {
            return resolve_js_ts_module_binding(
                file,
                language,
                &binding.module_specifier,
                exported_name,
                analyzer,
                support,
                Some(&aliases),
                value_position,
            );
        }
    }

    let mut same_file = support.file_identifier(file, reference);
    if value_position {
        same_file = jsts_value_space_candidates(analyzer, same_file);
    } else {
        same_file = jsts_type_space_candidates(analyzer, same_file);
    }
    if !same_file.is_empty() {
        return js_ts_candidates_outcome(analyzer, same_file);
    }

    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed JS/TS definition"),
    )
}

#[allow(clippy::too_many_arguments)]
fn ts_contextual_object_literal_key_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    imports: &ImportBinder,
    aliases: &AliasResolver,
) -> Vec<CodeUnit> {
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return Vec::new();
    };
    let Some((property, object, name)) = ts_object_literal_property_at_key(node, source) else {
        return Vec::new();
    };
    if !(property.start_byte() <= site.focus_start_byte
        && site.focus_end_byte <= property.end_byte())
    {
        return Vec::new();
    }
    let owners = ts_contextual_object_literal_owners(
        analyzer, support, file, source, imports, aliases, object,
    );
    ts_member_candidates(analyzer, support, owners, &name, true)
}

fn ts_object_literal_property_at_key<'tree>(
    node: Node<'tree>,
    source: &str,
) -> Option<(Node<'tree>, Node<'tree>, String)> {
    let property = match node.kind() {
        "pair" | "shorthand_property_identifier" | "method_definition" => node,
        _ => node.parent().filter(|parent| {
            matches!(
                parent.kind(),
                "pair" | "shorthand_property_identifier" | "method_definition"
            ) && parent
                .child_by_field_name("key")
                .or_else(|| parent.child_by_field_name("name"))
                .or_else(|| parent.named_child(0))
                .is_some_and(|key| key.id() == node.id())
        })?,
    };
    let object = property
        .parent()
        .filter(|parent| parent.kind() == "object")?;
    let name = crate::analyzer::typescript::ts_object_literal_property_name(property, source)?;
    Some((property, object, name))
}

#[allow(clippy::too_many_arguments)]
fn ts_contextual_object_literal_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    object: Node<'_>,
) -> Vec<CodeUnit> {
    if let Some(variable) = object
        .parent()
        .filter(|parent| parent.kind() == "variable_declarator")
        && variable
            .child_by_field_name("value")
            .is_some_and(|value| value.id() == object.id())
        && let Some(type_node) = variable.child_by_field_name("type")
    {
        return ts_resolve_type_text_to_property_owners(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            ts_type_annotation_text(type_node, source).as_str(),
            0,
        );
    }

    let Some(return_statement) = object
        .parent()
        .filter(|parent| parent.kind() == "return_statement")
    else {
        return Vec::new();
    };
    let mut cursor = return_statement.walk();
    if return_statement
        .named_children(&mut cursor)
        .next()
        .is_none_or(|value| value.id() != object.id())
    {
        return Vec::new();
    }
    let Some(function) = jsts_enclosing_function_scope(object, object.start_byte()) else {
        return Vec::new();
    };
    let Some(type_node) = function.child_by_field_name("return_type") else {
        return Vec::new();
    };
    ts_resolve_type_text_to_property_owners(
        analyzer,
        support,
        file,
        source,
        imports,
        aliases,
        ts_type_annotation_text(type_node, source).as_str(),
        0,
    )
}

fn ts_global_object_receiver_type(receiver: &str) -> Option<&'static str> {
    match receiver {
        "window" => Some("Window"),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_js_ts_module_binding(
    file: &ProjectFile,
    language: Language,
    module: &str,
    exported_name: &str,
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    aliases: Option<&AliasResolver>,
    value_position: bool,
) -> DefinitionLookupOutcome {
    let files = crate::analyzer::resolve_js_ts_module_specifier(file, module, language, aliases);
    if files.is_empty() {
        if is_bare_js_ts_specifier(module) {
            return boundary(format!(
                "`{module}` is a package import outside this partial workspace analysis"
            ));
        }
        return boundary(format!(
            "`{module}` could not be resolved to a workspace JS/TS file"
        ));
    }

    let candidates = resolve_js_ts_module_binding_candidates(
        analyzer,
        support,
        language,
        file,
        module,
        exported_name,
        aliases,
        value_position,
    );
    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("`{exported_name}` is not indexed in `{module}`"),
        );
    }
    js_ts_candidates_outcome(analyzer, candidates)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_js_ts_module_binding_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    language: Language,
    file: &ProjectFile,
    module: &str,
    exported_name: &str,
    aliases: Option<&AliasResolver>,
    value_position: bool,
) -> Vec<CodeUnit> {
    let files = crate::analyzer::resolve_js_ts_module_specifier(file, module, language, aliases);
    if files.is_empty() {
        return Vec::new();
    }

    let mut candidates = jsts_module_export_candidates(
        analyzer,
        support,
        language,
        &files,
        exported_name,
        value_position,
    );
    if value_position {
        candidates = jsts_value_space_candidates(analyzer, candidates);
    } else {
        candidates = jsts_type_space_candidates(analyzer, candidates);
    }
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
        if value_position {
            candidates = jsts_value_space_candidates(analyzer, candidates);
        } else {
            candidates = jsts_type_space_candidates(analyzer, candidates);
        }
    }
    candidates
}

fn jsts_exact_same_file_dotted_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    reference: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates: Vec<_> = support
        .fqn(reference)
        .into_iter()
        .filter(|unit| unit.source() == file)
        .collect();
    if value_position {
        candidates = jsts_value_space_candidates(analyzer, candidates);
    } else {
        candidates = jsts_type_space_candidates(analyzer, candidates);
    }
    candidates
}

#[derive(Clone, Copy)]
struct JstsScopedDottedLookup<'a, 'tree> {
    analyzer: &'a dyn IAnalyzer,
    support: &'a DefinitionLookupIndex,
    file: &'a ProjectFile,
    root: Node<'tree>,
    source: &'a str,
    reference: &'a str,
    receiver: &'a str,
    value_position: bool,
    binding_scope: JstsReceiverBindingScope,
    before_byte: usize,
}

fn jsts_exact_scoped_dotted_candidates(ctx: JstsScopedDottedLookup<'_, '_>) -> Vec<CodeUnit> {
    let mut candidates: Vec<_> = ctx
        .support
        .fqn(ctx.reference)
        .into_iter()
        .filter(|unit| unit.source() == ctx.file)
        .filter(|unit| {
            ctx.analyzer.ranges(unit).iter().any(|range| {
                range.start_byte < ctx.before_byte
                    && jsts_visible_receiver_binding_scope(
                        ctx.root,
                        ctx.source,
                        ctx.receiver,
                        range.start_byte,
                    ) == Some(ctx.binding_scope)
            })
        })
        .collect();
    if ctx.value_position {
        candidates = jsts_value_space_candidates(ctx.analyzer, candidates);
    } else {
        candidates = jsts_type_space_candidates(ctx.analyzer, candidates);
    }
    candidates
}

fn jsts_exact_dotted_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    reference: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = support.fqn(reference);
    if let Some(top_level) = jsts_top_level_path_component(file) {
        let preferred: Vec<_> = candidates
            .iter()
            .filter(|unit| jsts_top_level_path_component(unit.source()) == Some(top_level))
            .cloned()
            .collect();
        if !preferred.is_empty() {
            candidates = preferred;
        }
    }
    if value_position {
        candidates = jsts_value_space_candidates(analyzer, candidates);
    } else {
        candidates = jsts_type_space_candidates(analyzer, candidates);
    }
    candidates
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JstsReceiverBindingScope {
    start_byte: usize,
    end_byte: usize,
}

fn jsts_visible_receiver_binding_scope(
    root: Node<'_>,
    source: &str,
    receiver: &str,
    before_byte: usize,
) -> Option<JstsReceiverBindingScope> {
    let mut node = smallest_named_node_covering(root, before_byte, before_byte)?;
    loop {
        if jsts_lexical_scope_kind(node.kind())
            && jsts_scope_declares_name_before(node, source, receiver, before_byte)
        {
            return Some(JstsReceiverBindingScope {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
            });
        }
        node = node.parent()?;
    }
}

fn jsts_lexical_scope_kind(kind: &str) -> bool {
    matches!(
        kind,
        "program"
            | "statement_block"
            | "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
    )
}

fn jsts_scope_declares_name_before(
    scope: Node<'_>,
    source: &str,
    name: &str,
    before_byte: usize,
) -> bool {
    let mut found = false;
    let scope_range = JstsReceiverBindingScope {
        start_byte: scope.start_byte(),
        end_byte: scope.end_byte(),
    };
    jsts_visit_scope_bindings_before(
        scope,
        source,
        name,
        before_byte,
        true,
        scope_range,
        &mut found,
    );
    found
}

fn jsts_visit_scope_bindings_before(
    node: Node<'_>,
    source: &str,
    name: &str,
    before_byte: usize,
    is_root: bool,
    scope_range: JstsReceiverBindingScope,
    found: &mut bool,
) {
    if *found || node.start_byte() >= before_byte {
        return;
    }
    if !is_root
        && matches!(
            node.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "class_declaration"
        )
    {
        return;
    }
    if matches!(
        node.kind(),
        "formal_parameter" | "required_parameter" | "optional_parameter" | "variable_declarator"
    ) && let Some(pattern) = node
        .child_by_field_name("pattern")
        .or_else(|| node.child_by_field_name("name"))
        && jsts_pattern_contains_name(pattern, source, name)
        && jsts_binding_scope_for_declaration(node, source) == Some(scope_range)
    {
        *found = true;
        return;
    }
    if matches!(node.kind(), "identifier" | "type_identifier")
        && node
            .parent()
            .is_some_and(|parent| matches!(parent.kind(), "formal_parameters" | "parameters"))
        && source
            .get(node.start_byte()..node.end_byte())
            .is_some_and(|text| text.trim() == name)
        && jsts_binding_scope_for_declaration(node, source) == Some(scope_range)
    {
        *found = true;
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= before_byte {
            break;
        }
        jsts_visit_scope_bindings_before(
            child,
            source,
            name,
            before_byte,
            false,
            scope_range,
            found,
        );
        if *found {
            break;
        }
    }
}

fn jsts_binding_scope_for_declaration(
    node: Node<'_>,
    source: &str,
) -> Option<JstsReceiverBindingScope> {
    if node.kind() == "variable_declarator" && jsts_variable_declarator_is_var(node, source) {
        return jsts_nearest_var_scope(node);
    }
    jsts_nearest_lexical_scope(node)
}

fn jsts_variable_declarator_is_var(node: Node<'_>, source: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "variable_declaration" | "lexical_declaration"
        ) {
            return source
                .get(parent.start_byte()..node.start_byte())
                .is_some_and(|prefix| prefix.trim_start().starts_with("var"));
        }
        if jsts_lexical_scope_kind(parent.kind()) {
            return false;
        }
        current = parent.parent();
    }
    false
}

fn jsts_nearest_var_scope(node: Node<'_>) -> Option<JstsReceiverBindingScope> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "program"
                | "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
        ) {
            return Some(JstsReceiverBindingScope {
                start_byte: parent.start_byte(),
                end_byte: parent.end_byte(),
            });
        }
        current = parent.parent();
    }
    None
}

fn jsts_nearest_lexical_scope(node: Node<'_>) -> Option<JstsReceiverBindingScope> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if jsts_lexical_scope_kind(parent.kind()) {
            return Some(JstsReceiverBindingScope {
                start_byte: parent.start_byte(),
                end_byte: parent.end_byte(),
            });
        }
        current = parent.parent();
    }
    None
}

fn jsts_pattern_contains_name(node: Node<'_>, source: &str, name: &str) -> bool {
    if matches!(
        node.kind(),
        "identifier" | "shorthand_property_identifier_pattern"
    ) {
        return source
            .get(node.start_byte()..node.end_byte())
            .is_some_and(|text| text.trim() == name);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| jsts_pattern_contains_name(child, source, name))
}

fn jsts_top_level_path_component(file: &ProjectFile) -> Option<&str> {
    file.rel_path()
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
}

fn jsts_module_export_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    language: Language,
    files: &[ProjectFile],
    exported_name: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let Some(index) = cached_jsts_index(analyzer, language) else {
        return Vec::new();
    };

    let bindings = index.local_bindings_for_exported_name(files, exported_name);
    let mut candidates = Vec::new();
    for (file, local_name) in bindings {
        let file_candidates = support.file_identifier_in_files(&[file], &local_name);
        candidates.extend(file_candidates);
    }

    if value_position {
        jsts_value_space_candidates(analyzer, candidates)
    } else {
        jsts_type_space_candidates(analyzer, candidates)
    }
}

pub(super) fn jsts_site_for_focus(mut site: ResolvedReferenceSite) -> ResolvedReferenceSite {
    if let Some(reference) = jsts_reference_prefix_for_focus(&site) {
        site.range.end_byte = site.range.start_byte + reference.len();
        site.text = reference;
    }
    site
}

fn jsts_reference_prefix_for_focus(site: &ResolvedReferenceSite) -> Option<String> {
    if !site.text.contains('.') {
        return None;
    }
    let relative_start = site.focus_start_byte.checked_sub(site.range.start_byte)?;
    let relative_end = site.focus_end_byte.checked_sub(site.range.start_byte)?;
    if relative_start >= relative_end || relative_end > site.text.len() {
        return None;
    }

    let mut segment_start = 0;
    for segment in site.text.split('.') {
        let segment_end = segment_start + segment.len();
        if relative_start >= segment_start && relative_end <= segment_end {
            if segment_end == site.text.len() {
                return None;
            }
            return Some(site.text[..segment_end].to_string());
        }
        segment_start = segment_end + 1;
    }
    None
}

/// Resolve `new Foo().member` by typing the receiver as the constructed class.
/// Returns the member candidates when the caret is on the property of a
/// member-expression whose object is a `new_expression`.
fn jsts_construction_receiver_members(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    language: Language,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<Vec<CodeUnit>> {
    let node =
        smallest_named_node_covering(tree.root_node(), site.range.start_byte, site.range.end_byte)?;
    // The site may resolve to the property identifier or to the whole
    // member-expression (`new Foo().bar`).
    let member_expr = if node.kind() == "member_expression" {
        node
    } else if node
        .parent()
        .is_some_and(|p| p.kind() == "member_expression")
    {
        node.parent()?
    } else {
        return None;
    };
    let object = member_expr.child_by_field_name("object")?;
    if object.kind() != "new_expression" {
        return None;
    }
    let constructor = object.child_by_field_name("constructor")?;
    if constructor.kind() != "identifier" {
        return None;
    }
    let property = member_expr.child_by_field_name("property")?;
    let class_name = &source[constructor.start_byte()..constructor.end_byte()];
    let member = &source[property.start_byte()..property.end_byte()];
    let receiver_candidates =
        jsts_value_space_candidates(analyzer, support.file_identifier(file, class_name));
    let members = if language == Language::TypeScript {
        ts_member_candidates(analyzer, support, receiver_candidates, member, true)
    } else {
        jsts_member_candidates(analyzer, support, receiver_candidates, member, true)
    };
    (!members.is_empty()).then_some(members)
}

#[allow(clippy::too_many_arguments)]
fn jsts_receiver_provider_member_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    language: Language,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    member: &str,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    let node =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte);
    let Some(node) = node else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    let member_expr = if node.kind() == "member_expression" {
        node
    } else if node
        .parent()
        .is_some_and(|parent| parent.kind() == "member_expression")
    {
        node.parent().expect("checked parent")
    } else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    let Some(property) = member_expr.child_by_field_name("property") else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    if node_text(property, source) != member {
        return ReceiverAnalysisOutcome::Unknown;
    }
    let Some(object) = member_expr.child_by_field_name("object") else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    let provider = JsTsReceiverFactProvider::new(
        analyzer,
        support,
        language,
        file,
        source,
        tree.root_node(),
        compute_jsts_import_binder(source, tree),
    );
    provider.resolve_member_targets(
        object,
        member,
        site.focus_start_byte,
        ReceiverAnalysisBudget::default(),
    )
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn jsts_member_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    receiver_candidates: Vec<CodeUnit>,
    member: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for receiver in receiver_candidates {
        candidates.extend(support.fqn(&format!("{}.{}", receiver.fq_name(), member)));
    }
    if value_position {
        jsts_value_space_candidates(analyzer, candidates)
    } else {
        jsts_type_space_candidates(analyzer, candidates)
    }
}

fn ts_member_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    receiver_candidates: Vec<CodeUnit>,
    member: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for receiver in receiver_candidates {
        let plain_fqn = format!("{}.{}", receiver.fq_name(), member);
        let static_fqn = format!("{plain_fqn}$static");
        let static_access = value_position && receiver.is_class();

        let mut members =
            ts_filtered_member_candidates(analyzer, support, &plain_fqn, value_position);
        if static_access {
            let static_members =
                ts_filtered_member_candidates(analyzer, support, &static_fqn, value_position);
            if !static_members.is_empty() {
                members = static_members;
            }
        } else if members.is_empty() {
            members = ts_filtered_member_candidates(analyzer, support, &static_fqn, value_position);
        }

        let has_synthetic = members.iter().any(CodeUnit::is_synthetic);
        if has_synthetic
            && !jsts_unit_is_type_only(analyzer, &receiver)
            && !ts_synthetic_member_is_supported_by_receiver_initializer(
                analyzer, support, &receiver, member,
            )
        {
            candidates.extend(members.into_iter().filter(|member| !member.is_synthetic()));
        } else {
            candidates.extend(members);
        }
    }
    candidates
}

fn ts_filtered_member_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    fqn: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let members = support.fqn(fqn);
    if value_position {
        jsts_value_space_candidates(analyzer, members)
    } else {
        jsts_type_space_candidates(analyzer, members)
    }
}

fn ts_synthetic_member_is_supported_by_receiver_initializer(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    receiver: &CodeUnit,
    member: &str,
) -> bool {
    let Ok(source) = receiver.source().read_to_string() else {
        return false;
    };
    let Some(tree) = parse_js_ts_tree(receiver.source(), &source, Language::TypeScript) else {
        return false;
    };
    let imports = compute_jsts_import_binder(&source, &tree);
    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());

    let mut saw_receiver_node = false;
    for node in ts_nodes_for_code_unit(analyzer, receiver, tree.root_node()) {
        let Some(declarator) = ts_variable_declarator_for_unit_node(node, receiver, &source) else {
            continue;
        };
        saw_receiver_node = true;
        let Some(value) = declarator.child_by_field_name("value") else {
            continue;
        };
        let Some(call) =
            ts_unwrap_expression(value).filter(|value| value.kind() == "call_expression")
        else {
            return true;
        };
        let Some(argument_index) =
            ts_call_direct_object_argument_index_with_member(call, &source, member)
        else {
            continue;
        };
        if ts_call_preserves_argument_shape(
            analyzer,
            support,
            receiver.source(),
            &source,
            &imports,
            &aliases,
            call,
            argument_index,
        ) {
            return true;
        }
    }
    let _ = saw_receiver_node;
    false
}

fn ts_variable_declarator_for_unit_node<'tree>(
    node: Node<'tree>,
    unit: &CodeUnit,
    source: &str,
) -> Option<Node<'tree>> {
    if node.kind() == "variable_declarator"
        && node
            .child_by_field_name("name")
            .is_some_and(|name| node_text_matches(name, source, unit.identifier()))
    {
        return Some(node);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find_map(|child| {
        (child.kind() == "variable_declarator"
            && child
                .child_by_field_name("name")
                .is_some_and(|name| node_text_matches(name, source, unit.identifier())))
        .then_some(child)
        .or_else(|| ts_variable_declarator_for_unit_node(child, unit, source))
    })
}

fn ts_call_direct_object_argument_index_with_member(
    call: Node<'_>,
    source: &str,
    member: &str,
) -> Option<usize> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .enumerate()
        .find_map(|(index, argument)| {
            let object = ts_direct_object_literal_value(argument)?;
            ts_object_literal_has_member(object, source, member).then_some(index)
        })
}

fn ts_direct_object_literal_value(node: Node<'_>) -> Option<Node<'_>> {
    let node = ts_unwrap_expression(node)?;
    (node.kind() == "object").then_some(node)
}

fn ts_unwrap_expression(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "as_expression"
        | "satisfies_expression"
        | "type_assertion"
        | "parenthesized_expression" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| {
                    child.kind() != "type_annotation"
                        && child.kind() != "type_identifier"
                        && child.kind() != "predefined_type"
                })
                .and_then(ts_unwrap_expression)
        }
        _ => Some(node),
    }
}

fn ts_object_literal_has_member(object: Node<'_>, source: &str, member: &str) -> bool {
    let mut cursor = object.walk();
    object
        .named_children(&mut cursor)
        .filter_map(|child| {
            crate::analyzer::typescript::ts_object_literal_property_name(child, source)
        })
        .any(|name| name == member)
}

#[allow(clippy::too_many_arguments)]
fn ts_call_preserves_argument_shape(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    call: Node<'_>,
    argument_index: usize,
) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    ts_call_expression_callees(
        analyzer, support, file, source, imports, aliases, function, 0,
    )
    .into_iter()
    .any(|callee| ts_function_preserves_parameter_shape(analyzer, &callee, argument_index))
}

fn ts_function_preserves_parameter_shape(
    analyzer: &dyn IAnalyzer,
    callee: &CodeUnit,
    parameter_index: usize,
) -> bool {
    let Ok(source) = callee.source().read_to_string() else {
        return false;
    };
    let Some(tree) = parse_js_ts_tree(callee.source(), &source, Language::TypeScript) else {
        return false;
    };
    ts_nodes_for_code_unit(analyzer, callee, tree.root_node())
        .into_iter()
        .any(|node| ts_function_node_preserves_parameter_shape(node, &source, parameter_index))
}

fn ts_function_node_preserves_parameter_shape(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> bool {
    let Some(parameter_name) = ts_function_parameter_name(function, source, parameter_index) else {
        return false;
    };
    if function.kind() == "arrow_function"
        && let Some(body) = function.child_by_field_name("body")
        && ts_expression_preserves_parameter_shape(body, source, &parameter_name)
    {
        return true;
    }
    ts_function_returns_parameter_shape(function, function.id(), source, &parameter_name)
}

fn ts_function_parameter_name(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> Option<String> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(ts_parameter_name_node)
        .nth(parameter_index)
        .and_then(|name| source.get(name.start_byte()..name.end_byte()))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn ts_function_returns_parameter_shape(
    node: Node<'_>,
    root_id: usize,
    source: &str,
    parameter_name: &str,
) -> bool {
    if node.id() != root_id
        && matches!(
            node.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "class_declaration"
                | "abstract_class_declaration"
                | "interface_declaration"
        )
    {
        return false;
    }
    if node.kind() == "return_statement" {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .next()
            .is_some_and(|expression| {
                ts_expression_preserves_parameter_shape(expression, source, parameter_name)
            });
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| ts_function_returns_parameter_shape(child, root_id, source, parameter_name))
}

fn ts_expression_preserves_parameter_shape(
    expression: Node<'_>,
    source: &str,
    parameter_name: &str,
) -> bool {
    let Some(expression) = ts_unwrap_expression(expression) else {
        return false;
    };
    if matches!(expression.kind(), "identifier" | "property_identifier")
        && node_text_matches(expression, source, parameter_name)
    {
        return true;
    }
    if expression.kind() != "object" {
        return false;
    }
    let mut cursor = expression.walk();
    expression.named_children(&mut cursor).any(|child| {
        child.kind() == "spread_element"
            && child
                .named_child(0)
                .and_then(ts_unwrap_expression)
                .is_some_and(|spread| node_text_matches(spread, source, parameter_name))
    })
}

#[allow(clippy::too_many_arguments)]
fn ts_local_receiver_owner_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    receiver: &str,
) -> Vec<CodeUnit> {
    ts_receiver_owner_candidates_at_byte(
        analyzer,
        support,
        file,
        source,
        tree.root_node(),
        imports,
        aliases,
        receiver,
        site.focus_start_byte,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ts_receiver_owner_candidates_at_byte(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    receiver: &str,
    byte: usize,
) -> Vec<CodeUnit> {
    if receiver == "this"
        && let Some(owner) = jsts_enclosing_class(analyzer, file, byte)
    {
        return vec![owner];
    }
    let Some(scope) = jsts_enclosing_function_scope(root, byte) else {
        return Vec::new();
    };

    let mut candidates = ts_receiver_owners_from_parameters(
        analyzer, support, file, source, imports, aliases, scope, receiver,
    );
    if candidates.is_empty() {
        candidates.extend(ts_receiver_owners_from_contextual_callback(
            analyzer, support, file, source, imports, aliases, scope, receiver,
        ));
    }
    candidates.extend(ts_receiver_owners_from_local_bindings(
        analyzer, support, file, source, imports, aliases, scope, receiver, byte, 0,
    ));
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn jsts_enclosing_class(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    let fqn = ClassRangeIndex::build(analyzer, file)
        .enclosing(byte)?
        .to_string();
    analyzer.definitions(&fqn).next().cloned()
}

fn jsts_enclosing_function_scope(root: Node<'_>, byte: usize) -> Option<Node<'_>> {
    let mut current = smallest_named_node_covering(root, byte, byte)?;
    loop {
        if matches!(
            current.kind(),
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        ) {
            return Some(current);
        }
        current = current.parent()?;
    }
}

fn jsts_enclosing_function_or_program_scope(root: Node<'_>, byte: usize) -> Option<Node<'_>> {
    let mut current = smallest_named_node_covering(root, byte, byte)?;
    loop {
        if matches!(
            current.kind(),
            "program"
                | "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
        ) {
            return Some(current);
        }
        current = current.parent()?;
    }
}

#[allow(clippy::too_many_arguments)]
fn ts_receiver_owners_from_parameters(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    scope: Node<'_>,
    receiver: &str,
) -> Vec<CodeUnit> {
    let Some(parameters) = scope
        .child_by_field_name("parameters")
        .or_else(|| scope.child_by_field_name("parameter"))
    else {
        return Vec::new();
    };
    let mut owners = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if !matches!(
            parameter.kind(),
            "required_parameter" | "optional_parameter"
        ) {
            continue;
        }
        let Some(type_node) = parameter.child_by_field_name("type") else {
            continue;
        };
        if parameter
            .child_by_field_name("name")
            .is_some_and(|name| node_text_matches(name, source, receiver))
        {
            owners.extend(ts_resolve_type_text_to_property_owners(
                analyzer,
                support,
                file,
                source,
                imports,
                aliases,
                ts_type_annotation_text(type_node, source).as_str(),
                0,
            ));
            continue;
        }
        if parameter
            .child_by_field_name("pattern")
            .is_some_and(|pattern| ts_object_pattern_binds(pattern, source, receiver))
        {
            let container_owners = ts_resolve_type_text_to_property_owners(
                analyzer,
                support,
                file,
                source,
                imports,
                aliases,
                ts_type_annotation_text(type_node, source).as_str(),
                0,
            );
            let fields =
                jsts_member_candidates(analyzer, support, container_owners, receiver, true);
            for field in fields {
                owners.extend(ts_field_signature_type_owners(
                    analyzer, support, file, source, imports, aliases, &field, 0,
                ));
            }
        }
    }
    owners
}

#[allow(clippy::too_many_arguments)]
fn ts_receiver_owners_from_contextual_callback(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    scope: Node<'_>,
    receiver: &str,
) -> Vec<CodeUnit> {
    let Some(callback_parameter_index) = ts_callback_parameter_index(scope, source, receiver)
    else {
        return Vec::new();
    };
    let Some((call, argument_index)) = ts_callback_argument_context(scope) else {
        return Vec::new();
    };
    let Some(function) = call.child_by_field_name("function") else {
        return Vec::new();
    };
    let callees = ts_call_expression_callees(
        analyzer, support, file, source, imports, aliases, function, 0,
    );

    let mut owners = Vec::new();
    for callee in callees {
        owners.extend(ts_callback_parameter_owners_from_callee(
            analyzer,
            support,
            &callee,
            argument_index,
            callback_parameter_index,
            0,
        ));
    }
    owners
}

fn ts_callback_parameter_index(scope: Node<'_>, source: &str, receiver: &str) -> Option<usize> {
    let parameters = scope
        .child_by_field_name("parameters")
        .or_else(|| scope.child_by_field_name("parameter"))?;
    if parameters.kind() == "identifier" {
        return node_text_matches(parameters, source, receiver).then_some(0);
    }
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(|parameter| ts_parameter_name_node(parameter))
        .position(|name| node_text_matches(name, source, receiver))
}

fn ts_parameter_name_node(parameter: Node<'_>) -> Option<Node<'_>> {
    match parameter.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => Some(parameter),
        "required_parameter" | "optional_parameter" => parameter
            .child_by_field_name("pattern")
            .or_else(|| parameter.child_by_field_name("name")),
        _ => None,
    }
}

fn ts_callback_argument_context(scope: Node<'_>) -> Option<(Node<'_>, usize)> {
    let mut current = scope;
    while let Some(parent) = current.parent() {
        if parent.kind() == "arguments" {
            let mut cursor = parent.walk();
            let argument_index = parent
                .named_children(&mut cursor)
                .position(|child| child.id() == current.id())?;
            let call = parent
                .parent()
                .filter(|node| node.kind() == "call_expression")?;
            return Some((call, argument_index));
        }
        current = parent;
    }
    None
}

fn ts_callback_parameter_owners_from_callee(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    callee: &CodeUnit,
    argument_index: usize,
    callback_parameter_index: usize,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let Ok(source) = callee.source().read_to_string() else {
        return Vec::new();
    };
    let Some(tree) = parse_js_ts_tree(callee.source(), &source, Language::TypeScript) else {
        return Vec::new();
    };
    let imports = compute_jsts_import_binder(&source, &tree);
    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());
    let mut owners = Vec::new();
    for node in ts_nodes_for_code_unit(analyzer, callee, tree.root_node()) {
        let Some(callback_type) = ts_function_parameter_type_text(node, &source, argument_index)
        else {
            continue;
        };
        let Some(parameter_type) =
            ts_callback_parameter_type_text(&callback_type, callback_parameter_index)
        else {
            continue;
        };
        owners.extend(ts_resolve_type_text_to_property_owners(
            analyzer,
            support,
            callee.source(),
            &source,
            &imports,
            &aliases,
            &parameter_type,
            depth + 1,
        ));
    }
    owners
}

fn ts_function_parameter_type_text(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> Option<String> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|parameter| {
            matches!(
                parameter.kind(),
                "required_parameter" | "optional_parameter"
            )
        })
        .nth(parameter_index)
        .and_then(|parameter| parameter.child_by_field_name("type"))
        .map(|type_node| ts_type_annotation_text(type_node, source))
}

fn ts_callback_parameter_type_text(callback_type: &str, parameter_index: usize) -> Option<String> {
    let callback_type = callback_type.trim();
    let open = callback_type.find('(')?;
    let close = ts_matching_close_delimiter(callback_type, open, '(', ')')?;
    let parameters = callback_type.get(open + 1..close)?;
    let parameter = ts_split_top_level_commas(parameters)
        .into_iter()
        .nth(parameter_index)?;
    let (_, type_text) = parameter.split_once(':')?;
    Some(ts_clean_type_text(type_text))
}

fn ts_matching_close_delimiter(
    text: &str,
    open_byte: usize,
    open_char: char,
    close_char: char,
) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_byte)
    {
        if ch == open_char {
            depth += 1;
        } else if ch == close_char {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn ts_split_top_level_commas(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (index, ch) in text.char_indices() {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if paren_depth == 0
                && angle_depth == 0
                && brace_depth == 0
                && bracket_depth == 0 =>
            {
                parts.push(text[start..index].trim());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(text[start..].trim());
    parts
}

#[allow(clippy::too_many_arguments)]
fn ts_receiver_owners_from_local_bindings(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    scope: Node<'_>,
    receiver: &str,
    before_byte: usize,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let mut owners = Vec::new();
    ts_collect_receiver_owners_from_bindings(
        analyzer,
        support,
        file,
        source,
        imports,
        aliases,
        scope,
        scope.id(),
        receiver,
        before_byte,
        depth,
        &mut owners,
    );
    owners
}

#[allow(clippy::too_many_arguments)]
fn ts_collect_receiver_owners_from_bindings(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    node: Node<'_>,
    root_id: usize,
    receiver: &str,
    before_byte: usize,
    depth: usize,
    out: &mut Vec<CodeUnit>,
) {
    if node.start_byte() >= before_byte {
        return;
    }
    if node.id() != root_id
        && matches!(
            node.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "class_declaration"
                | "abstract_class_declaration"
                | "interface_declaration"
        )
    {
        return;
    }

    if node.kind() == "variable_declarator"
        && let Some(name) = node.child_by_field_name("name")
        && node_text_matches(name, source, receiver)
    {
        let mut latest = Vec::new();
        if let Some(type_node) = node.child_by_field_name("type") {
            latest.extend(ts_resolve_type_text_to_property_owners(
                analyzer,
                support,
                file,
                source,
                imports,
                aliases,
                ts_type_annotation_text(type_node, source).as_str(),
                depth + 1,
            ));
        }
        if let Some(value) = node.child_by_field_name("value") {
            latest.extend(ts_expression_property_owners(
                analyzer,
                support,
                file,
                source,
                imports,
                aliases,
                value,
                depth + 1,
            ));
        }
        out.clear();
        out.extend(latest);
    }

    if node.kind() == "assignment_expression"
        && let Some(left) = node.child_by_field_name("left")
        && matches!(left.kind(), "identifier" | "type_identifier")
        && node_text_matches(left, source, receiver)
    {
        let latest = node
            .child_by_field_name("right")
            .map(|value| {
                ts_expression_property_owners(
                    analyzer,
                    support,
                    file,
                    source,
                    imports,
                    aliases,
                    value,
                    depth + 1,
                )
            })
            .unwrap_or_default();
        out.clear();
        out.extend(latest);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        ts_collect_receiver_owners_from_bindings(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            child,
            root_id,
            receiver,
            before_byte,
            depth,
            out,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn ts_expression_property_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    expression: Node<'_>,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    match expression.kind() {
        "call_expression" => expression
            .child_by_field_name("function")
            .map(|function| {
                let callees = ts_call_expression_callees(
                    analyzer,
                    support,
                    file,
                    source,
                    imports,
                    aliases,
                    function,
                    depth + 1,
                );
                ts_expand_property_owners(analyzer, support, callees, depth + 1)
            })
            .unwrap_or_default(),
        "await_expression" => {
            let mut cursor = expression.walk();
            expression
                .named_children(&mut cursor)
                .next()
                .map(|child| {
                    ts_expression_property_owners(
                        analyzer,
                        support,
                        file,
                        source,
                        imports,
                        aliases,
                        child,
                        depth + 1,
                    )
                })
                .unwrap_or_default()
        }
        "new_expression" => expression
            .child_by_field_name("constructor")
            .map(|constructor| {
                jsts_constructor_owner_candidates(
                    analyzer,
                    support,
                    file,
                    Language::TypeScript,
                    source,
                    imports,
                    aliases,
                    constructor,
                    false,
                )
            })
            .unwrap_or_default(),
        "as_expression" | "satisfies_expression" | "type_assertion" => expression
            .child_by_field_name("type")
            .or_else(|| ts_assertion_type_child(expression))
            .map(|type_node| {
                ts_resolve_type_text_to_property_owners(
                    analyzer,
                    support,
                    file,
                    source,
                    imports,
                    aliases,
                    ts_type_annotation_text(type_node, source).as_str(),
                    depth + 1,
                )
            })
            .unwrap_or_else(|| {
                let mut cursor = expression.walk();
                expression
                    .named_children(&mut cursor)
                    .find(|child| child.kind() != "type_annotation")
                    .map(|child| {
                        ts_expression_property_owners(
                            analyzer,
                            support,
                            file,
                            source,
                            imports,
                            aliases,
                            child,
                            depth + 1,
                        )
                    })
                    .unwrap_or_default()
            }),
        _ => Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn jsts_local_new_receiver_owner_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    language: Language,
    source: &str,
    root: Node<'_>,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    receiver: &str,
    before_byte: usize,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let Some(scope) = jsts_enclosing_function_or_program_scope(root, before_byte) else {
        return Vec::new();
    };
    let mut state = None;
    jsts_collect_local_new_receiver_owner_candidates(
        analyzer,
        support,
        file,
        language,
        source,
        scope,
        scope.id(),
        imports,
        aliases,
        receiver,
        before_byte,
        depth,
        &mut state,
    );
    state.unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn jsts_collect_local_new_receiver_owner_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    language: Language,
    source: &str,
    node: Node<'_>,
    root_id: usize,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    receiver: &str,
    before_byte: usize,
    depth: usize,
    state: &mut Option<Vec<CodeUnit>>,
) {
    if node.start_byte() >= before_byte {
        return;
    }
    if node.id() != root_id
        && matches!(
            node.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "class_declaration"
                | "abstract_class_declaration"
                | "interface_declaration"
        )
    {
        return;
    }

    if node.kind() == "variable_declarator"
        && let Some(name) = node.child_by_field_name("name")
        && node_text_matches(name, source, receiver)
    {
        let owners = node
            .child_by_field_name("value")
            .map(|value| {
                jsts_local_receiver_value_owner_candidates(
                    analyzer,
                    support,
                    file,
                    language,
                    source,
                    root_node(node),
                    imports,
                    aliases,
                    value,
                    before_byte,
                    depth + 1,
                )
            })
            .unwrap_or_default();
        *state = Some(owners);
    }

    if node.kind() == "assignment_expression"
        && let Some(left) = node.child_by_field_name("left")
        && matches!(left.kind(), "identifier" | "type_identifier")
        && node_text_matches(left, source, receiver)
    {
        let owners = node
            .child_by_field_name("right")
            .map(|value| {
                jsts_local_receiver_value_owner_candidates(
                    analyzer,
                    support,
                    file,
                    language,
                    source,
                    root_node(node),
                    imports,
                    aliases,
                    value,
                    before_byte,
                    depth + 1,
                )
            })
            .unwrap_or_default();
        *state = Some(owners);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        jsts_collect_local_new_receiver_owner_candidates(
            analyzer,
            support,
            file,
            language,
            source,
            child,
            root_id,
            imports,
            aliases,
            receiver,
            before_byte,
            depth,
            state,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn jsts_local_receiver_value_owner_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    language: Language,
    source: &str,
    root: Node<'_>,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    value: Node<'_>,
    _before_byte: usize,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    match value.kind() {
        "new_expression" => value
            .child_by_field_name("constructor")
            .map(|constructor| {
                jsts_constructor_owner_candidates(
                    analyzer,
                    support,
                    file,
                    language,
                    source,
                    imports,
                    aliases,
                    constructor,
                    false,
                )
            })
            .unwrap_or_default(),
        "identifier" | "type_identifier" => source
            .get(value.start_byte()..value.end_byte())
            .map(str::trim)
            .filter(|alias| !alias.is_empty())
            .map(|alias| {
                jsts_local_new_receiver_owner_candidates(
                    analyzer,
                    support,
                    file,
                    language,
                    source,
                    root,
                    imports,
                    aliases,
                    alias,
                    value.start_byte(),
                    depth + 1,
                )
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn jsts_constructor_owner_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    language: Language,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    constructor: Node<'_>,
    value_position: bool,
) -> Vec<CodeUnit> {
    let Some(name) = jsts_constructor_name(constructor, source) else {
        return Vec::new();
    };
    let mut candidates = if let Some(binding) = imports.bindings.get(name) {
        let exported_name = match binding.kind {
            ImportKind::Named => binding.imported_name.as_deref().unwrap_or(name),
            ImportKind::Default => "default",
            ImportKind::Namespace | ImportKind::CommonJsRequire | ImportKind::Glob => name,
        };
        if matches!(binding.kind, ImportKind::Named | ImportKind::Default) {
            resolve_js_ts_module_binding_candidates(
                analyzer,
                support,
                language,
                file,
                &binding.module_specifier,
                exported_name,
                Some(aliases),
                value_position,
            )
        } else {
            Vec::new()
        }
    } else {
        support.file_identifier(file, name)
    };
    candidates.retain(|unit| unit.is_class());
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn jsts_constructor_name<'a>(constructor: Node<'_>, source: &'a str) -> Option<&'a str> {
    match constructor.kind() {
        "identifier" | "type_identifier" => source
            .get(constructor.start_byte()..constructor.end_byte())
            .map(str::trim)
            .filter(|name| !name.is_empty()),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn ts_call_expression_callees(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    function: Node<'_>,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    if function.kind() == "member_expression" {
        let Some(object) = function.child_by_field_name("object") else {
            return Vec::new();
        };
        let Some(property) = function
            .child_by_field_name("property")
            .and_then(|property| ts_call_reference_name(property, source))
        else {
            return Vec::new();
        };
        if let Some(namespace) = source
            .get(object.start_byte()..object.end_byte())
            .map(str::trim)
            .filter(|namespace| !namespace.is_empty())
            && let Some(binding) = imports.bindings.get(namespace)
            && matches!(
                binding.kind,
                ImportKind::Namespace | ImportKind::CommonJsRequire
            )
        {
            return resolve_js_ts_module_binding_candidates(
                analyzer,
                support,
                Language::TypeScript,
                file,
                &binding.module_specifier,
                &property,
                Some(aliases),
                true,
            );
        }
        let receiver_owners = ts_expression_receiver_owners(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            object,
            depth + 1,
        );
        let callees = jsts_member_candidates(analyzer, support, receiver_owners, &property, true);
        if !callees.is_empty() {
            return callees;
        }
    }

    ts_call_reference_name(function, source)
        .map(|name| {
            ts_identifier_candidates(
                analyzer, support, file, source, imports, aliases, &name, true,
            )
        })
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn ts_expression_receiver_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    expression: Node<'_>,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    match expression.kind() {
        "identifier" | "property_identifier" | "this" => {
            let Some(receiver) = source
                .get(expression.start_byte()..expression.end_byte())
                .map(str::trim)
            else {
                return Vec::new();
            };
            ts_receiver_owner_candidates_at_byte(
                analyzer,
                support,
                file,
                source,
                root_node(expression),
                imports,
                aliases,
                receiver,
                expression.start_byte(),
            )
        }
        _ => ts_expression_property_owners(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            expression,
            depth + 1,
        ),
    }
}

fn root_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        node = parent;
    }
    node
}

#[allow(clippy::too_many_arguments)]
fn ts_identifier_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    _source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    name: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = if let Some(binding) = imports.bindings.get(name) {
        let exported_name = match binding.kind {
            ImportKind::Named => binding.imported_name.as_deref().unwrap_or(name),
            ImportKind::Default => "default",
            ImportKind::Namespace | ImportKind::CommonJsRequire | ImportKind::Glob => name,
        };
        if matches!(binding.kind, ImportKind::Named | ImportKind::Default) {
            resolve_js_ts_module_binding_candidates(
                analyzer,
                support,
                Language::TypeScript,
                file,
                &binding.module_specifier,
                exported_name,
                Some(aliases),
                value_position,
            )
        } else {
            Vec::new()
        }
    } else {
        support.file_identifier(file, name)
    };
    if value_position {
        candidates = jsts_value_space_candidates(analyzer, candidates);
    } else {
        candidates = jsts_type_space_candidates(analyzer, candidates);
    }
    candidates
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ts_resolve_type_text_to_property_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    type_text: &str,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let type_text = ts_clean_type_text(type_text);
    if type_text.is_empty() {
        return Vec::new();
    }

    if let Some(name) = ts_typeof_target(&type_text) {
        let candidates = ts_identifier_candidates(
            analyzer, support, file, source, imports, aliases, name, true,
        );
        return ts_expand_property_owners(analyzer, support, candidates, depth + 1);
    }

    if let Some(inner) = ts_generic_type_argument(&type_text, "ReturnType") {
        return ts_resolve_type_text_to_property_owners(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            inner,
            depth + 1,
        );
    }

    if let Some(inner) = ts_generic_type_argument(&type_text, "Promise") {
        return ts_resolve_type_text_to_property_owners(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            inner,
            depth + 1,
        );
    }

    if let Some(inner) = ts_schema_infer_argument(&type_text) {
        return ts_resolve_type_text_to_property_owners(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            inner,
            depth + 1,
        );
    }

    let Some(name) = ts_leading_type_identifier(&type_text) else {
        return Vec::new();
    };
    let candidates = ts_identifier_candidates(
        analyzer, support, file, source, imports, aliases, name, false,
    );
    ts_expand_property_owners(analyzer, support, candidates, depth + 1)
}

fn ts_expand_property_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    candidates: Vec<CodeUnit>,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let mut owners = Vec::new();
    for candidate in candidates {
        if jsts_unit_is_type_only(analyzer, &candidate) {
            let signatures = analyzer.signatures(&candidate);
            let expanded = signatures
                .iter()
                .flat_map(|signature| {
                    ts_alias_rhs(signature)
                        .map(|rhs| {
                            ts_resolve_type_from_unit_context(
                                analyzer,
                                support,
                                &candidate,
                                rhs,
                                depth + 1,
                            )
                        })
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>();
            if expanded.is_empty() {
                owners.push(candidate);
            } else {
                owners.extend(expanded);
            }
        } else if candidate.is_function() {
            owners.push(candidate.clone());
            owners.extend(ts_function_return_property_owners(
                analyzer,
                support,
                &candidate,
                depth + 1,
            ));
        } else {
            owners.push(candidate);
        }
    }
    sort_units(&mut owners);
    owners.dedup();
    owners
}

fn ts_resolve_type_from_unit_context(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    unit: &CodeUnit,
    type_text: &str,
    depth: usize,
) -> Vec<CodeUnit> {
    let Ok(source) = unit.source().read_to_string() else {
        return Vec::new();
    };
    let Some(tree) = parse_js_ts_tree(unit.source(), &source, Language::TypeScript) else {
        return Vec::new();
    };
    let imports = compute_jsts_import_binder(&source, &tree);
    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());
    ts_resolve_type_text_to_property_owners(
        analyzer,
        support,
        unit.source(),
        &source,
        &imports,
        &aliases,
        type_text,
        depth + 1,
    )
}

pub(crate) fn ts_function_return_property_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    function: &CodeUnit,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let Ok(source) = function.source().read_to_string() else {
        return Vec::new();
    };
    let Some(tree) = parse_js_ts_tree(function.source(), &source, Language::TypeScript) else {
        return Vec::new();
    };
    let imports = compute_jsts_import_binder(&source, &tree);
    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());
    let mut owners = Vec::new();
    for node in ts_nodes_for_code_unit(analyzer, function, tree.root_node()) {
        if let Some(type_text) = ts_function_return_type_text(node, &source) {
            owners.extend(ts_resolve_type_text_to_property_owners(
                analyzer,
                support,
                function.source(),
                &source,
                &imports,
                &aliases,
                &type_text,
                depth + 1,
            ));
        }
        ts_collect_return_property_owners(
            analyzer,
            support,
            function.source(),
            &source,
            &imports,
            &aliases,
            node,
            node.id(),
            depth + 1,
            &mut owners,
        );
    }
    sort_units(&mut owners);
    owners.dedup();
    owners
}

fn ts_function_return_type_text(function: Node<'_>, source: &str) -> Option<String> {
    function
        .child_by_field_name("return_type")
        .map(|type_node| ts_type_annotation_text(type_node, source))
        .filter(|text| !text.is_empty())
}

fn ts_nodes_for_code_unit<'tree>(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    root: Node<'tree>,
) -> Vec<Node<'tree>> {
    let ranges = analyzer.ranges(unit);
    let mut nodes = Vec::new();
    for range in ranges {
        if let Some(node) = smallest_named_node_covering(root, range.start_byte, range.end_byte) {
            nodes.push(
                node.child_by_field_name("declaration")
                    .filter(|_| node.kind() == "export_statement")
                    .unwrap_or(node),
            );
        }
    }
    nodes
}

#[allow(clippy::too_many_arguments)]
fn ts_collect_return_property_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    node: Node<'_>,
    root_id: usize,
    depth: usize,
    out: &mut Vec<CodeUnit>,
) {
    if depth > 8 {
        return;
    }
    if node.id() != root_id
        && matches!(
            node.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "class_declaration"
                | "abstract_class_declaration"
                | "interface_declaration"
        )
    {
        return;
    }
    if node.kind() == "return_statement" {
        let mut cursor = node.walk();
        if let Some(expression) = node.named_children(&mut cursor).next() {
            out.extend(ts_expression_property_owners(
                analyzer,
                support,
                file,
                source,
                imports,
                aliases,
                expression,
                depth + 1,
            ));
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        ts_collect_return_property_owners(
            analyzer, support, file, source, imports, aliases, child, root_id, depth, out,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn ts_field_signature_type_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    field: &CodeUnit,
    depth: usize,
) -> Vec<CodeUnit> {
    let mut owners = Vec::new();
    for signature in analyzer.signatures(field) {
        if let Some(type_text) = ts_field_type_text(signature) {
            owners.extend(ts_resolve_type_text_to_property_owners(
                analyzer,
                support,
                file,
                source,
                imports,
                aliases,
                type_text,
                depth + 1,
            ));
        }
    }
    owners
}

fn ts_object_pattern_binds(pattern: Node<'_>, source: &str, receiver: &str) -> bool {
    if pattern.kind() != "object_pattern" {
        return false;
    }
    let mut cursor = pattern.walk();
    pattern
        .named_children(&mut cursor)
        .any(|child| match child.kind() {
            "shorthand_property_identifier_pattern" => node_text_matches(child, source, receiver),
            "pair_pattern" => child
                .child_by_field_name("value")
                .is_some_and(|value| ts_pattern_binds_name(value, source, receiver)),
            _ => false,
        })
}

fn ts_pattern_binds_name(pattern: Node<'_>, source: &str, receiver: &str) -> bool {
    match pattern.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            node_text_matches(pattern, source, receiver)
        }
        "assignment_pattern" => pattern
            .child_by_field_name("left")
            .is_some_and(|left| ts_pattern_binds_name(left, source, receiver)),
        _ => false,
    }
}

fn node_text_matches(node: Node<'_>, source: &str, expected: &str) -> bool {
    source
        .get(node.start_byte()..node.end_byte())
        .is_some_and(|text| text.trim() == expected)
}

pub(crate) fn ts_type_annotation_text(node: Node<'_>, source: &str) -> String {
    ts_clean_type_text(source.get(node.start_byte()..node.end_byte()).unwrap_or(""))
}

fn ts_clean_type_text(text: &str) -> String {
    text.trim()
        .trim_start_matches(':')
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_string()
}

fn ts_field_type_text(signature: &str) -> Option<&str> {
    let (_, rhs) = signature.split_once(':')?;
    Some(
        rhs.split(['=', ','])
            .next()
            .unwrap_or(rhs)
            .trim()
            .trim_end_matches(';')
            .trim(),
    )
}

fn ts_alias_rhs(signature: &str) -> Option<&str> {
    let (_, rhs) = signature.split_once('=')?;
    Some(rhs.trim().trim_end_matches(';').trim())
}

fn ts_typeof_target(text: &str) -> Option<&str> {
    text.trim().strip_prefix("typeof").map(str::trim)
}

fn ts_generic_type_argument<'a>(text: &'a str, generic: &str) -> Option<&'a str> {
    let text = text.trim();
    let rest = text.strip_prefix(generic)?;
    let rest = rest.trim_start();
    let inner = rest.strip_prefix('<')?.strip_suffix('>')?;
    Some(inner.trim())
}

/// Recognizes a schema library's type-inference helper applied to a value, e.g. zod's
/// `z.infer<typeof Schema>` (and the `Infer` alias other libraries expose), so navigation can
/// follow the wrapped argument to the schema's shape. Matches the qualified `.infer`/`.Infer`
/// member-name convention regardless of the namespace alias, rather than the literal `z.infer`.
fn ts_schema_infer_argument(text: &str) -> Option<&str> {
    let text = text.trim();
    let open = text.find('<')?;
    let head = text[..open].trim();
    let last = head.rsplit('.').next()?;
    if !head.contains('.') || !(last == "infer" || last == "Infer") {
        return None;
    }
    let inner = text[open..].strip_prefix('<')?.strip_suffix('>')?;
    Some(inner.trim())
}

fn ts_leading_type_identifier(text: &str) -> Option<&str> {
    let text = text.trim();
    let end = text
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'))
        .unwrap_or(text.len());
    (end > 0).then_some(&text[..end])
}

fn ts_call_reference_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "property_identifier" => source
            .get(node.start_byte()..node.end_byte())
            .map(|text| text.trim().to_string()),
        "member_expression" => node
            .child_by_field_name("property")
            .and_then(|property| ts_call_reference_name(property, source)),
        _ => None,
    }
}

fn ts_assertion_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "type_identifier"
                | "generic_type"
                | "type_arguments"
                | "object_type"
                | "predefined_type"
                | "union_type"
                | "intersection_type"
        )
    })
}

fn jsts_reference_is_value_position(tree: &Tree, site: &ResolvedReferenceSite) -> bool {
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return true;
    };
    !jsts_reference_is_type_position(node)
}

fn jsts_reference_is_type_position(mut node: Node<'_>) -> bool {
    loop {
        match node.kind() {
            "type_identifier"
            | "predefined_type"
            | "type_annotation"
            | "type_arguments"
            | "type_parameters"
            | "generic_type"
            | "union_type"
            | "intersection_type"
            | "interface_declaration"
            | "type_alias_declaration"
            | "extends_type_clause"
            | "implements_clause"
            | "constraint" => return true,
            "call_expression"
            | "arguments"
            | "member_expression"
            | "subscript_expression"
            | "binary_expression"
            | "unary_expression"
            | "return_statement"
            | "expression_statement"
            | "variable_declarator"
            | "assignment_expression" => return false,
            _ => {}
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        node = parent;
    }
}

fn jsts_value_space_candidates(
    analyzer: &dyn IAnalyzer,
    candidates: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    let value_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| !jsts_unit_is_type_only(analyzer, candidate))
        .cloned()
        .collect();
    if value_candidates.is_empty() {
        candidates
    } else {
        value_candidates
    }
}

pub(crate) fn jsts_type_space_candidates(
    analyzer: &dyn IAnalyzer,
    candidates: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    let type_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| jsts_unit_is_type_only(analyzer, candidate))
        .cloned()
        .collect();
    if type_candidates.is_empty() {
        candidates
    } else {
        type_candidates
    }
}

fn jsts_unit_is_type_only(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    if analyzer
        .type_alias_provider()
        .is_some_and(|provider| provider.is_type_alias(unit))
    {
        return true;
    }
    unit.signature().is_some_and(jsts_signature_is_type_only)
        || analyzer
            .signatures(unit)
            .iter()
            .any(|signature| jsts_signature_is_type_only(signature))
}

fn jsts_signature_is_type_only(signature: &str) -> bool {
    let signature = signature.trim_start();
    signature.starts_with("interface ")
        || signature.starts_with("export interface ")
        || signature.starts_with("declare interface ")
        || signature.starts_with("export declare interface ")
        || signature.starts_with("type ")
        || signature.starts_with("export type ")
        || signature.starts_with("declare type ")
        || signature.starts_with("export declare type ")
}

fn is_bare_js_ts_specifier(module: &str) -> bool {
    !module.starts_with("./") && !module.starts_with("../") && !module.starts_with('/')
}

pub(crate) fn parse_js_ts_tree(
    file: &ProjectFile,
    source: &str,
    language: Language,
) -> Option<Tree> {
    let mut parser = Parser::new();
    let tree_sitter_language =
        crate::analyzer::usages::parsed_tree::js_ts_tree_sitter_language_for_file(file, language)?;
    parser.set_language(&tree_sitter_language).ok()?;
    parser.parse(source, None)
}
