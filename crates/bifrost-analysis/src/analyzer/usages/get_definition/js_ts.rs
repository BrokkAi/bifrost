use super::*;
use crate::analyzer::BoundedDefinitionLookup;
use crate::analyzer::js_ts::providers::resolve_js_ts_source;
use crate::analyzer::tree_walk::subtree_contains;
use crate::analyzer::usages::js_ts_graph::{
    browser_global_property_shape, unbound_browser_global_property,
};
use brokk_bifrost_js_ts::imports::{
    resolve_js_ts_direct_import_candidates, resolve_js_ts_module_binding_candidates,
};
use brokk_bifrost_js_ts::providers::JsTsSource;
use brokk_bifrost_js_ts::syntax::parse_js_ts_tree;
use brokk_bifrost_js_ts::syntax::{
    JsTsImportBinder, JsTsLexicalBindingIndex, MAX_STATIC_IMPORT_BINDINGS_PER_NAME,
    direct_property_definitions, is_declaration_identifier, is_explicit_object_literal_key, slice,
};
/// The receiver-owner / type-text cluster this route drives now lives beside the
/// rest of the JS/TS language logic, so the usage graph can call it without
/// importing the definition route. The route imports it back, the mirror of what
/// `js_ts/syntax.rs` already is (issue: the js_ts crate extraction, Js-1b).
use brokk_bifrost_js_ts::ts_owners::{
    TsReceiverResolution, jsts_constructor_owner_candidates, jsts_enclosing_function_scope,
    jsts_identifier_candidates, jsts_member_candidates, node_text_matches, root_node,
    ts_call_expression_callees, ts_direct_object_literal_value,
    ts_expand_call_return_property_owners, ts_nodes_for_code_unit, ts_parameter_name_node,
    ts_receiver_owner_candidates_at_byte, ts_resolve_type_text_to_property_owners,
    ts_unwrap_expression,
};
use brokk_bifrost_js_ts::type_text::{
    jsts_type_space_candidates, jsts_unit_is_type_only, jsts_value_space_candidates,
    ts_type_annotation_text,
};
use brokk_bifrost_js_ts::typescript::ts_is_global_internal_module;

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
    context: &mut DefinitionBatchContext<'_>,
    file: &ProjectFile,
    language: Language,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(tree) = tree else {
        return no_definition("jsts_parse_failed", "JS/TS source could not be parsed");
    };
    // The one downcast for the whole route: the JS/TS candidate logic is
    // parameterized on `JsTsSource`, and `host` is threaded from here
    // rather than re-derived at each call. Without the matching analyzer there
    // is no JS/TS declaration index either, so every candidate this route could
    // produce would be empty anyway.
    let Some(host) = resolve_js_ts_source(analyzer, language) else {
        return no_definition(
            "jsts_analyzer_unavailable",
            "no JavaScript/TypeScript analyzer is registered for this workspace",
        );
    };
    let batch = context.js_ts_context(file, language, source, tree);
    let support = context.bounded_support();
    let reference = site.text.as_str();
    let value_position = jsts_reference_is_value_position(tree, site);
    let imports = &batch.imports;
    let aliases = batch.aliases.as_ref();
    let lexical_bindings = JsTsLexicalBindingIndex::build(tree.root_node(), source);
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte);

    if focused.is_some_and(|node| {
        jsts_is_commonjs_host_export_assignment_object(node, source)
            && jsts_visible_receiver_binding_scope(
                tree.root_node(),
                source,
                "module",
                site.focus_start_byte,
            )
            .is_none()
    }) {
        return no_definition(
            "commonjs_host_binding",
            "the CommonJS `module` host binding is provided by the runtime and has no workspace definition",
        );
    }

    if let Some(targets) = focused.and_then(|node| {
        JsTsReceiverFactProvider::new_with_batch_data(
            host,
            support,
            language,
            file,
            source,
            tree.root_node(),
            imports.clone(),
            Arc::clone(&batch.aliases),
            Arc::clone(&batch.syntax_index),
        )
        .resolve_jsx_attribute_targets(node, ReceiverAnalysisBudget::default())
    }) {
        return if targets.is_empty() {
            no_definition(
                "unresolved_jsx_attribute_owner",
                format!("the JSX component's `{reference}` prop owner could not be proven"),
            )
        } else {
            js_ts_candidates_outcome(analyzer, targets)
        };
    }

    if language == Language::TypeScript {
        let contextual_members = ts_contextual_object_literal_key_candidates(
            analyzer, host, support, file, source, tree, site, imports, aliases,
        );
        if !contextual_members.is_empty() {
            return js_ts_candidates_outcome(analyzer, contextual_members);
        }
    }

    if focused
        .is_some_and(|node| is_declaration_identifier(node) || is_explicit_object_literal_key(node))
    {
        return no_definition(
            "declaration_site",
            "JS/TS declaration and explicit object-key names do not reference indexed definitions",
        );
    }
    if !reference.contains(['.', ':'])
        && jsts_visible_receiver_binding_scope(
            tree.root_node(),
            source,
            reference,
            site.focus_start_byte,
        )
        .is_some_and(|scope| {
            scope.start_byte != tree.root_node().start_byte()
                || scope.end_byte != tree.root_node().end_byte()
        })
    {
        return no_definition(
            "local_binding",
            format!("`{reference}` is a local JS/TS binding, which is not indexed"),
        );
    }

    // AST path for an inline construction receiver `new Foo().member` — the
    // text-split path below cannot express `new Foo()` as a qualifier.
    if let Some(members) = jsts_construction_receiver_members(
        analyzer, host, support, file, language, source, tree, site,
    ) {
        return js_ts_candidates_outcome(analyzer, members);
    }

    if let Some((qualifier, name)) = reference.split_once('.') {
        let visible_bindings = jsts_all_visible_import_bindings(
            imports,
            &lexical_bindings,
            tree.root_node(),
            qualifier,
            site.focus_start_byte,
        );
        let namespace_outcomes = visible_bindings
            .iter()
            .filter(|binding| {
                matches!(
                    binding.kind,
                    ImportKind::Namespace | ImportKind::CommonJsRequire
                )
            })
            .map(|binding| {
                resolve_js_ts_module_binding(
                    file,
                    language,
                    &binding.module_specifier,
                    name,
                    analyzer,
                    host,
                    support,
                    Some(aliases),
                    value_position,
                )
            })
            .collect::<Vec<_>>();
        if let Some(outcome) = merge_js_ts_binding_outcomes(
            analyzer,
            reference,
            namespace_outcomes,
            imports.was_truncated(qualifier),
        ) {
            return outcome;
        }
        let imported_receiver_binding = !visible_bindings.is_empty()
            && imports
                .resolvable_direct_bindings_for(qualifier)
                .next()
                .is_some();
        let receiver_candidates = if imported_receiver_binding {
            resolve_js_ts_direct_import_candidates(
                host,
                support,
                language,
                file,
                imports,
                qualifier,
                Some(aliases),
                value_position,
            )
            .unwrap_or_default()
        } else {
            let mut same_file = support.file_identifier(file, qualifier);
            if value_position {
                same_file = jsts_value_space_candidates(host, same_file);
            } else {
                same_file = jsts_type_space_candidates(host, same_file);
            }
            same_file
        };
        let generic_member_candidates =
            if language == Language::JavaScript && imported_receiver_binding {
                jsts_file_scoped_member_candidates(
                    host,
                    support,
                    receiver_candidates,
                    name,
                    value_position,
                )
            } else if language == Language::TypeScript {
                ts_member_candidates(
                    analyzer,
                    host,
                    support,
                    receiver_candidates,
                    name,
                    value_position,
                )
            } else {
                jsts_member_candidates(host, support, receiver_candidates, name, value_position)
            };
        let program_binding = lexical_bindings.is_program_binding_at(
            qualifier,
            site.focus_start_byte,
            tree.root_node(),
        );
        let dotted_lookup = JstsDottedLookup {
            analyzer,
            host,
            support,
            file,
            root: tree.root_node(),
            source,
            reference,
            receiver: qualifier,
            value_position,
            before_byte: site.range.start_byte,
        };
        if language == Language::JavaScript
            && !imported_receiver_binding
            && let Some(local_candidates) = focused.and_then(|node| {
                jsts_exact_local_dotted_candidates(
                    dotted_lookup,
                    &lexical_bindings,
                    node,
                    &generic_member_candidates,
                )
            })
        {
            if !local_candidates.is_empty() {
                return js_ts_candidates_outcome(analyzer, local_candidates);
            }
            return no_definition(
                "no_indexed_definition",
                format!("`{reference}` did not resolve to an indexed JS/TS definition"),
            );
        }
        if (imported_receiver_binding || program_binding) && !generic_member_candidates.is_empty() {
            return js_ts_candidates_outcome(analyzer, generic_member_candidates);
        }
        match jsts_receiver_provider_member_candidates(
            host, support, file, language, source, tree, site, name, &batch,
        ) {
            ReceiverAnalysisOutcome::Precise(candidates) if !candidates.is_empty() => {
                let candidates = if language == Language::TypeScript {
                    if value_position {
                        jsts_value_space_candidates(host, candidates)
                    } else {
                        jsts_type_space_candidates(host, candidates)
                    }
                } else {
                    jsts_value_space_candidates(host, candidates)
                };
                if language == Language::JavaScript
                    && !imported_receiver_binding
                    && let Some(local_candidates) = focused.and_then(|node| {
                        jsts_exact_local_dotted_candidates(
                            dotted_lookup,
                            &lexical_bindings,
                            node,
                            &candidates,
                        )
                    })
                {
                    if !local_candidates.is_empty() {
                        return js_ts_candidates_outcome(analyzer, local_candidates);
                    }
                    return no_definition(
                        "no_indexed_definition",
                        format!("`{reference}` did not resolve to an indexed JS/TS definition"),
                    );
                }
                return js_ts_candidates_outcome(analyzer, candidates);
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
            host,
            support,
            file,
            language,
            source,
            tree.root_node(),
            imports,
            aliases,
            qualifier,
            site.range.start_byte,
            0,
        );
        let new_receiver_member_candidates = if language == Language::TypeScript {
            ts_member_candidates(
                analyzer,
                host,
                support,
                new_receiver_candidates,
                name,
                value_position,
            )
        } else {
            jsts_member_candidates(host, support, new_receiver_candidates, name, value_position)
        };
        if !new_receiver_member_candidates.is_empty() {
            return js_ts_candidates_outcome(analyzer, new_receiver_member_candidates);
        }
        if !generic_member_candidates.is_empty() {
            return js_ts_candidates_outcome(analyzer, generic_member_candidates);
        }
        let exact_same_file = jsts_unproven_same_file_dotted_candidates(dotted_lookup);
        if !exact_same_file.is_empty() {
            return js_ts_candidates_outcome(analyzer, exact_same_file);
        }
        if language == Language::TypeScript {
            let inferred_receivers = ts_local_receiver_owner_candidates(
                host, support, file, source, tree, site, imports, aliases, qualifier,
            );
            let inferred_member_candidates = ts_member_candidates(
                analyzer,
                host,
                support,
                inferred_receivers,
                name,
                value_position,
            );
            if !inferred_member_candidates.is_empty() {
                return js_ts_candidates_outcome(analyzer, inferred_member_candidates);
            }
            let inferred_receivers = ts_local_receiver_owner_candidates(
                host, support, file, source, tree, site, imports, aliases, qualifier,
            );
            let inferred_member_candidates = jsts_file_scoped_member_candidates(
                host,
                support,
                inferred_receivers,
                name,
                value_position,
            );
            if !inferred_member_candidates.is_empty() {
                return js_ts_candidates_outcome(analyzer, inferred_member_candidates);
            }
            if let Some(receiver_type) = ts_global_object_receiver_type(qualifier) {
                let global_receivers = support
                    .fqn(receiver_type)
                    .into_iter()
                    .filter(|unit| jsts_unit_is_type_only(host, unit))
                    .collect();
                let global_member_candidates = ts_member_candidates(
                    analyzer,
                    host,
                    support,
                    global_receivers,
                    name,
                    value_position,
                );
                if !global_member_candidates.is_empty() {
                    return js_ts_candidates_outcome(analyzer, global_member_candidates);
                }
            }
        }
        if language == Language::TypeScript {
            let exact_global = ts_exact_global_dotted_candidates(
                analyzer,
                host,
                support,
                reference,
                value_position,
            );
            if !exact_global.is_empty() {
                return js_ts_candidates_outcome(analyzer, exact_global);
            }
        } else {
            let exact_project = jsts_exact_dotted_candidates(
                analyzer,
                host,
                support,
                file,
                reference,
                value_position,
            );
            if !exact_project.is_empty() {
                return js_ts_candidates_outcome(analyzer, exact_project);
            }
        }
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve to an indexed JS/TS definition"),
        );
    }

    if let Some(outcome) = resolve_js_ts_visible_module_bindings(
        jsts_visible_import_bindings(
            imports,
            &lexical_bindings,
            tree.root_node(),
            reference,
            site.focus_start_byte,
        ),
        imports.was_truncated(reference),
        file,
        language,
        reference,
        analyzer,
        host,
        support,
        Some(aliases),
        value_position,
    ) {
        return outcome;
    }

    let same_file_candidates = support.file_identifier(file, reference);
    let mut same_file: Vec<_> = same_file_candidates
        .iter()
        .filter(|candidate| jsts_candidate_is_bare_declaration(file, reference, candidate))
        .cloned()
        .collect();
    if same_file.is_empty() && language == Language::JavaScript {
        same_file = jsts_exact_browser_global_bare_candidates(
            analyzer,
            tree.root_node(),
            source,
            reference,
            &same_file_candidates,
        );
    }
    if value_position {
        same_file = jsts_value_space_candidates(host, same_file);
    } else {
        same_file = jsts_type_space_candidates(host, same_file);
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
fn resolve_js_ts_visible_module_bindings(
    bindings: Vec<&crate::analyzer::usages::ImportBinding>,
    bindings_truncated: bool,
    file: &ProjectFile,
    language: Language,
    reference: &str,
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    aliases: Option<&AliasResolver>,
    value_position: bool,
) -> Option<DefinitionLookupOutcome> {
    let outcomes = bindings
        .into_iter()
        .map(|binding| {
            let exported_name = match binding.kind {
                ImportKind::Named => binding.imported_name.as_deref().unwrap_or(reference),
                ImportKind::Default => "default",
                _ => unreachable!("bindings were filtered to direct module imports"),
            };
            resolve_js_ts_module_binding(
                file,
                language,
                &binding.module_specifier,
                exported_name,
                analyzer,
                host,
                support,
                aliases,
                value_position,
            )
        })
        .collect::<Vec<_>>();
    merge_js_ts_binding_outcomes(analyzer, reference, outcomes, bindings_truncated)
}

fn merge_js_ts_binding_outcomes(
    analyzer: &dyn IAnalyzer,
    reference: &str,
    mut outcomes: Vec<DefinitionLookupOutcome>,
    bindings_truncated: bool,
) -> Option<DefinitionLookupOutcome> {
    if outcomes.is_empty() {
        return None;
    }
    if outcomes.len() == 1 && !bindings_truncated {
        return outcomes.pop();
    }

    let mut definitions = Vec::new();
    let mut diagnostics = Vec::new();
    let mut crossed_external_boundary = false;
    let mut unresolved_import = false;
    for outcome in outcomes {
        match outcome.status {
            DefinitionLookupStatus::UnresolvableImportBoundary => crossed_external_boundary = true,
            DefinitionLookupStatus::NoDefinition
            | DefinitionLookupStatus::UnsupportedLanguage
            | DefinitionLookupStatus::InvalidLocation
            | DefinitionLookupStatus::NotFound => unresolved_import = true,
            DefinitionLookupStatus::Resolved | DefinitionLookupStatus::Ambiguous => {}
        }
        definitions.extend(outcome.definitions);
        diagnostics.extend(outcome.diagnostics);
    }
    let mut outcome = if definitions.is_empty() {
        DefinitionLookupOutcome {
            status: DefinitionLookupStatus::Ambiguous,
            reference: None,
            definitions,
            lexical_definition: None,
            diagnostics,
        }
    } else {
        let mut outcome = js_ts_candidates_outcome(analyzer, definitions);
        outcome.status = DefinitionLookupStatus::Ambiguous;
        outcome.diagnostics.extend(diagnostics);
        outcome
    };
    outcome.diagnostics.push(DefinitionLookupDiagnostic {
        kind: "ambiguous_definition".to_string(),
        message: format!("`{reference}` is supplied by multiple visible imports"),
    });
    if crossed_external_boundary {
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: PARTIAL_IMPORT_BOUNDARY_DIAGNOSTIC.to_string(),
            message: format!(
                "at least one competing import for `{reference}` crosses the indexed workspace boundary"
            ),
        });
    }
    if unresolved_import {
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: PARTIAL_IMPORT_UNRESOLVED_DIAGNOSTIC.to_string(),
            message: format!(
                "at least one competing import for `{reference}` could not be resolved"
            ),
        });
    }
    if bindings_truncated {
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: IMPORT_BINDINGS_TRUNCATED_DIAGNOSTIC.to_string(),
            message: format!(
                "competing imports for `{reference}` exceeded the per-name limit of {MAX_STATIC_IMPORT_BINDINGS_PER_NAME}"
            ),
        });
    }
    Some(outcome)
}

fn jsts_candidate_is_bare_declaration(
    file: &ProjectFile,
    reference: &str,
    candidate: &CodeUnit,
) -> bool {
    if candidate.short_name() == reference {
        return true;
    }
    let Some(file_name) = file.rel_path().file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    candidate.is_field() && candidate.short_name() == format!("{file_name}.{reference}")
}

fn jsts_exact_browser_global_bare_candidates(
    analyzer: &dyn IAnalyzer,
    root: Node<'_>,
    source: &str,
    reference: &str,
    candidates: &[CodeUnit],
) -> Vec<CodeUnit> {
    let shaped: Vec<_> = candidates
        .iter()
        .filter(|candidate| {
            browser_global_property_shape(candidate)
                .is_some_and(|(object, property)| object == "window" && property == reference)
        })
        .collect();
    if shaped.is_empty() {
        return Vec::new();
    }

    let lexical_bindings = JsTsLexicalBindingIndex::build(root, source);
    shaped
        .into_iter()
        .filter(|candidate| {
            unbound_browser_global_property(analyzer, candidate, root, source, &lexical_bindings)
                .is_some()
        })
        .cloned()
        .collect()
}

fn jsts_is_commonjs_host_export_assignment_object(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "identifier" || node_text(node, source) != "module" {
        return false;
    }
    let Some(exports_member) = node.parent().filter(|parent| {
        parent.kind() == "member_expression"
            && parent
                .child_by_field_name("object")
                .is_some_and(|object| object.id() == node.id())
            && parent
                .child_by_field_name("property")
                .is_some_and(|property| node_text(property, source) == "exports")
    }) else {
        return false;
    };

    let mut assignment_target = exports_member;
    while let Some(parent) = assignment_target.parent().filter(|parent| {
        parent.kind() == "member_expression"
            && parent
                .child_by_field_name("object")
                .is_some_and(|object| object.id() == assignment_target.id())
    }) {
        assignment_target = parent;
    }

    assignment_target
        .parent()
        .filter(|parent| parent.kind() == "assignment_expression")
        .and_then(|assignment| assignment.child_by_field_name("left"))
        .is_some_and(|left| left.id() == assignment_target.id())
}

#[allow(clippy::too_many_arguments)]
fn ts_contextual_object_literal_key_candidates(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    imports: &JsTsImportBinder,
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
    let owners =
        ts_contextual_object_literal_owners(host, support, file, source, imports, aliases, object);
    ts_member_candidates(analyzer, host, support, owners, &name, true)
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
    let name = brokk_bifrost_js_ts::typescript::ts_object_literal_property_name(property, source)?;
    Some((property, object, name))
}

#[allow(clippy::too_many_arguments)]
fn ts_contextual_object_literal_owners(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
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
            host,
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
        host,
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
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    aliases: Option<&AliasResolver>,
    value_position: bool,
) -> DefinitionLookupOutcome {
    let files = crate::analyzer::resolve_js_ts_module_specifier(file, module, language, aliases);
    if files.is_empty() {
        // Only a bare specifier (`react`, `lodash`) is a confident external
        // package boundary. A relative/absolute specifier (`./`, `../`, `/`)
        // that resolves to no file is an in-workspace path that did not land —
        // a typo or a not-yet-indexed sibling — never a confident cross-workspace
        // claim (#1158): treat the relative shape as workspace-internal so the
        // gate yields `no_definition` instead of `boundary`.
        return gated_boundary(
            || !is_bare_js_ts_specifier(module),
            format!("`{module}` is a package import outside this partial workspace analysis"),
            "no_indexed_definition",
            format!("`{module}` could not be resolved to a workspace JS/TS file"),
        );
    }

    let candidates = resolve_js_ts_module_binding_candidates(
        host,
        support,
        language,
        file,
        module,
        exported_name,
        aliases,
        value_position,
    );
    if candidates.is_empty() {
        if let Some((reexport_file, external_module)) = cached_jsts_index(analyzer, language, None)
            .and_then(|index| index.unresolved_reexport_boundary(&files, exported_name))
        {
            // gated upstream: `unresolved_reexport_boundary` only returns Some for
            // a re-export chain that terminates outside the indexed workspace.
            return boundary_unchecked(format!(
                "`{exported_name}` is re-exported by `{}` from `{external_module}`, which is outside the indexed workspace",
                rel_path_string(&reexport_file)
            ));
        }
        return no_definition(
            "no_indexed_definition",
            format!("`{exported_name}` is not indexed in `{module}`"),
        );
    }
    js_ts_candidates_outcome(analyzer, candidates)
}

/// Resolve a dotted FQN within one exact declaration file. JS/TS FQNs omit module
/// paths, so callers that have already resolved a receiver must retain this scope.
fn jsts_file_scoped_dotted_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
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
        candidates = jsts_value_space_candidates(host, candidates);
    } else {
        candidates = jsts_type_space_candidates(host, candidates);
    }
    candidates
}

fn jsts_unproven_same_file_dotted_candidates(ctx: JstsDottedLookup<'_, '_>) -> Vec<CodeUnit> {
    let mut candidates = ctx.same_file_candidates();
    candidates.retain(|unit| {
        !jsts_js_unbound_assigned_property_candidate_requires_exact_receiver(
            ctx.analyzer,
            unit,
            ctx.receiver,
        ) || jsts_same_file_unbound_assignment_matches_reference_scope(
            ctx.analyzer,
            unit,
            ctx.receiver,
            ctx.root,
            ctx.source,
            ctx.before_byte,
        )
    });
    candidates
}

fn jsts_same_file_unbound_assignment_matches_reference_scope(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    qualifier: &str,
    root: Node<'_>,
    source: &str,
    before_byte: usize,
) -> bool {
    let Some((object_name, property_name)) = jsts_unbound_assigned_property_shape(analyzer, target)
    else {
        return false;
    };
    if object_name != qualifier {
        return false;
    }
    let target_ranges = analyzer.ranges(target);
    let reference_scope = smallest_named_node_covering(root, before_byte, before_byte)
        .and_then(jsts_nearest_reference_fallback_scope)
        .unwrap_or(JstsReceiverBindingScope {
            start_byte: root.start_byte(),
            end_byte: root.end_byte(),
        });

    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "member_expression"
            && node.parent().is_some_and(|parent| {
                parent.kind() == "assignment_expression"
                    && parent
                        .child_by_field_name("left")
                        .is_some_and(|left| left.id() == node.id())
            })
            && let (Some(object), Some(property)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("property"),
            )
            && node_text(object, source) == object_name
            && node_text(property, source) == property_name
            && property.start_byte() < before_byte
            && target_ranges.iter().any(|range| {
                range.start_byte <= property.start_byte() && property.end_byte() <= range.end_byte
            })
        {
            let assignment_scope =
                jsts_nearest_reference_fallback_scope(node).unwrap_or(JstsReceiverBindingScope {
                    start_byte: root.start_byte(),
                    end_byte: root.end_byte(),
                });
            if assignment_scope == reference_scope {
                return true;
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    false
}

fn jsts_nearest_reference_fallback_scope(node: Node<'_>) -> Option<JstsReceiverBindingScope> {
    jsts_nearest_lexical_scope(node).or_else(|| jsts_nearest_var_scope(node))
}

#[derive(Clone, Copy)]
struct JstsDottedLookup<'a, 'tree> {
    analyzer: &'a dyn IAnalyzer,
    host: &'a dyn JsTsSource,
    support: &'a dyn BoundedDefinitionLookup,
    file: &'a ProjectFile,
    root: Node<'tree>,
    source: &'a str,
    reference: &'a str,
    receiver: &'a str,
    value_position: bool,
    before_byte: usize,
}

impl JstsDottedLookup<'_, '_> {
    fn same_file_candidates(self) -> Vec<CodeUnit> {
        jsts_file_scoped_dotted_candidates(
            self.host,
            self.support,
            self.file,
            self.reference,
            self.value_position,
        )
    }
}

fn jsts_exact_local_dotted_candidates(
    ctx: JstsDottedLookup<'_, '_>,
    lexical_bindings: &JsTsLexicalBindingIndex,
    focused: Node<'_>,
    hinted_candidates: &[CodeUnit],
) -> Option<Vec<CodeUnit>> {
    let binding_scope = lexical_bindings.binding_scope_at(ctx.receiver, ctx.before_byte)?;
    let (reference_receiver, property) =
        jsts_focused_reference_receiver_property(focused, ctx.source)?;
    let target_member = slice(property, ctx.source);
    if target_member.is_empty() || slice(reference_receiver.root, ctx.source) != ctx.receiver {
        return None;
    }

    let mut candidates = ctx.same_file_candidates();
    candidates.extend(
        hinted_candidates
            .iter()
            .filter(|candidate| candidate.source() == ctx.file)
            .cloned(),
    );
    sort_units(&mut candidates);
    candidates.dedup();
    let candidates_with_definitions: Vec<_> = candidates
        .into_iter()
        .filter_map(|candidate| {
            let definitions = direct_property_definitions(
                ctx.root,
                ctx.source,
                &ctx.analyzer.ranges(&candidate),
                target_member,
            );
            (!definitions.is_empty()).then_some((candidate, definitions))
        })
        .collect();
    if candidates_with_definitions.is_empty() {
        return None;
    }
    let candidates = candidates_with_definitions
        .into_iter()
        .filter_map(|(candidate, definitions)| {
            definitions
                .into_iter()
                .any(|definition| {
                    slice(definition.receiver.root, ctx.source) == ctx.receiver
                        && definition.receiver.members.len() == reference_receiver.members.len()
                        && definition
                            .receiver
                            .members
                            .iter()
                            .zip(&reference_receiver.members)
                            .all(|(actual, expected)| {
                                slice(*actual, ctx.source) == slice(*expected, ctx.source)
                            })
                        && lexical_bindings
                            .binding_scope_at(ctx.receiver, definition.receiver.root.start_byte())
                            == Some(binding_scope)
                        && definition.property_range.end_byte <= ctx.before_byte
                })
                .then_some(candidate)
        })
        .collect();
    Some(candidates)
}

fn jsts_all_visible_import_bindings<'a>(
    imports: &'a JsTsImportBinder,
    lexical_bindings: &JsTsLexicalBindingIndex,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Vec<&'a crate::analyzer::usages::ImportBinding> {
    if lexical_bindings.is_program_binding_at(name, byte, root) {
        imports.bindings_for(name).collect()
    } else {
        Vec::new()
    }
}

fn jsts_visible_import_bindings<'a>(
    imports: &'a JsTsImportBinder,
    lexical_bindings: &JsTsLexicalBindingIndex,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Vec<&'a crate::analyzer::usages::ImportBinding> {
    if lexical_bindings.is_program_binding_at(name, byte, root) {
        imports.resolvable_direct_bindings_for(name).collect()
    } else {
        Vec::new()
    }
}

fn jsts_focused_reference_receiver_property<'tree>(
    focused: Node<'tree>,
    source: &str,
) -> Option<(
    brokk_bifrost_js_ts::syntax::JsTsStaticMemberReceiver<'tree>,
    Node<'tree>,
)> {
    let member_expression = match focused.kind() {
        "member_expression" => focused,
        "property_identifier" => focused
            .parent()
            .filter(|parent| parent.kind() == "member_expression")?,
        _ => return None,
    };
    let object = member_expression.child_by_field_name("object")?;
    let property = member_expression.child_by_field_name("property")?;
    let receiver = brokk_bifrost_js_ts::syntax::static_member_receiver(object, source)?;
    Some((receiver, property))
}

fn jsts_exact_dotted_candidates(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    reference: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let qualifier = reference.split_once('.').map(|(qualifier, _)| qualifier);
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
    if let Some(qualifier) = qualifier {
        candidates.retain(|unit| {
            (unit.source() == file
                || jsts_cross_file_dotted_receiver_has_global_identity(analyzer, unit, qualifier))
                && !jsts_js_unbound_assigned_property_candidate_requires_exact_receiver(
                    analyzer, unit, qualifier,
                )
        });
    }
    if value_position {
        candidates = jsts_value_space_candidates(host, candidates);
    } else {
        candidates = jsts_type_space_candidates(host, candidates);
    }
    candidates
}

fn jsts_cross_file_dotted_receiver_has_global_identity(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    receiver: &str,
) -> bool {
    let language = crate::analyzer::common::language_for_file(candidate.source());
    if !matches!(language, Language::JavaScript | Language::TypeScript) {
        return false;
    }
    let Ok(source) = candidate.source().read_to_string() else {
        return false;
    };
    let Some(tree) = parse_js_ts_tree(candidate.source(), &source, language) else {
        return false;
    };
    let root = tree.root_node();
    if jsts_program_is_external_module(root, &source) {
        return false;
    }
    analyzer.ranges(candidate).iter().any(|range| {
        jsts_visible_receiver_binding_scope(root, &source, receiver, range.start_byte)
            == Some(JstsReceiverBindingScope {
                start_byte: root.start_byte(),
                end_byte: root.end_byte(),
            })
    })
}

fn jsts_program_is_external_module(root: Node<'_>, source: &str) -> bool {
    let mut cursor = root.walk();
    root.named_children(&mut cursor).any(|statement| {
        matches!(statement.kind(), "import_statement" | "export_statement")
            || subtree_contains(statement, |node| {
                (node.kind() == "call_expression"
                    && node.child_by_field_name("function").is_some_and(|callee| {
                        callee.kind() == "identifier" && node_text(callee, source) == "require"
                    }))
                    || (node.kind() == "assignment_expression"
                        && node
                            .child_by_field_name("left")
                            .and_then(jsts_static_member_root)
                            .is_some_and(|root| {
                                matches!(node_text(root, source), "exports" | "module")
                            }))
            })
    })
}

fn jsts_static_member_root(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" => return Some(node),
            "member_expression" => node = node.child_by_field_name("object")?,
            _ => return None,
        }
    }
}

fn ts_exact_global_dotted_candidates(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    reference: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = support
        .fqn(reference)
        .into_iter()
        .filter(|candidate| ts_unit_is_global_declaration(analyzer, candidate))
        .collect();
    if value_position {
        candidates = jsts_value_space_candidates(host, candidates);
    } else {
        candidates = jsts_type_space_candidates(host, candidates);
    }
    candidates
}

fn ts_unit_is_global_declaration(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    let Ok(source) = unit.source().read_to_string() else {
        return false;
    };
    let Some(tree) = parse_js_ts_tree(unit.source(), &source, Language::TypeScript) else {
        return false;
    };
    let root = tree.root_node();
    let mut cursor = root.walk();
    let is_external_module = root
        .named_children(&mut cursor)
        .any(|child| matches!(child.kind(), "import_statement" | "export_statement"));
    if !is_external_module {
        return true;
    }
    let global_namespace_exports = ts_global_namespace_exports(root, &source);

    analyzer.ranges(unit).iter().any(|range| {
        let Some(mut node) = smallest_named_node_covering(root, range.start_byte, range.end_byte)
        else {
            return false;
        };
        loop {
            if ts_is_global_internal_module(node, &source) {
                return true;
            }
            if node.kind() == "internal_module"
                && node
                    .child_by_field_name("name")
                    .map(|name| node_text(name, &source).to_string())
                    .is_some_and(|name| global_namespace_exports.contains(&name))
            {
                return true;
            }
            let Some(parent) = node.parent() else {
                return false;
            };
            node = parent;
        }
    })
}

fn ts_global_namespace_exports(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut names = HashSet::default();
    let mut cursor = root.walk();
    for statement in root
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "export_statement")
    {
        let mut has_as = false;
        let mut has_namespace = false;
        for index in 0..statement.child_count() {
            let Some(child) = statement.child(index) else {
                continue;
            };
            match child.kind() {
                "as" => has_as = true,
                "namespace" => has_namespace = true,
                _ => {}
            }
        }
        if has_as
            && has_namespace
            && let Some(name) = statement
                .named_children(&mut statement.walk())
                .find(|child| child.kind() == "identifier")
        {
            names.insert(node_text(name, source).to_string());
        }
    }
    names
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
            | "for_statement"
            | "for_in_statement"
            | "switch_statement"
            | "catch_clause"
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
    let scope_range = JstsReceiverBindingScope {
        start_byte: scope.start_byte(),
        end_byte: scope.end_byte(),
    };
    jsts_scope_contains_binding_before(scope, source, name, before_byte, scope_range)
}

fn jsts_scope_contains_binding_before(
    scope: Node<'_>,
    source: &str,
    name: &str,
    before_byte: usize,
    scope_range: JstsReceiverBindingScope,
) -> bool {
    let root_id = scope.id();
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        if node.id() != root_id
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
            )
        {
            continue;
        }
        if matches!(
            node.kind(),
            "formal_parameter"
                | "required_parameter"
                | "optional_parameter"
                | "variable_declarator"
        ) && let Some(pattern) = node
            .child_by_field_name("pattern")
            .or_else(|| node.child_by_field_name("name"))
            && jsts_pattern_contains_name(pattern, source, name)
            && jsts_binding_scope_for_declaration(node, source) == Some(scope_range)
        {
            return true;
        }
        if matches!(node.kind(), "identifier" | "type_identifier")
            && jsts_identifier_is_parameter(node)
            && source
                .get(node.start_byte()..node.end_byte())
                .is_some_and(|text| text.trim() == name)
            && jsts_binding_scope_for_declaration(node, source) == Some(scope_range)
        {
            return true;
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node
            .named_children(&mut cursor)
            .take_while(|child| child.start_byte() < before_byte)
            .collect();
        stack.extend(children.into_iter().rev());
    }
    false
}

fn jsts_identifier_is_parameter(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(parent.kind(), "formal_parameters" | "parameters")
        || (parent.kind() == "arrow_function"
            && parent
                .child_by_field_name("parameter")
                .is_some_and(|parameter| parameter.id() == node.id()))
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
    subtree_contains(node, |node| {
        matches!(
            node.kind(),
            "identifier" | "shorthand_property_identifier_pattern"
        ) && source
            .get(node.start_byte()..node.end_byte())
            .is_some_and(|text| text.trim() == name)
    })
}

fn jsts_top_level_path_component(file: &ProjectFile) -> Option<&str> {
    file.rel_path()
        .components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
}

fn jsts_js_unbound_assigned_property_candidate_requires_exact_receiver(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    qualifier: &str,
) -> bool {
    let Some((object_name, _property_name)) =
        jsts_unbound_assigned_property_shape(analyzer, candidate)
    else {
        return false;
    };
    object_name == qualifier && object_name != "window"
}

fn jsts_unbound_assigned_property_shape<'a>(
    analyzer: &dyn IAnalyzer,
    target: &'a CodeUnit,
) -> Option<(&'a str, &'a str)> {
    if !target.is_field() && !target.is_function() {
        return None;
    }
    let [object_id, property_id] = target.fq().segments() else {
        return None;
    };
    let interner = crate::analyzer::fq_name::segment_interner();
    let (object_name, _) = interner.resolve(*object_id);
    let (property_name, _) = interner.resolve(*property_id);
    if object_name.is_empty() || property_name.is_empty() {
        return None;
    }

    let language = crate::analyzer::common::language_for_file(target.source());
    if !matches!(language, Language::JavaScript | Language::TypeScript) {
        return None;
    }
    let Ok(source) = target.source().read_to_string() else {
        return None;
    };
    let tree = parse_js_ts_tree(target.source(), &source, language)?;
    let root = tree.root_node();
    let lexical_bindings = JsTsLexicalBindingIndex::build(root, &source);
    let target_ranges = analyzer.ranges(target);

    let mut found = false;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "member_expression"
            && node.parent().is_some_and(|parent| {
                parent.kind() == "assignment_expression"
                    && parent
                        .child_by_field_name("left")
                        .is_some_and(|left| left.id() == node.id())
            })
            && let (Some(object), Some(property)) = (
                node.child_by_field_name("object"),
                node.child_by_field_name("property"),
            )
            && node_text(object, &source) == object_name
            && node_text(property, &source) == property_name
            && target_ranges.iter().any(|range| {
                range.start_byte <= property.start_byte() && property.end_byte() <= range.end_byte
            })
        {
            found = true;
            if lexical_bindings.is_bound_at(object_name, object.start_byte()) {
                return None;
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }

    found.then_some((object_name, property_name))
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
#[allow(clippy::too_many_arguments)]
fn jsts_construction_receiver_members(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
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
        jsts_value_space_candidates(host, support.file_identifier(file, class_name));
    let members = if language == Language::TypeScript {
        ts_member_candidates(analyzer, host, support, receiver_candidates, member, true)
    } else {
        jsts_member_candidates(host, support, receiver_candidates, member, true)
    };
    (!members.is_empty()).then_some(members)
}

#[allow(clippy::too_many_arguments)]
fn jsts_receiver_provider_member_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    language: Language,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    member: &str,
    batch: &JsTsDefinitionContext,
) -> ReceiverAnalysisOutcome<CodeUnit> {
    let node =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte);
    let Some(node) = node else {
        return ReceiverAnalysisOutcome::Unknown;
    };
    let provider = JsTsReceiverFactProvider::new_with_batch_data(
        host,
        support,
        language,
        file,
        source,
        tree.root_node(),
        batch.imports.clone(),
        Arc::clone(&batch.aliases),
        Arc::clone(&batch.syntax_index),
    );
    provider
        .resolve_member_targets_at_site(
            node,
            Some(member),
            site.focus_start_byte,
            ReceiverAnalysisBudget::default(),
        )
        .map(|report| report.analysis.outcome)
        .unwrap_or(ReceiverAnalysisOutcome::Unknown)
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    crate::analyzer::common::node_source_text(node, source)
}

fn jsts_file_scoped_member_candidates(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    receiver_candidates: Vec<CodeUnit>,
    member: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for receiver in receiver_candidates {
        candidates.extend(jsts_file_scoped_dotted_candidates(
            host,
            support,
            receiver.source(),
            &format!("{}.{}", receiver.fq_name(), member),
            value_position,
        ));
    }
    candidates
}

fn ts_member_candidates(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    receiver_candidates: Vec<CodeUnit>,
    member: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for receiver in receiver_candidates {
        let plain_fqn = format!("{}.{}", receiver.fq_name(), member);
        let static_fqn = format!("{plain_fqn}$static");
        let static_access = value_position && receiver.is_class();

        let mut members = jsts_file_scoped_dotted_candidates(
            host,
            support,
            receiver.source(),
            &plain_fqn,
            value_position,
        );
        if static_access {
            let static_members = jsts_file_scoped_dotted_candidates(
                host,
                support,
                receiver.source(),
                &static_fqn,
                value_position,
            );
            if !static_members.is_empty() {
                members = static_members;
            }
        } else if members.is_empty() {
            members = jsts_file_scoped_dotted_candidates(
                host,
                support,
                receiver.source(),
                &static_fqn,
                value_position,
            );
        }

        let has_synthetic = members.iter().any(CodeUnit::is_synthetic);
        if has_synthetic
            && !jsts_unit_is_type_only(host, &receiver)
            && !ts_synthetic_member_is_supported_by_receiver_initializer(
                analyzer, host, support, &receiver, member,
            )
        {
            candidates.extend(members.into_iter().filter(|member| !member.is_synthetic()));
        } else {
            candidates.extend(members);
        }
    }
    candidates
}

fn ts_synthetic_member_is_supported_by_receiver_initializer(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
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
            host,
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

fn ts_object_literal_has_member(object: Node<'_>, source: &str, member: &str) -> bool {
    let mut cursor = object.walk();
    object
        .named_children(&mut cursor)
        .filter_map(|child| {
            brokk_bifrost_js_ts::typescript::ts_object_literal_property_name(child, source)
        })
        .any(|name| name == member)
}

#[allow(clippy::too_many_arguments)]
fn ts_call_preserves_argument_shape(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    call: Node<'_>,
    argument_index: usize,
) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    ts_call_expression_callees(
        host,
        support,
        file,
        source,
        imports,
        aliases,
        function,
        0,
        &TsReceiverResolution::default(),
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
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    receiver: &str,
) -> Vec<CodeUnit> {
    ts_receiver_owner_candidates_at_byte(
        host,
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
fn jsts_local_new_receiver_owner_candidates(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    language: Language,
    source: &str,
    root: Node<'_>,
    imports: &JsTsImportBinder,
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
        host,
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
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    language: Language,
    source: &str,
    node: Node<'_>,
    root_id: usize,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    receiver: &str,
    before_byte: usize,
    depth: usize,
    state: &mut Option<Vec<CodeUnit>>,
) {
    let root = root_node(node);
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
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
            continue;
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
                        host,
                        support,
                        file,
                        language,
                        source,
                        root,
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
                        host,
                        support,
                        file,
                        language,
                        source,
                        root,
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
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
}

#[allow(clippy::too_many_arguments)]
fn jsts_local_receiver_value_owner_candidates(
    analyzer: &dyn IAnalyzer,
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    language: Language,
    source: &str,
    root: Node<'_>,
    imports: &JsTsImportBinder,
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
                    host,
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
        "call_expression" => value
            .child_by_field_name("function")
            .map(|function| {
                let callees = jsts_call_expression_callees(
                    host, support, file, language, source, imports, aliases, function,
                );
                ts_expand_call_return_property_owners(host, support, callees, depth + 1)
            })
            .unwrap_or_default(),
        "identifier" | "type_identifier" => source
            .get(value.start_byte()..value.end_byte())
            .map(str::trim)
            .filter(|alias| !alias.is_empty())
            .map(|alias| {
                jsts_local_new_receiver_owner_candidates(
                    analyzer,
                    host,
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
fn jsts_call_expression_callees(
    host: &dyn JsTsSource,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    language: Language,
    source: &str,
    imports: &JsTsImportBinder,
    aliases: &AliasResolver,
    function: Node<'_>,
) -> Vec<CodeUnit> {
    match function.kind() {
        "identifier" | "type_identifier" | "property_identifier" => source
            .get(function.start_byte()..function.end_byte())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| {
                jsts_identifier_candidates(
                    host, support, language, file, source, imports, aliases, name, true,
                )
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
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

fn is_bare_js_ts_specifier(module: &str) -> bool {
    !module.starts_with("./") && !module.starts_with("../") && !module.starts_with('/')
}
