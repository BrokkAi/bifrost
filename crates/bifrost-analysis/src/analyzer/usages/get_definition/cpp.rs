use super::*;
use crate::analyzer::LanguageAdapter;
use crate::analyzer::cpp::CppAdapter;
use crate::analyzer::cpp::{
    CppOccurrenceRole, cpp_callable_definitions_share_identity_evidence,
    cpp_header_body_files_are_related, cpp_indexed_callable_linkage, cpp_is_range_for_binding_name,
    cpp_occurrence_role_for_range,
};
use crate::analyzer::declaration_range::code_unit_declaration_name_range_for_range;
use crate::analyzer::resolve_include_targets_with_index;
use crate::analyzer::tree_walk::subtree_contains;
use crate::analyzer::usages::cpp_graph::canonical_cpp_scope_components;
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{SignatureMetadata, StructuredTypeName};
use brokk_bifrost_cpp::call_match::{
    CppArgType, cpp_filter_candidates_by_args, cpp_literal_arg_type, cpp_parameter_type_text,
    cpp_signature_param_types, cpp_type_text_pointer_depth, normalize_cpp_type_name,
};

pub(crate) const CPP_UNPROVEN_LINK_UNIT_DIAGNOSTIC: &str = "unproven_cpp_link_unit";

/// The user-facing explanation for a failed C++ template resolution. Each
/// failure mode gets an honest message; the ambiguous case names every
/// contender.
fn cpp_template_resolution_message(text: &str, error: &CppTemplateResolutionError) -> String {
    match error {
        CppTemplateResolutionError::AliasCycle { alias } => format!(
            "`{text}` expands through a recursive C++ template alias chain that revisits `{}`",
            alias.fq_name()
        ),
        CppTemplateResolutionError::ArgumentBinding => format!(
            "the template arguments of `{text}` do not bind to the declared C++ template parameters"
        ),
        CppTemplateResolutionError::Substitution => format!(
            "the template arguments of `{text}` do not substitute into its C++ template alias target"
        ),
        CppTemplateResolutionError::PrimarySelection => format!(
            "`{text}` has no visible C++ primary template declaration that reconciles with its specializations"
        ),
        CppTemplateResolutionError::AmbiguousSpecialization { candidates } => {
            let contenders = candidates
                .iter()
                .map(|unit| {
                    let declaration = unit
                        .signature()
                        .map(str::to_string)
                        .unwrap_or_else(|| unit.fq_name());
                    format!("`{declaration}` ({})", unit.source())
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("`{text}` is ambiguous between C++ template specializations: {contenders}")
        }
    }
}
const CPP_BOUNDED_AUXILIARY_MAX_SOURCE_BYTES: usize =
    crate::analyzer::usages::receiver_analysis::DEFAULT_RECEIVER_MAX_SCOPE_NODES * 256;

pub(super) struct CppNavigationIndex {
    ranges: HashMap<CodeUnit, Vec<Range>>,
    truncated: HashSet<CodeUnit>,
}

impl CppNavigationIndex {
    pub(super) fn build(file: &ProjectFile, source: &str, tree: &Tree) -> Self {
        let parsed = CppAdapter.parse_file(file, source, tree);
        Self {
            ranges: parsed.navigation_ranges,
            truncated: parsed.navigation_ranges_truncated,
        }
    }

    fn ranges(&self, candidate: &CodeUnit) -> &[Range] {
        self.ranges.get(candidate).map(Vec::as_slice).unwrap_or(&[])
    }

    fn is_truncated(&self, candidate: &CodeUnit) -> bool {
        self.truncated.contains(candidate)
    }
}

pub(super) fn declaration_at_offset(
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<CodeUnit> {
    let tree = parse_cpp_tree(source)?;
    let index = CppNavigationIndex::build(file, source, &tree);
    index
        .ranges
        .iter()
        .flat_map(|(candidate, ranges)| {
            ranges.iter().filter_map(|range| {
                let name_range = code_unit_declaration_name_range_for_range(
                    source,
                    tree.root_node(),
                    candidate,
                    *range,
                )?;
                (offset >= name_range.start_byte && offset < name_range.end_byte).then_some((
                    name_range.end_byte.saturating_sub(name_range.start_byte),
                    candidate.clone(),
                ))
            })
        })
        .min_by_key(|(length, candidate)| (*length, candidate.clone()))
        .map(|(_, candidate)| candidate)
}

pub(super) struct CppNavigationSelection {
    pub(super) targets: Vec<NavigationTarget>,
    pub(super) structure_unavailable: bool,
    pub(super) unproven_link_unit: bool,
    pub(super) truncated: bool,
}

pub(super) fn select_navigation_targets(
    context: &mut DefinitionBatchContext<'_>,
    candidates: &[CodeUnit],
    operation: NavigationOperation,
) -> CppNavigationSelection {
    let mut classified = Vec::new();
    let mut structure_unavailable = false;
    let mut source_ranges_truncated = false;
    for candidate in candidates {
        let Some(tree) = context.cpp_indexed_tree(candidate.source()) else {
            if operation == NavigationOperation::Declaration {
                classified.push((candidate.clone(), None, CppOccurrenceRole::Unknown));
            }
            structure_unavailable = true;
            continue;
        };
        let root = tree.root_node();
        let Some(index) = context.cpp_navigation_index(candidate.source()) else {
            if operation == NavigationOperation::Declaration {
                classified.push((candidate.clone(), None, CppOccurrenceRole::Unknown));
            }
            structure_unavailable = true;
            continue;
        };
        let ranges = index.ranges(candidate);
        source_ranges_truncated |= index.is_truncated(candidate);
        if ranges.is_empty() && !candidate.is_callable() && !candidate.is_class() {
            classified.push((candidate.clone(), None, CppOccurrenceRole::Both));
            continue;
        }
        classified.extend(ranges.iter().copied().map(|range| {
            let kind = cpp_occurrence_role_for_range(root, candidate, &range);
            (candidate.clone(), Some(range), kind)
        }));
    }
    let has_declaration_only = classified
        .iter()
        .any(|(_, _, kind)| *kind == CppOccurrenceRole::DeclarationOnly);
    let mut selected: Vec<_> = classified
        .into_iter()
        .filter(|(_, _, kind)| match operation {
            NavigationOperation::Declaration => {
                if has_declaration_only {
                    *kind == CppOccurrenceRole::DeclarationOnly
                } else {
                    true
                }
            }
            NavigationOperation::Definition => matches!(
                *kind,
                CppOccurrenceRole::Definition | CppOccurrenceRole::Both
            ),
        })
        .collect();
    selected.sort_by(|left, right| (&left.0, left.1).cmp(&(&right.0, right.1)));
    selected.dedup();
    let unproven_link_unit = operation == NavigationOperation::Definition
        && selected
            .iter()
            .filter(|(_, _, kind)| *kind == CppOccurrenceRole::Definition)
            .count()
            > 1
        && selected
            .iter()
            .filter(|(_, _, kind)| *kind == CppOccurrenceRole::Definition)
            .map(|(candidate, _, _)| {
                (
                    definition_symbol_key(candidate),
                    candidate.signature().map(str::to_owned),
                )
            })
            .collect::<HashSet<_>>()
            .len()
            == 1;
    let truncated = source_ranges_truncated || selected.len() > context.navigation_target_limit;
    selected.truncate(context.navigation_target_limit);
    CppNavigationSelection {
        targets: selected
            .into_iter()
            .map(|(code_unit, declaration_range, _)| NavigationTarget {
                code_unit,
                declaration_range,
            })
            .collect(),
        structure_unavailable,
        unproven_link_unit,
        truncated,
    }
}

pub(super) fn resolve_cpp<'a>(
    analyzer: &'a dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'a>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
        return no_definition("cpp_analyzer_unavailable", "C++ analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("cpp_parse_failed", "C++ source could not be parsed");
    };
    let visibility = context.cpp_visibility(cpp, analyzer, file);
    let class_ranges = context.cpp_class_ranges(file);
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed C++ definition",
                site.text
            ),
        );
    };
    let reference = cpp_reference_node(node);
    if let Some(CppReferenceNode::Type(type_node)) = reference {
        if cpp_type_node_is_unqualified_name(type_node)
            && (cpp_type_node_is_local_constructor_argument(type_node)
                || (cpp_type_node_is_value_argument(type_node)
                    && !cpp_type_node_is_parameter_type(type_node)))
            && !cpp_type_node_resolves_lexically(
                analyzer,
                visibility.as_ref(),
                file,
                source,
                type_node,
            )
        {
            let text = cpp_node_text(type_node, source);
            let support = context.bounded_support();
            let ctx = CppLookupCtx {
                analyzer,
                support,
                file,
                visibility: visibility.as_ref(),
                source,
                root,
                class_ranges: None,
            };
            let bindings = cpp_local_bindings_before(ctx, node, node.start_byte());
            if bindings.is_shadowed(text) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{text}` is a local C++ value"),
                );
            }
        }
        if cpp_is_non_reference_declaration_name(node) {
            return no_definition(
                "declaration_or_import_site",
                format!("`{}` is not a C++ reference site", site.text),
            );
        }
        return resolve_cpp_type(
            analyzer,
            context,
            file,
            visibility.as_ref(),
            source,
            type_node,
            Some(class_ranges.as_ref()),
        );
    }

    let support = context.bounded_support();
    let ctx = CppLookupCtx {
        analyzer,
        support,
        file,
        visibility: visibility.as_ref(),
        source,
        root,
        class_ranges: Some(class_ranges.as_ref()),
    };
    match reference {
        Some(CppReferenceNode::Type(_)) => unreachable!("type references returned above"),
        Some(CppReferenceNode::Construction(construction)) => {
            resolve_cpp_construction_type(ctx, construction)
        }
        Some(CppReferenceNode::Call(call)) => resolve_cpp_call(ctx, call),
        Some(CppReferenceNode::Field(field)) => resolve_cpp_field(ctx, field, None, None),
        Some(CppReferenceNode::Identifier(identifier)) => {
            if let Some(designator_owner) =
                cpp_designated_initializer_owner(ctx.visibility, ctx.file, ctx.source, identifier)
            {
                let member = cpp_node_text(identifier, ctx.source);
                let CppDesignatedInitializerOwner::Resolved(owner) = designator_owner else {
                    return no_definition(
                        "unresolved_designated_initializer_owner",
                        format!("aggregate owner for designated field `{member}` is unresolved"),
                    );
                };
                let candidates = cpp_member_candidates(ctx, vec![owner], member, None, None)
                    .into_iter()
                    .filter(CodeUnit::is_field)
                    .collect::<Vec<_>>();
                return if candidates.is_empty() {
                    no_definition(
                        "no_indexed_definition",
                        format!("`{member}` did not resolve to an indexed C++ field"),
                    )
                } else {
                    candidates_outcome(candidates)
                };
            }
            if cpp_is_non_reference_declaration_name(identifier)
                || cpp_is_non_reference_preprocessor_token(identifier)
            {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a C++ reference site", site.text),
                );
            }
            let text = cpp_node_text(identifier, ctx.source);
            if text.is_empty() {
                return no_definition("no_reference_text", "C++ identifier is blank");
            }
            let bindings = cpp_local_bindings_before(ctx, identifier, identifier.start_byte());
            if bindings.is_shadowed(text) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{text}` is a local C++ value"),
                );
            }
            if let Some(owner) = cpp_enclosing_class(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                ctx.root,
                identifier.start_byte(),
            ) {
                let member_candidates = cpp_member_candidates(ctx, vec![owner], text, None, None)
                    .into_iter()
                    .filter(|unit| unit.is_field())
                    .collect::<Vec<_>>();
                if !member_candidates.is_empty() {
                    return candidates_outcome(member_candidates);
                }
            }
            let candidates = ctx
                .support
                .file_identifier(ctx.file, text)
                .into_iter()
                .filter(|unit| {
                    cpp_unit_matches_kind(
                        ctx.analyzer,
                        ctx.support,
                        unit,
                        CppTargetKind::GlobalField,
                    )
                })
                .collect::<Vec<_>>();
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            let candidates = cpp_visible_name_candidates(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.support,
                text,
                Some(CppTargetKind::GlobalField),
                cpp_lexical_namespace(identifier, ctx.source).as_deref(),
            );
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed C++ definition"),
            )
        }
        None => no_definition(
            "unsupported_cpp_reference_shape",
            format!(
                "`{}` is a C++ `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

pub(crate) struct CppBoundedTypeResolution {
    pub(crate) fqn: String,
    pub(crate) candidates: Vec<CodeUnit>,
    pub(crate) target_kind: TypeLookupTargetKind,
    pub(crate) ambiguous: bool,
}

struct CppBoundedProvider<'a> {
    cpp: &'a CppAnalyzer,
    session: &'a ResolutionSession,
}

impl CppBoundedProvider<'_> {
    fn definitions_named(&self, fqn: &str, terminal_name: &str) -> Vec<CodeUnit> {
        let exact = self.session.query_limited_rows(|limit| {
            self.cpp
                .declaration_candidates_by_fqn_limited(fqn, false, limit, || {
                    self.session.observe_cancellation()
                })
        });
        if !exact.is_empty() {
            return exact;
        }
        let normalized = self.session.query_limited_rows(|limit| {
            self.cpp
                .declaration_candidates_by_fqn_limited(fqn, true, limit, || {
                    self.session.observe_cancellation()
                })
        });
        if !normalized.is_empty() {
            return normalized;
        }
        // Some live C++ declarations are held in the definition-lookup
        // projection rather than the persisted-FQN projection. The bounded
        // identifier query is only a retrieval index: the exact AST-derived
        // FQN filter below remains the resolution criterion.
        self.session
            .query_limited_rows(|limit| {
                self.cpp
                    .declaration_candidates_by_identifier_limited(terminal_name, limit, || {
                        self.session.observe_cancellation()
                    })
            })
            .into_iter()
            .filter(|candidate| candidate.fq_name() == fqn)
            .collect()
    }

    fn members_named(&self, owner: &CodeUnit, member: &str) -> Vec<CodeUnit> {
        let projected = self.session.query_limited_rows(|limit| {
            self.cpp
                .member_candidates_for_owner_limited(&owner.fq_name(), member, limit, || {
                    self.session.observe_cancellation()
                })
        });
        if !projected.is_empty() {
            return projected;
        }
        let member_fqn = format!("{}.{}", owner.fq_name(), member);
        self.definitions_named(&member_fqn, member)
            .into_iter()
            .filter(|candidate| candidate.identifier() == member)
            .collect()
    }

    fn ranges(&self, unit: &CodeUnit) -> Vec<Range> {
        self.session
            .query_limited_rows(|limit| self.cpp.ranges_limited(unit, limit))
    }

    fn signature_metadata(&self, unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.session
            .query_limited_rows(|limit| self.cpp.signature_metadata_limited(unit, limit))
    }

    fn prepared_syntax(
        &self,
        file: &ProjectFile,
    ) -> Option<Arc<crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree>> {
        use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxLimitedOutcome;

        if !self.session.scope_step() {
            return None;
        }
        match self.cpp.prepared_syntax_limited_cancellable(
            file,
            CPP_BOUNDED_AUXILIARY_MAX_SOURCE_BYTES,
            self.session.cancellation(),
        ) {
            PreparedSyntaxLimitedOutcome::Available(prepared) => {
                self.session.observe_cancellation().then_some(prepared)
            }
            PreparedSyntaxLimitedOutcome::Exceeded(_) => {
                self.session.mark_scope_incomplete();
                None
            }
            PreparedSyntaxLimitedOutcome::Cancelled => {
                self.session.observe_cancellation();
                None
            }
            PreparedSyntaxLimitedOutcome::Unavailable => None,
        }
    }
}

pub(crate) fn resolve_cpp_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "cpp_analyzer_unavailable",
            "C++ analyzer is unavailable",
        ));
    };
    if !brokk_bifrost_cpp::imports::receiver_query_supported(file) {
        return session.finish(no_definition(
            "cpp_c_receiver_unsupported",
            "bounded receiver traversal is intentionally unsupported for plain C",
        ));
    }
    let Some(tree) = tree else {
        return session.finish(no_definition(
            "cpp_parse_failed",
            "C++ source could not be parsed",
        ));
    };
    let provider = CppBoundedProvider {
        cpp,
        session: &session,
    };
    let outcome = resolve_cpp_bounded_in_session(&provider, file, source, tree.root_node(), site);
    session.finish(outcome)
}

fn resolve_cpp_bounded_in_session(
    provider: &CppBoundedProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(node) = cpp_bounded_smallest_node(
        root,
        site.focus_start_byte,
        site.focus_end_byte,
        provider.session,
    ) else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed C++ definition",
                site.text
            ),
        );
    };
    if cpp_bounded_preprocessing_boundary(node, provider.session) {
        return no_definition(
            "cpp_preprocessing_receiver_boundary",
            "C++ receiver resolution cannot prove the active preprocessing branch",
        );
    }
    if let Some(field) = cpp_bounded_enclosing_member_field(node, provider.session) {
        return resolve_cpp_bounded_member(provider, file, source, root, field);
    }

    match cpp_bounded_reference_node(node, provider.session) {
        Some(CppReferenceNode::Field(field)) => {
            resolve_cpp_bounded_member(provider, file, source, root, field)
        }
        Some(CppReferenceNode::Call(call)) => {
            let Some(function) = call.child_by_field_name("function") else {
                return no_definition(
                    "unsupported_cpp_reference_shape",
                    "C++ call expression has no structured function",
                );
            };
            resolve_cpp_bounded_call_target(provider, file, source, root, function)
        }
        Some(CppReferenceNode::Construction(construction)) => {
            let Some(type_node) = construction
                .child_by_field_name("type")
                .or_else(|| cpp_constructor_type_node(construction))
            else {
                return no_definition(
                    "unsupported_cpp_reference_shape",
                    "C++ construction has no structured type",
                );
            };
            cpp_bounded_type_candidates(provider, file, source, type_node).map_or_else(
                || {
                    no_definition(
                        "no_indexed_definition",
                        "C++ construction type is not indexed",
                    )
                },
                |resolution| candidates_outcome(resolution.candidates),
            )
        }
        Some(CppReferenceNode::Type(type_node)) => {
            cpp_bounded_type_candidates(provider, file, source, type_node).map_or_else(
                || {
                    no_definition(
                        "no_indexed_definition",
                        format!("`{}` did not resolve to an indexed C++ type", site.text),
                    )
                },
                |resolution| candidates_outcome(resolution.candidates),
            )
        }
        Some(CppReferenceNode::Identifier(identifier)) => {
            resolve_cpp_bounded_callable(provider, source, root, identifier)
        }
        None => no_definition(
            "unsupported_cpp_reference_shape",
            format!(
                "`{}` is a C++ `{}` reference shape that bounded receiver resolution does not support",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn cpp_bounded_enclosing_member_field<'tree>(
    node: Node<'tree>,
    session: &ResolutionSession,
) -> Option<Node<'tree>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if !session.scope_step() {
            return None;
        }
        if candidate.kind() == "field_expression" {
            return Some(candidate);
        }
        if matches!(
            candidate.kind(),
            "compound_statement"
                | "expression_statement"
                | "declaration"
                | "return_statement"
                | "co_return_statement"
        ) {
            return None;
        }
        current = candidate.parent();
    }
    None
}

fn cpp_bounded_reference_node<'tree>(
    node: Node<'tree>,
    session: &ResolutionSession,
) -> Option<CppReferenceNode<'tree>> {
    let mut current = node;
    loop {
        if !session.scope_step() {
            return None;
        }
        let Some(parent) = current.parent() else {
            break;
        };
        let extends_reference = (matches!(
            parent.kind(),
            "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
        ) && parent.child_by_field_name("name") == Some(current))
            || (matches!(
                parent.kind(),
                "dependent_name" | "template_function" | "template_method" | "template_type"
            ) && parent.child_by_field_name("name") == Some(current))
            || (parent.kind() == "field_expression"
                && parent.child_by_field_name("field") == Some(current))
            || (parent.kind() == "call_expression"
                && parent.child_by_field_name("function") == Some(current))
            || (parent.kind() == "new_expression"
                && parent.start_byte() <= current.start_byte()
                && parent.end_byte() >= current.end_byte())
            || (parent.kind() == "compound_literal_expression"
                && parent.child_by_field_name("type") == Some(current));
        if !extends_reference {
            break;
        }
        current = parent;
    }

    match current.kind() {
        "new_expression" | "compound_literal_expression" => {
            Some(CppReferenceNode::Construction(current))
        }
        "call_expression" => Some(CppReferenceNode::Call(current)),
        "field_expression" => Some(CppReferenceNode::Field(current)),
        "type_identifier"
        | "namespace_identifier"
        | "qualified_identifier"
        | "template_type"
        | "scoped_type_identifier" => Some(CppReferenceNode::Type(current)),
        "identifier"
        | "field_identifier"
        | "preproc_arg"
        | "operator_name"
        | "operator_cast"
        | "destructor_name"
        | "literal_operator_name" => Some(CppReferenceNode::Identifier(current)),
        _ => None,
    }
}

fn resolve_cpp_bounded_member(
    provider: &CppBoundedProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    field: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(member_node) = field
        .child_by_field_name("field")
        .and_then(|node| cpp_bounded_callable_name_node(node, provider.session))
    else {
        return no_definition(
            "no_member_name",
            "C++ field expression has no supported member name",
        );
    };
    let Some(receiver) = field
        .child_by_field_name("argument")
        .or_else(|| field.named_child(0))
    else {
        return no_definition("no_member_receiver", "C++ field expression has no receiver");
    };
    let member = cpp_node_text(member_node, source);
    if member.is_empty() {
        return no_definition("no_member_name", "C++ member name is blank");
    }
    let Some(resolution) =
        cpp_bounded_type_resolution_for_node(provider, file, source, root, receiver)
    else {
        return no_definition(
            "unsupported_cpp_receiver",
            format!("receiver for C++ member `{member}` is not resolved"),
        );
    };

    let callable = field.parent().is_some_and(|parent| {
        parent.kind() == "call_expression" && parent.child_by_field_name("function") == Some(field)
    });
    let mut candidates = Vec::new();
    let mut ambiguous_base_subobject = false;
    for owner in resolution.candidates {
        if !provider.session.scope_step() {
            return no_definition(
                "cpp_receiver_budget_exhausted",
                "C++ member resolution exhausted its bounded owner traversal",
            );
        }
        let root_key = CppBoundedBaseSubobjectKey {
            virtual_root: None,
            non_virtual_path: vec![owner.clone()],
        };
        let mut subobjects = vec![CppBoundedBaseSubobject {
            owner,
            key: root_key,
            parent: None,
        }];
        let mut seen = HashSet::default();
        let mut level = vec![0];
        while !level.is_empty() {
            if !provider.session.scope_step() {
                return no_definition(
                    "cpp_receiver_budget_exhausted",
                    "C++ member resolution exhausted its bounded hierarchy traversal",
                );
            }
            let mut level_candidates = Vec::new();
            let mut candidate_subobjects = HashMap::default();
            let mut level_subobjects = Vec::new();
            for subobject_index in level {
                if !provider.session.scope_step() {
                    return no_definition(
                        "cpp_receiver_budget_exhausted",
                        "C++ member resolution exhausted its bounded hierarchy traversal",
                    );
                }
                let subobject = &subobjects[subobject_index];
                if !seen.insert(subobject.key.clone()) {
                    continue;
                }
                for candidate in provider
                    .members_named(&subobject.owner, member)
                    .into_iter()
                    .filter(|candidate| !callable || candidate.is_callable())
                {
                    if candidate_subobjects
                        .insert(candidate.clone(), subobject.key.clone())
                        .is_some_and(|existing| existing != subobject.key)
                    {
                        ambiguous_base_subobject = true;
                    }
                    level_candidates.push(candidate);
                }
                level_subobjects.push(subobject_index);
            }
            if !level_candidates.is_empty() {
                candidates.extend(level_candidates);
                break;
            }
            let mut next_level = Vec::new();
            for subobject_index in level_subobjects {
                if !provider.session.scope_step() {
                    return no_definition(
                        "cpp_receiver_budget_exhausted",
                        "C++ member resolution exhausted its bounded hierarchy traversal",
                    );
                }
                let current_owner = subobjects[subobject_index].owner.clone();
                let current_key = subobjects[subobject_index].key.clone();
                for edge in cpp_bounded_direct_ancestor_edges(provider, &current_owner) {
                    let mut ancestor = Some(subobject_index);
                    let mut cycle = false;
                    while let Some(ancestor_index) = ancestor {
                        if !provider.session.scope_step() {
                            return no_definition(
                                "cpp_receiver_budget_exhausted",
                                "C++ member resolution exhausted its bounded hierarchy traversal",
                            );
                        }
                        let ancestor_subobject = &subobjects[ancestor_index];
                        if ancestor_subobject.owner == edge.target {
                            cycle = true;
                            break;
                        }
                        ancestor = ancestor_subobject.parent;
                    }
                    if cycle {
                        continue;
                    }
                    let key = if edge.is_virtual {
                        CppBoundedBaseSubobjectKey {
                            virtual_root: Some(edge.target.clone()),
                            non_virtual_path: Vec::new(),
                        }
                    } else {
                        let mut key = current_key.clone();
                        key.non_virtual_path.push(edge.target.clone());
                        key
                    };
                    let next_index = subobjects.len();
                    subobjects.push(CppBoundedBaseSubobject {
                        owner: edge.target,
                        key,
                        parent: Some(subobject_index),
                    });
                    next_level.push(next_index);
                }
            }
            level = next_level;
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("C++ member `{member}` is not indexed for the resolved receiver"),
        );
    }
    let mut outcome = candidates_outcome(candidates);
    if ambiguous_base_subobject && outcome.status == DefinitionLookupStatus::Resolved {
        outcome.status = DefinitionLookupStatus::Ambiguous;
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: "cpp_ambiguous_base_subobject".to_string(),
            message: "C++ member is inherited through multiple non-virtual base subobjects"
                .to_string(),
        });
    }
    if resolution.ambiguous && outcome.status == DefinitionLookupStatus::Resolved {
        outcome.status = DefinitionLookupStatus::Ambiguous;
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: "cpp_open_receiver_type".to_string(),
            message:
                "C++ receiver type crosses a template or otherwise incomplete structured boundary"
                    .to_string(),
        });
    }
    outcome
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CppBoundedBaseSubobjectKey {
    virtual_root: Option<CodeUnit>,
    non_virtual_path: Vec<CodeUnit>,
}

struct CppBoundedBaseSubobject {
    owner: CodeUnit,
    key: CppBoundedBaseSubobjectKey,
    parent: Option<usize>,
}

#[derive(Clone, PartialEq, Eq)]
struct CppBoundedBaseEdge {
    target: CodeUnit,
    is_virtual: bool,
}

fn cpp_bounded_direct_ancestor_edges(
    provider: &CppBoundedProvider<'_>,
    owner: &CodeUnit,
) -> Vec<CppBoundedBaseEdge> {
    if !owner.is_class() {
        return Vec::new();
    }
    let Some(prepared) = provider.prepared_syntax(owner.source()) else {
        return Vec::new();
    };
    let mut edges = Vec::new();
    for range in provider.ranges(owner) {
        if !provider.session.scope_step() {
            return Vec::new();
        }
        let Some(declaration) = cpp_bounded_declaration_node_for_range(
            prepared.tree().root_node(),
            &range,
            provider.session,
        ) else {
            continue;
        };
        let Some(owner_node) = cpp_bounded_class_declaration_node(
            declaration,
            owner,
            prepared.source(),
            provider.session,
        ) else {
            continue;
        };
        let mut cursor = owner_node.walk();
        for child in owner_node.named_children(&mut cursor) {
            if !provider.session.scope_step() {
                return Vec::new();
            }
            if child.kind() != "base_class_clause" {
                continue;
            }
            let mut is_virtual = false;
            for index in 0..child.child_count() {
                if !provider.session.scope_step() {
                    return Vec::new();
                }
                let Some(candidate) = child.child(index) else {
                    continue;
                };
                match candidate.kind() {
                    "," => {
                        is_virtual = false;
                    }
                    "virtual" => {
                        is_virtual = true;
                    }
                    "type_identifier"
                    | "qualified_identifier"
                    | "scoped_type_identifier"
                    | "template_type" => {
                        if let Some(resolution) = cpp_bounded_type_candidates(
                            provider,
                            owner.source(),
                            prepared.source(),
                            candidate,
                        ) {
                            edges.extend(
                                resolution
                                    .candidates
                                    .into_iter()
                                    .map(|target| CppBoundedBaseEdge { target, is_virtual }),
                            );
                        }
                        is_virtual = false;
                    }
                    _ => {}
                }
            }
        }
    }
    edges.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then(left.is_virtual.cmp(&right.is_virtual))
    });
    edges.dedup();
    edges
}

fn cpp_bounded_class_declaration_node<'tree>(
    declaration: Node<'tree>,
    owner: &CodeUnit,
    source: &str,
    session: &ResolutionSession,
) -> Option<Node<'tree>> {
    let mut pending = vec![declaration];
    while let Some(candidate) = pending.pop() {
        if !session.scope_step() {
            return None;
        }
        if matches!(
            candidate.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) && candidate
            .child_by_field_name("name")
            .is_some_and(|name| cpp_node_text(name, source) == owner.identifier())
        {
            return Some(candidate);
        }
        for index in (0..candidate.named_child_count()).rev() {
            if !session.scope_step() {
                return None;
            }
            if let Some(child) = candidate.named_child(index) {
                pending.push(child);
            }
        }
    }
    None
}

fn resolve_cpp_bounded_callable(
    provider: &CppBoundedProvider<'_>,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(name_node) = cpp_bounded_callable_name_node(node, provider.session) else {
        return no_definition(
            "unsupported_cpp_reference_shape",
            format!(
                "C++ callable `{}` is not an exact named callable",
                cpp_node_text(node, source)
            ),
        );
    };
    let name = cpp_node_text(name_node, source);
    if node.id() == name_node.id()
        && cpp_bounded_binding_type_node(source, root, name_node, provider.session).is_some()
    {
        return no_definition(
            "local_callable_reference",
            format!("C++ callable `{name}` is shadowed by a visible local binding"),
        );
    }
    let structured_path = cpp_bounded_structured_type_path(node, source, provider.session);
    let relative_fqn = structured_path
        .as_ref()
        .map(|path| path.fqn.as_str())
        .unwrap_or(name);
    let Some(lexical_scopes) = cpp_bounded_lexical_scope_fqns(node, source, provider.session)
    else {
        return no_definition(
            "cpp_receiver_budget_exhausted",
            "C++ callable resolution exhausted its bounded lexical traversal",
        );
    };
    let mut candidates = Vec::new();
    if !structured_path
        .as_ref()
        .is_some_and(|path| path.is_absolute)
    {
        for scope in lexical_scopes.iter().rev() {
            if !provider.session.scope_step() {
                return no_definition(
                    "cpp_receiver_budget_exhausted",
                    "C++ callable resolution exhausted its bounded lexical traversal",
                );
            }
            let candidate_fqn = format!("{scope}.{relative_fqn}");
            candidates = provider
                .definitions_named(&candidate_fqn, name)
                .into_iter()
                .filter(CodeUnit::is_callable)
                .collect();
            if !candidates.is_empty() {
                break;
            }
        }
    }
    if candidates.is_empty() {
        candidates = provider
            .definitions_named(relative_fqn, name)
            .into_iter()
            .filter(CodeUnit::is_callable)
            .collect();
    }
    if candidates.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!("C++ callable `{name}` is not indexed"),
        )
    } else {
        candidates_outcome(candidates)
    }
}

fn resolve_cpp_bounded_call_target(
    provider: &CppBoundedProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    function: Node<'_>,
) -> DefinitionLookupOutcome {
    if function.kind() == "field_expression" {
        resolve_cpp_bounded_member(provider, file, source, root, function)
    } else {
        resolve_cpp_bounded_callable(provider, source, root, function)
    }
}

pub(crate) fn cpp_type_lookup_resolution_in_session(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    session: &ResolutionSession,
) -> Option<CppBoundedTypeResolution> {
    let cpp = resolve_analyzer::<CppAnalyzer>(analyzer)?;
    if !brokk_bifrost_cpp::imports::receiver_query_supported(file) {
        return None;
    }
    let provider = CppBoundedProvider { cpp, session };
    let node = cpp_bounded_smallest_node(
        tree.root_node(),
        site.focus_start_byte,
        site.focus_end_byte,
        session,
    )?;
    if cpp_bounded_preprocessing_boundary(node, session) {
        return None;
    }
    cpp_bounded_type_resolution_for_node(&provider, file, source, tree.root_node(), node)
}

fn cpp_bounded_type_resolution_for_node(
    provider: &CppBoundedProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    mut node: Node<'_>,
) -> Option<CppBoundedTypeResolution> {
    loop {
        if !provider.session.scope_step() {
            return None;
        }
        node = match node.kind() {
            "parenthesized_expression" => node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))?,
            "pointer_expression" => node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))?,
            "cast_expression" => {
                let type_node = node.child_by_field_name("type")?;
                return cpp_bounded_type_candidates(provider, file, source, type_node);
            }
            _ => break,
        };
    }

    match node.kind() {
        "this" => cpp_bounded_current_receiver_type(provider, file, source, node),
        "identifier" | "field_identifier" => {
            let type_node = cpp_bounded_binding_type_node(source, root, node, provider.session)?;
            cpp_bounded_type_candidates(provider, file, source, type_node)
        }
        "new_expression" | "compound_literal_expression" => {
            let type_node = node
                .child_by_field_name("type")
                .or_else(|| cpp_constructor_type_node(node))?;
            cpp_bounded_type_candidates(provider, file, source, type_node)
        }
        "call_expression" => {
            let function = node.child_by_field_name("function")?;
            if let Some(construction) =
                cpp_bounded_type_candidates(provider, file, source, function)
            {
                return Some(CppBoundedTypeResolution {
                    target_kind: TypeLookupTargetKind::ValueExpression,
                    ..construction
                });
            }
            let definitions =
                resolve_cpp_bounded_call_target(provider, file, source, root, function);
            if definitions.status != DefinitionLookupStatus::Resolved {
                return None;
            }
            cpp_bounded_callable_return_type(
                provider,
                file,
                source,
                root,
                definitions.definitions.as_slice(),
            )
        }
        "field_expression" => {
            let definitions = resolve_cpp_bounded_member(provider, file, source, root, node);
            if definitions.status != DefinitionLookupStatus::Resolved {
                return None;
            }
            cpp_bounded_callable_return_type(
                provider,
                file,
                source,
                root,
                definitions.definitions.as_slice(),
            )
        }
        "type_identifier"
        | "namespace_identifier"
        | "qualified_identifier"
        | "scoped_type_identifier"
        | "template_type" => cpp_bounded_type_candidates(provider, file, source, node),
        _ => None,
    }
}

fn cpp_bounded_callable_return_type(
    provider: &CppBoundedProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    definitions: &[CodeUnit],
) -> Option<CppBoundedTypeResolution> {
    if definitions.is_empty() {
        return None;
    }

    let mut resolved = Vec::new();
    for definition in definitions {
        if !provider.session.scope_step() {
            return None;
        }
        let metadata = provider.signature_metadata(definition);
        let mut definition_resolved = Vec::new();
        for identity in metadata
            .iter()
            .filter_map(SignatureMetadata::return_type_identity)
        {
            let name = identity.nominal_name_with(|| provider.session.scope_step())?;
            definition_resolved.push(cpp_bounded_type_candidates_for_name(provider, name)?);
        }

        if definition_resolved.is_empty() && definition.source() == file {
            for range in provider.ranges(definition) {
                if !provider.session.scope_step() {
                    return None;
                }
                let declaration =
                    cpp_bounded_declaration_node_for_range(root, &range, provider.session)?;
                let type_node = declaration.child_by_field_name("type").or_else(|| {
                    provider
                        .session
                        .scope_step()
                        .then(|| declaration.parent()?.child_by_field_name("type"))
                        .flatten()
                });
                if let Some(type_node) = type_node {
                    definition_resolved.push(cpp_bounded_type_candidates(
                        provider, file, source, type_node,
                    )?);
                }
            }
        }
        if definition_resolved.is_empty() {
            return None;
        }
        resolved.extend(definition_resolved);
    }

    let first_fqn = resolved.first()?.fqn.clone();
    if resolved
        .iter()
        .any(|resolution| resolution.fqn != first_fqn)
    {
        return None;
    }
    let ambiguous = resolved.iter().any(|resolution| resolution.ambiguous);
    let mut candidates = resolved
        .into_iter()
        .flat_map(|resolution| resolution.candidates)
        .collect::<Vec<_>>();
    sort_units(&mut candidates);
    candidates.dedup();
    Some(CppBoundedTypeResolution {
        fqn: first_fqn,
        candidates,
        target_kind: TypeLookupTargetKind::ValueExpression,
        ambiguous,
    })
}

fn cpp_bounded_type_candidates_for_name(
    provider: &CppBoundedProvider<'_>,
    name: &StructuredTypeName,
) -> Option<CppBoundedTypeResolution> {
    let terminal = name.path().last()?;
    let mut candidates = Vec::new();
    let first_scope_depth = if name.is_absolute() {
        0
    } else {
        name.lexical_scope().len()
    };
    for scope_depth in (0..=first_scope_depth).rev() {
        if !provider.session.scope_step() {
            return None;
        }
        let mut components = Vec::with_capacity(scope_depth.saturating_add(name.path().len()));
        components.extend_from_slice(&name.lexical_scope()[..scope_depth]);
        components.extend_from_slice(name.path());
        let fqn = components.join(".");
        candidates = provider
            .definitions_named(&fqn, terminal)
            .into_iter()
            .filter(CodeUnit::is_class)
            .collect();
        if !candidates.is_empty() {
            break;
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if candidates.is_empty() {
        return None;
    }
    let distinct_fqns = candidates
        .iter()
        .map(CodeUnit::fq_name)
        .collect::<HashSet<_>>();
    Some(CppBoundedTypeResolution {
        fqn: if distinct_fqns.len() == 1 {
            candidates[0].fq_name()
        } else {
            name.path().join(".")
        },
        candidates,
        target_kind: TypeLookupTargetKind::ValueExpression,
        ambiguous: distinct_fqns.len() != 1,
    })
}

fn cpp_bounded_type_candidates(
    provider: &CppBoundedProvider<'_>,
    _file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<CppBoundedTypeResolution> {
    let name_node = cpp_bounded_type_name_node(node, provider.session)?;
    let name = cpp_node_text(name_node, source);
    if name.is_empty() || matches!(name, "auto" | "decltype") {
        return None;
    }
    let structured_path = cpp_bounded_structured_type_path(node, source, provider.session);
    let relative_fqn = structured_path
        .as_ref()
        .map(|path| path.fqn.as_str())
        .unwrap_or(name);
    let lexical_scopes = cpp_bounded_lexical_scope_fqns(node, source, provider.session)?;
    let mut candidates = Vec::new();
    if !structured_path
        .as_ref()
        .is_some_and(|path| path.is_absolute)
    {
        for scope in lexical_scopes.iter().rev() {
            if !provider.session.scope_step() {
                return None;
            }
            let candidate_fqn = format!("{scope}.{relative_fqn}");
            candidates = provider
                .definitions_named(&candidate_fqn, name)
                .into_iter()
                .filter(CodeUnit::is_class)
                .collect();
            if !candidates.is_empty() {
                break;
            }
        }
    }
    if candidates.is_empty() {
        candidates = provider
            .definitions_named(relative_fqn, name)
            .into_iter()
            .filter(CodeUnit::is_class)
            .collect();
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if candidates.is_empty() {
        return None;
    }
    let ambiguous = candidates
        .iter()
        .map(CodeUnit::fq_name)
        .collect::<HashSet<_>>()
        .len()
        != 1
        || cpp_bounded_template_boundary(node, provider.session);
    let fqn = if candidates.len() == 1 {
        candidates[0].fq_name()
    } else {
        structured_path
            .map(|path| path.fqn)
            .unwrap_or_else(|| name.to_string())
    };
    Some(CppBoundedTypeResolution {
        fqn,
        candidates,
        target_kind: if cpp_bounded_type_reference(node, provider.session) {
            TypeLookupTargetKind::TypeReference
        } else {
            TypeLookupTargetKind::ValueExpression
        },
        ambiguous,
    })
}

fn cpp_bounded_current_receiver_type(
    provider: &CppBoundedProvider<'_>,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<CppBoundedTypeResolution> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if !provider.session.scope_step() {
            return None;
        }
        if matches!(
            parent.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier"
        ) && let Some(name) = parent.child_by_field_name("name")
        {
            let mut resolution = cpp_bounded_type_candidates(provider, file, source, name)?;
            resolution.target_kind = TypeLookupTargetKind::ValueExpression;
            return Some(resolution);
        }
        current = parent.parent();
    }
    None
}

fn cpp_bounded_binding_type_node<'tree>(
    source: &str,
    root: Node<'tree>,
    reference: Node<'tree>,
    session: &ResolutionSession,
) -> Option<Node<'tree>> {
    let name = cpp_node_text(reference, source);
    let callable = cpp_bounded_enclosing_callable(reference, session)?;
    let mut best: Option<(usize, usize, Node<'tree>)> = None;
    let mut stack = vec![callable];
    while let Some(node) = stack.pop() {
        if !session.scope_step() {
            return None;
        }
        if node.start_byte() > reference.start_byte() {
            continue;
        }
        if node.id() != callable.id() && cpp_bounded_nested_callable(node) {
            continue;
        }
        if matches!(node.kind(), "parameter_declaration" | "declaration")
            && let Some(type_node) = node.child_by_field_name("type")
        {
            let scope = if node.kind() == "parameter_declaration" {
                callable
            } else {
                cpp_bounded_enclosing_scope(node, callable, session)?
            };
            if scope.start_byte() <= reference.start_byte()
                && reference.start_byte() < scope.end_byte()
            {
                let mut declarators = Vec::new();
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    declarators.push(declarator);
                }
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if !session.scope_step() {
                        return None;
                    }
                    if child.kind() == "init_declarator" {
                        declarators.push(child);
                    }
                }
                if declarators.into_iter().any(|declarator| {
                    cpp_bounded_declarator_name_node(declarator, session)
                        .is_some_and(|name_node| cpp_node_text(name_node, source) == name)
                }) {
                    let candidate = (
                        scope.end_byte().saturating_sub(scope.start_byte()),
                        usize::MAX.saturating_sub(node.start_byte()),
                        type_node,
                    );
                    if best
                        .as_ref()
                        .is_none_or(|current| (candidate.0, candidate.1) < (current.0, current.1))
                    {
                        best = Some(candidate);
                    }
                }
            }
        }
        let mut cursor = node.walk();
        let mut children = Vec::new();
        for child in node.named_children(&mut cursor) {
            if !session.scope_step() {
                return None;
            }
            children.push(child);
        }
        stack.extend(children.into_iter().rev());
    }
    let _ = root;
    best.map(|(_, _, type_node)| type_node)
}

fn cpp_bounded_enclosing_callable<'tree>(
    node: Node<'tree>,
    session: &ResolutionSession,
) -> Option<Node<'tree>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if !session.scope_step() {
            return None;
        }
        if cpp_bounded_callable_declaration(candidate) {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn cpp_bounded_callable_declaration(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_definition" | "lambda_expression" | "operator_cast_definition"
    )
}

fn cpp_bounded_nested_callable(node: Node<'_>) -> bool {
    cpp_bounded_callable_declaration(node)
}

fn cpp_bounded_enclosing_scope<'tree>(
    node: Node<'tree>,
    fallback: Node<'tree>,
    session: &ResolutionSession,
) -> Option<Node<'tree>> {
    let mut current = node.parent();
    while let Some(candidate) = current {
        if !session.scope_step() {
            return None;
        }
        if candidate.kind() == "compound_statement" {
            return Some(candidate);
        }
        if candidate.id() == fallback.id() {
            break;
        }
        current = candidate.parent();
    }
    Some(fallback)
}

fn cpp_bounded_declarator_name_node<'tree>(
    mut node: Node<'tree>,
    session: &ResolutionSession,
) -> Option<Node<'tree>> {
    loop {
        if !session.scope_step() {
            return None;
        }
        match node.kind() {
            "identifier" | "field_identifier" => return Some(node),
            "qualified_identifier" => node = node.child_by_field_name("name")?,
            "function_declarator"
            | "pointer_declarator"
            | "array_declarator"
            | "init_declarator"
            | "attributed_declarator" => node = node.child_by_field_name("declarator")?,
            "reference_declarator" | "parenthesized_declarator" => node = node.named_child(0)?,
            _ => return None,
        }
    }
}

fn cpp_bounded_callable_name_node<'tree>(
    mut node: Node<'tree>,
    session: &ResolutionSession,
) -> Option<Node<'tree>> {
    loop {
        if !session.scope_step() {
            return None;
        }
        node = match node.kind() {
            "identifier"
            | "field_identifier"
            | "type_identifier"
            | "namespace_identifier"
            | "operator_name"
            | "operator_cast"
            | "destructor_name"
            | "literal_operator_name"
            | "primitive_type" => return Some(node),
            "dependent_name" | "template_function" | "template_method" | "template_type" => {
                node.child_by_field_name("name")?
            }
            "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier" => {
                let mut cursor = node.walk();
                let mut selected = None;
                for child in node.children_by_field_name("name", &mut cursor) {
                    if !session.scope_step() {
                        return None;
                    }
                    if child.is_named() {
                        selected = Some(child);
                    }
                }
                selected?
            }
            "field_expression" => node.child_by_field_name("field")?,
            "parenthesized_expression" => {
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor);
                let child = children.next()?;
                if !session.scope_step() || children.next().is_some() {
                    return None;
                }
                child
            }
            _ => return None,
        };
    }
}

fn cpp_bounded_type_name_node<'tree>(
    mut node: Node<'tree>,
    session: &ResolutionSession,
) -> Option<Node<'tree>> {
    loop {
        if !session.scope_step() {
            return None;
        }
        match node.kind() {
            "type_identifier" | "identifier" => return Some(node),
            "qualified_identifier" | "scoped_type_identifier" => {
                node = node.child_by_field_name("name")?
            }
            "template_type" | "dependent_type" => {
                node = node
                    .child_by_field_name("name")
                    .or_else(|| node.named_child(0))?
            }
            "type_descriptor" | "sized_type_specifier" | "placeholder_type_specifier" => {
                node = node
                    .child_by_field_name("type")
                    .or_else(|| node.named_child(0))?
            }
            _ => return None,
        }
    }
}

struct CppBoundedStructuredPath {
    fqn: String,
    is_absolute: bool,
}

fn cpp_bounded_structured_type_path(
    node: Node<'_>,
    source: &str,
    session: &ResolutionSession,
) -> Option<CppBoundedStructuredPath> {
    let mut components = Vec::new();
    let mut pending = vec![node];
    let mut is_absolute = false;
    while let Some(candidate) = pending.pop() {
        if !session.scope_step() {
            return None;
        }
        is_absolute |= candidate.child_by_field_name("scope").is_none()
            && candidate.child(0).is_some_and(|child| child.kind() == "::");
        match candidate.kind() {
            "namespace_identifier"
            | "type_identifier"
            | "identifier"
            | "field_identifier"
            | "operator_name"
            | "destructor_name" => {
                let component = cpp_node_text(candidate, source);
                if !component.is_empty() {
                    components.push(component.to_string());
                }
            }
            "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier" => {
                if let Some(name) = candidate.child_by_field_name("name") {
                    pending.push(name);
                }
                if let Some(scope) = candidate.child_by_field_name("scope") {
                    pending.push(scope);
                }
            }
            "template_type" | "template_function" | "template_method" | "dependent_type"
            | "dependent_name" => {
                if let Some(name) = candidate.child_by_field_name("name") {
                    pending.push(name);
                }
            }
            _ => {}
        }
    }
    (components.len() > 1 || is_absolute).then(|| CppBoundedStructuredPath {
        fqn: components.join("."),
        is_absolute,
    })
}

fn cpp_bounded_lexical_scope_fqns(
    node: Node<'_>,
    source: &str,
    session: &ResolutionSession,
) -> Option<Vec<String>> {
    let mut scopes = Vec::new();
    let mut current = node.parent();
    while let Some(candidate) = current {
        if !session.scope_step() {
            return None;
        }
        if matches!(
            candidate.kind(),
            "namespace_definition" | "class_specifier" | "struct_specifier" | "union_specifier"
        ) && let Some(name_node) = candidate.child_by_field_name("name")
            && !(name_node.start_byte() <= node.start_byte()
                && node.end_byte() <= name_node.end_byte())
        {
            let scope = cpp_bounded_structured_type_path(name_node, source, session)
                .map(|path| path.fqn)
                .unwrap_or_else(|| cpp_node_text(name_node, source).to_string());
            if !scope.is_empty() {
                scopes.push(scope);
            }
        }
        current = candidate.parent();
    }
    scopes.reverse();
    let mut fqns = Vec::with_capacity(scopes.len());
    let mut prefix = String::new();
    for scope in scopes {
        if !session.scope_step() {
            return None;
        }
        if !prefix.is_empty() {
            prefix.push('.');
        }
        prefix.push_str(&scope);
        fqns.push(prefix.clone());
    }
    Some(fqns)
}

fn cpp_bounded_type_reference(node: Node<'_>, session: &ResolutionSession) -> bool {
    if matches!(
        node.kind(),
        "type_identifier"
            | "namespace_identifier"
            | "qualified_identifier"
            | "scoped_type_identifier"
            | "template_type"
    ) {
        if !session.scope_step() {
            return false;
        }
        return node.parent().is_some_and(|parent| {
            matches!(
                parent.kind(),
                "field_expression" | "qualified_identifier" | "scoped_identifier"
            )
        });
    }
    false
}

fn cpp_bounded_template_boundary(node: Node<'_>, session: &ResolutionSession) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if !session.scope_step() {
            return true;
        }
        if matches!(
            candidate.kind(),
            "template_type"
                | "template_method"
                | "template_function"
                | "dependent_type"
                | "dependent_name"
        ) {
            return true;
        }
        if matches!(
            candidate.kind(),
            "statement" | "declaration" | "function_definition" | "translation_unit"
        ) {
            return false;
        }
        current = candidate.parent();
    }
    false
}

fn cpp_bounded_preprocessing_boundary(node: Node<'_>, session: &ResolutionSession) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if !session.scope_step() {
            return true;
        }
        if candidate.kind().starts_with("preproc_") || candidate.kind() == "ERROR" {
            return true;
        }
        current = candidate.parent();
    }
    false
}

fn cpp_bounded_smallest_node<'tree>(
    root: Node<'tree>,
    start: usize,
    end: usize,
    session: &ResolutionSession,
) -> Option<Node<'tree>> {
    if start >= end {
        return None;
    }
    let mut current = root;
    loop {
        if !session.scope_step() {
            return None;
        }
        let mut cursor = current.walk();
        let mut containing = None;
        for child in current.named_children(&mut cursor) {
            if !session.scope_step() {
                return None;
            }
            if child.start_byte() <= start && child.end_byte() >= end {
                containing = Some(child);
                break;
            }
        }
        let Some(child) = containing else {
            return (current.start_byte() <= start && current.end_byte() >= end).then_some(current);
        };
        current = child;
    }
}

fn cpp_bounded_declaration_node_for_range<'tree>(
    root: Node<'tree>,
    range: &Range,
    session: &ResolutionSession,
) -> Option<Node<'tree>> {
    let mut node = cpp_bounded_smallest_node(root, range.start_byte, range.end_byte, session)?;
    while node.start_byte() > range.start_byte || node.end_byte() < range.end_byte {
        if !session.scope_step() {
            return None;
        }
        node = node.parent()?;
    }
    Some(node)
}

pub(super) fn parse_cpp_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

#[derive(Clone, Copy)]
enum CppReferenceNode<'tree> {
    Type(Node<'tree>),
    Construction(Node<'tree>),
    Call(Node<'tree>),
    Field(Node<'tree>),
    Identifier(Node<'tree>),
}

#[derive(Clone, Copy)]
struct CppLookupCtx<'a, 'tree> {
    analyzer: &'a dyn IAnalyzer,
    support: &'a dyn BoundedDefinitionLookup,
    file: &'a ProjectFile,
    visibility: &'a CppVisibilityIndex<'a>,
    source: &'a str,
    root: Node<'tree>,
    class_ranges: Option<&'a ClassRangeIndex>,
}

fn cpp_reference_node(node: Node<'_>) -> Option<CppReferenceNode<'_>> {
    // In an out-of-line destructor definition, the terminal identifier in
    // `owner::~owner` names the same type as the structured qualifier.  It is
    // not a declaration of a separate callable named `owner`.
    if node.kind() == "identifier"
        && let Some(destructor) = node
            .parent()
            .filter(|parent| parent.kind() == "destructor_name")
        && let Some(qualified) = destructor.parent().filter(|parent| {
            parent.kind() == "qualified_identifier"
                && parent.child_by_field_name("name") == Some(destructor)
        })
        && let Some(scope) = qualified.child_by_field_name("scope")
    {
        return Some(CppReferenceNode::Type(scope));
    }

    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "ERROR"
            && parent.parent().is_some_and(|call| {
                call.kind() == "call_expression"
                    && cpp_explicit_operator_name(call) == Some(current)
            })
        {
            current = parent.parent()?;
            continue;
        }
        // A qualified template-id can be represented as a `template_type`
        // nested in the `name` field of its `qualified_identifier` (for
        // example `std::remove_reference_t<C>`).  Keep that explicit scope
        // on the reference.  Template-types used as the `scope` of a
        // qualified access (for example `Vector<T>::value`) remain focused on
        // the template itself and must not climb into the outer member path.
        if (current.kind() != "template_type"
            || parent
                .child_by_field_name("name")
                .is_some_and(|name| cpp_same_node(name, current)))
            && matches!(
                parent.kind(),
                "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier"
            )
            && qualified_access_focus(current, parent, &["scope"], &["name"])
                == Some(QualifiedAccessFocus::Member)
        {
            current = parent;
            continue;
        }
        if matches!(
            parent.kind(),
            "dependent_name" | "template_function" | "template_method" | "template_type"
        ) && parent.child_by_field_name("name") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "field_expression"
            && parent.child_by_field_name("field") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "call_expression"
            && parent.child_by_field_name("function") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "new_expression"
            && parent.start_byte() <= current.start_byte()
            && parent.end_byte() >= current.end_byte()
        {
            current = parent;
            continue;
        }
        if parent.kind() == "compound_literal_expression"
            && parent.child_by_field_name("type") == Some(current)
        {
            current = parent;
            continue;
        }
        break;
    }

    match current.kind() {
        "new_expression" | "compound_literal_expression" => {
            Some(CppReferenceNode::Construction(current))
        }
        "call_expression" => Some(CppReferenceNode::Call(current)),
        "field_expression" => Some(CppReferenceNode::Field(current)),
        "type_identifier"
        | "namespace_identifier"
        | "qualified_identifier"
        | "template_type"
        | "scoped_type_identifier" => Some(CppReferenceNode::Type(current)),
        "identifier"
        | "field_identifier"
        | "preproc_arg"
        | "operator_name"
        | "operator_cast"
        | "destructor_name"
        | "literal_operator_name" => Some(CppReferenceNode::Identifier(current)),
        _ => None,
    }
}

fn cpp_type_node_is_value_argument(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "argument_list" | "initializer_list") {
            return true;
        }
        if matches!(
            parent.kind(),
            "declaration"
                | "field_declaration"
                | "parameter_declaration"
                | "optional_parameter_declaration"
                | "function_definition"
                | "lambda_expression"
        ) {
            return false;
        }
        node = parent;
    }
    false
}

fn cpp_type_node_is_unqualified_name(node: Node<'_>) -> bool {
    matches!(node.kind(), "type_identifier" | "namespace_identifier")
}

fn cpp_type_node_is_parameter_type(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "parameter_declaration" | "optional_parameter_declaration"
        ) {
            return parent.child_by_field_name("type").is_some_and(|type_node| {
                type_node.start_byte() <= node.start_byte()
                    && node.end_byte() <= type_node.end_byte()
            });
        }
        if matches!(
            parent.kind(),
            "function_definition" | "lambda_expression" | "compound_statement"
        ) {
            return false;
        }
        node = parent;
    }
    false
}

fn cpp_type_node_is_declaration_type(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "parameter_declaration"
                | "optional_parameter_declaration"
                | "declaration"
                | "field_declaration"
                | "function_definition"
        ) {
            return parent.child_by_field_name("type").is_some_and(|type_node| {
                type_node.start_byte() <= node.start_byte()
                    && node.end_byte() <= type_node.end_byte()
            });
        }
        if matches!(
            parent.kind(),
            "compound_statement"
                | "return_statement"
                | "expression_statement"
                | "argument_list"
                | "initializer_list"
        ) {
            return false;
        }
        node = parent;
    }
    false
}

fn cpp_is_template_argument_type_leaf(node: Node<'_>) -> bool {
    let Some(type_descriptor) = node.parent() else {
        return false;
    };
    if type_descriptor.kind() != "type_descriptor"
        || type_descriptor.child_by_field_name("type") != Some(node)
    {
        return false;
    }
    let Some(arguments) = type_descriptor.parent() else {
        return false;
    };
    if arguments.kind() != "template_argument_list" {
        return false;
    }
    arguments.parent().is_some_and(|parent| {
        matches!(parent.kind(), "template_type" | "template_function")
            && parent.child_by_field_name("arguments") == Some(arguments)
    })
}

fn cpp_type_node_resolves_lexically(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> bool {
    let dispatch = CppDispatch::new(analyzer);
    let name = normalize_cpp_type_text(cpp_node_text(node, source));
    if name.is_empty() {
        return false;
    }
    let CppLexicalScopeResolution::Resolved(scope) =
        cpp_enclosing_lexical_scope_components(node, dispatch.source(), visibility, file, source)
    else {
        return false;
    };
    matches!(
        visibility.resolve_type_components_lexically_for_forward(
            dispatch.source(),
            file,
            &[name],
            false,
            &scope,
        ),
        CppLexicalTypeResolution::Resolved { unit, .. }
            if visibility.external_type_candidate_visible_in_context(dispatch.source(), file, &unit, node)
    )
}

fn cpp_type_node_is_local_constructor_argument(mut node: Node<'_>) -> bool {
    let mut inside_parameter = false;
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "parameter_declaration" | "optional_parameter_declaration" => {
                inside_parameter = true;
            }
            "function_declarator" if inside_parameter => {
                let mut declaration = parent.parent();
                while let Some(current) = declaration {
                    if current.kind() == "declaration" {
                        return cpp_enclosing_local_scope(current).is_some();
                    }
                    if matches!(current.kind(), "function_definition" | "field_declaration") {
                        return false;
                    }
                    declaration = current.parent();
                }
                return false;
            }
            "function_definition" | "lambda_expression" => return false,
            _ => {}
        }
        node = parent;
    }
    false
}

/// Resolve a `::`-qualified C++ type reference against the *enclosing namespaces*
/// of the reference site, trying each namespace prefix from innermost to the
/// global scope. This is the sibling-namespace shape (issue #1163): `inner::Gizmo`
/// referenced from inside `namespace outer { namespace deep { ... } }` resolves to
/// `outer::inner::Gizmo`.
///
/// With interned segments authoritative end-to-end (M4), C++'s mixed-separator
/// store no longer blocks this. The reference is re-interned with C++
/// namespace-qualified kinds — interior segments are namespaces
/// ([`SegmentKind::Package`]), the leaf is the referenced type
/// ([`SegmentKind::Type`]) — so composing it onto a namespace prefix renders in
/// the exact `::`-headed / `.`-terminated spelling the store keys nested-namespace
/// types by (`outer::inner.Gizmo`), and the walk descends the scope's `::`-joined
/// namespace head, which the shared dot-only enclosing-scope walk deliberately
/// never does. Each composed candidate is matched against the string-keyed
/// `definitions` index, so a hit is a real indexed declaration — never a guess;
/// the interior-namespace interpretation is the common `::`-qualified shape (a
/// `Class::Nested` nested-type reference is `$`-spelled in the store and is left
/// to the owner/member paths above).
fn cpp_resolve_qualified_via_enclosing_namespaces(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    reference: &str,
    byte: usize,
    accept: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    let parts = crate::analyzer::symbol_lookup::parse_symbol_path(Language::Cpp, reference);
    if parts.len() < 2 {
        // A bare name has no `::` head to re-anchor; the ordinary lexical and
        // enclosing-scope resolvers already cover it.
        return None;
    }
    let interner = crate::analyzer::fq_name::segment_interner();
    let mut reference_fq = crate::analyzer::fq_name::FqName::new();
    for (index, part) in parts.iter().enumerate() {
        let kind = if index + 1 == parts.len() {
            crate::analyzer::fq_name::SegmentKind::Type
        } else {
            crate::analyzer::fq_name::SegmentKind::Package
        };
        reference_fq.push(interner.intern(part, kind));
    }

    let range = Range {
        start_byte: byte,
        end_byte: byte + 1,
        start_line: 0,
        end_line: 0,
    };
    let scope_unit = analyzer.enclosing_code_unit(file, &range)?;
    let scope = scope_unit.fq();
    if scope.is_empty() {
        return None;
    }
    // The scope's namespace prefix is its leading run of `Package` (namespace)
    // segments; the owner/type/member tail below it is not a namespace we may
    // re-anchor a sibling namespace onto.
    let namespace_len = scope
        .segments()
        .iter()
        .take_while(|&&id| interner.resolve(id).1 == crate::analyzer::fq_name::SegmentKind::Package)
        .count();

    for prefix_len in (0..=namespace_len).rev() {
        let mut candidate = crate::analyzer::fq_name::FqName::new();
        for &id in &scope.segments()[..prefix_len] {
            candidate.push(id);
        }
        for &id in reference_fq.segments() {
            candidate.push(id);
        }
        let candidate_str = candidate.display_native(Language::Cpp, interner);
        if let Some(unit) = analyzer.definitions(&candidate_str).find(&accept) {
            return Some(unit);
        }
    }
    None
}

fn resolve_cpp_type(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    file: &ProjectFile,
    visibility: &CppVisibilityIndex,
    source: &str,
    node: Node<'_>,
    class_ranges: Option<&ClassRangeIndex>,
) -> DefinitionLookupOutcome {
    let dispatch = CppDispatch::new(analyzer);
    let node = cpp_expand_tagged_type_scope_reference(node).unwrap_or(node);
    let text = normalize_cpp_type_text(cpp_node_text(node, source));
    if text.is_empty() {
        return no_definition("no_reference_text", "C++ type reference is blank");
    }
    if cpp_is_non_reference_type_declaration_site(node)
        || cpp_is_non_reference_preprocessor_token(node)
    {
        return no_definition(
            "declaration_or_import_site",
            format!("`{text}` is not a C++ reference site"),
        );
    }
    if node.kind() == "type_identifier"
        && cpp_is_template_argument_type_leaf(node)
        && cpp_active_block_type_alias_node(node, &text, source).is_none()
        && !cpp_active_template_parameter_reference(node, source)
    {
        let candidates = cpp_enclosing_class_member_candidates(
            analyzer,
            context.bounded_support(),
            visibility,
            file,
            node,
            class_ranges,
            &text,
        );
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }
    // A template-id used as the scope of a qualified access denotes the
    // qualifier, not an independent unqualified template.  Resolve the full
    // structured qualifier below (for example `std::map<K,T>` in an inherited
    // constructor using-declaration).
    if cpp_focused_type_qualifier(node, source).is_none()
        && let Some(template_node) = cpp_template_application_node(node)
    {
        let qualified_template = matches!(
            template_node.kind(),
            "qualified_identifier" | "scoped_type_identifier"
        );
        if qualified_template
            && !visibility
                .resolve_type_node_primary(file, template_node, source)
                .is_some_and(|primary| {
                    cpp_qualified_type_candidate_matches_reference(template_node, source, &primary)
                })
        {
            let reference = cpp_callable_reference_text(template_node, source);
            // #1163 (was pinned at cpp.rs:2107): a `::`-qualified template-id whose
            // qualifier names a *sibling* nested namespace now resolves through the
            // segment-based namespace-outward net — C++'s mixed-separator store no
            // longer blocks it (M4). A hit is a real indexed declaration.
            if let Some(unit) = cpp_resolve_qualified_via_enclosing_namespaces(
                analyzer,
                file,
                &reference,
                node.start_byte(),
                |unit| {
                    unit.is_class()
                        && visibility.external_type_candidate_visible_at(
                            file,
                            unit,
                            node.start_byte(),
                        )
                },
            ) {
                return candidates_outcome(cpp_type_definition_candidates(
                    analyzer,
                    visibility,
                    file,
                    context.bounded_support(),
                    unit,
                ));
            }
            // Only a genuinely-external template-id reaches the include boundary.
            // `gated_boundary` makes the workspace-internal check structural: if the
            // namespace-outward net finds a *visible* indexed declaration for the
            // qualifier, the honest outcome is no_definition, never a boundary.
            return gated_boundary(
                || {
                    cpp_resolve_qualified_via_enclosing_namespaces(
                        analyzer,
                        file,
                        &reference,
                        node.start_byte(),
                        |unit| {
                            visibility.external_type_candidate_visible_at(
                                file,
                                unit,
                                node.start_byte(),
                            )
                        },
                    )
                    .is_some()
                        || !cpp_unresolved_include_boundary(analyzer, file, &reference)
                },
                format!(
                    "`{reference}` appears to cross a C++ include boundary not indexed in this workspace"
                ),
                "no_indexed_definition",
                format!("`{reference}` did not resolve to an indexed C++ type"),
            );
        }
        if !qualified_template {
            match cpp_enclosing_lexical_scope_components(
                node,
                dispatch.source(),
                visibility,
                file,
                source,
            ) {
                CppLexicalScopeResolution::Resolved(scope) => {
                    let lexical =
                        cpp_type_name_components(template_node, source).map(|components| {
                            visibility.resolve_type_components_lexically_for_forward(
                                dispatch.source(),
                                file,
                                &components,
                                false,
                                &scope,
                            )
                        });
                    match lexical {
                        Some(CppLexicalTypeResolution::Resolved { unit, .. })
                            if visibility.external_type_candidate_visible_at(
                                file,
                                &unit,
                                node.start_byte(),
                            ) =>
                        {
                            if cpp_unit_is_type_alias(analyzer, &unit) {
                                return candidates_outcome(vec![unit]);
                            }
                            let Some(arguments) =
                                cpp_template_reference_arguments(template_node, source)
                            else {
                                unreachable!("a template application has template arguments");
                            };
                            match visibility.resolve_template_arguments(file, unit, &arguments) {
                                Ok(unit) => {
                                    return candidates_outcome(cpp_type_definition_candidates(
                                        analyzer,
                                        visibility,
                                        file,
                                        context.bounded_support(),
                                        unit,
                                    ));
                                }
                                Err(error) => {
                                    return ambiguous_definition(cpp_template_resolution_message(
                                        &text, &error,
                                    ));
                                }
                            }
                        }
                        Some(CppLexicalTypeResolution::Ambiguous) => {
                            return ambiguous_definition(format!(
                                "`{text}` resolves ambiguously in its enclosing C++ class or namespace"
                            ));
                        }
                        Some(CppLexicalTypeResolution::Resolved { .. })
                        | Some(CppLexicalTypeResolution::Missing)
                        | None => {}
                    }
                }
                CppLexicalScopeResolution::Ambiguous => {
                    return ambiguous_definition(format!(
                        "the enclosing C++ owner of `{text}` resolves ambiguously"
                    ));
                }
                CppLexicalScopeResolution::Missing => {}
            }
        }
        match visibility.resolve_type_node_result(file, template_node, source) {
            Ok(Some(unit))
                if visibility.external_type_candidate_visible_at(
                    file,
                    &unit,
                    node.start_byte(),
                ) =>
            {
                return candidates_outcome(cpp_type_definition_candidates(
                    analyzer,
                    visibility,
                    file,
                    context.bounded_support(),
                    unit,
                ));
            }
            Err(error) => {
                return ambiguous_definition(cpp_template_resolution_message(&text, &error));
            }
            Ok(Some(_)) | Ok(None) => {}
        }
    }
    if let Some(qualifier) = cpp_focused_type_qualifier(node, source) {
        let namespace = cpp_lexical_namespace(node, source);
        let mut root = node;
        while let Some(parent) = root.parent() {
            root = parent;
        }
        let enclosing_owner = {
            let class_ranges = context.cpp_class_ranges(file);
            let support = context.bounded_support();
            cpp_enclosing_class_with_ranges(
                analyzer,
                support,
                visibility,
                file,
                source,
                root,
                node.start_byte(),
                &class_ranges,
            )
        };
        let enclosing_class_tiers =
            cpp_focused_type_enclosing_class_tiers(analyzer, context, enclosing_owner);
        let candidates = cpp_focused_type_qualifier_candidates(
            analyzer,
            context,
            visibility,
            file,
            &qualifier,
            namespace.as_deref(),
            &enclosing_class_tiers,
        )
        .into_iter()
        .filter(|candidate| {
            visibility.external_type_declaration_visible_at(file, candidate, node.start_byte())
        })
        .collect::<Vec<_>>();
        if !candidates.is_empty() {
            let support = context.bounded_support();
            let candidates = candidates
                .into_iter()
                .flat_map(|unit| {
                    cpp_selected_type_definition_candidates(
                        analyzer, visibility, file, support, unit,
                    )
                })
                .collect();
            return candidates_outcome(candidates);
        }
        // A template type parameter names no indexed type but is lexically
        // visible inside its own template (cutlass's `OperandLayout::packed`
        // inside OperandSharedStorage): the enclosing-scope walk finds the
        // parameter's declaration when it is indexed; without it the
        // qualifier drew a dishonest include-boundary claim (tier-4
        // DeepSpeed). The stand-in is restricted to parameter-like hits
        // (fields, not real types) so a class scope missing the member
        // stays an ordinary no-definition.
        if let Some(parameter) = resolve_in_enclosing_scopes(
            analyzer,
            file,
            &qualifier.reference,
            node.start_byte(),
            |unit| unit.source() == file && unit.is_field(),
        ) {
            return candidates_outcome(vec![parameter]);
        }
        if cpp_unresolved_include_boundary(analyzer, file, &qualifier.reference) {
            // gated upstream: the enclosing-scope parameter probe above returned
            // early for any workspace-declared qualifier; only an external one
            // (with an unresolved include) reaches here.
            return boundary_unchecked(format!(
                "`{}` appears to cross a C++ include boundary not indexed in this workspace",
                qualifier.reference
            ));
        }
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed C++ type qualifier",
                qualifier.reference
            ),
        );
    }
    resolve_cpp_type_without_focused_qualifier(
        analyzer,
        context.bounded_support(),
        file,
        visibility,
        source,
        node,
        &text,
        class_ranges,
    )
}

fn cpp_qualified_type_candidate_matches_reference(
    node: Node<'_>,
    source: &str,
    candidate: &CodeUnit,
) -> bool {
    if !matches!(
        node.kind(),
        "qualified_identifier" | "scoped_type_identifier"
    ) {
        return true;
    }
    let Some(reference) = cpp_type_name_components(node, source) else {
        return false;
    };
    let reference = reference.join("::");
    let candidate_name = cpp_name_for(candidate);
    if candidate_name == reference {
        return true;
    }
    cpp_lexical_namespace(node, source)
        .is_some_and(|namespace| candidate_name == format!("{namespace}::{reference}"))
}

fn cpp_template_application_node(mut node: Node<'_>) -> Option<Node<'_>> {
    let mut application = (node.kind() == "template_type").then_some(node);
    while let Some(parent) = node.parent() {
        if parent.kind() == "template_type" && parent.child_by_field_name("name") == Some(node) {
            node = parent;
            application = Some(node);
            continue;
        }
        if application.is_some()
            && matches!(
                parent.kind(),
                "qualified_identifier" | "scoped_type_identifier"
            )
            && parent.child_by_field_name("name") == Some(node)
        {
            node = parent;
            application = Some(node);
            continue;
        }
        break;
    }
    application
}

/// Macros are indexed as bare-named `CodeUnitType::Macro` units, but the
/// type and callable resolvers never consult them: an annotation macro
/// (`XXH_ALIGN_MEMBER(64, ...)`, `UNITY_PTR_ATTRIBUTE`) parses as the
/// declaration's type, and a function-like macro call parses as a call, so
/// every structured path missed and the include-boundary heuristic then
/// claimed the name was not indexed — while the `#define` sat in the very
/// file being probed (#1122). Resolve visible macro units: definitions in
/// the referencing file itself, plus definitions in headers the file
/// includes directly (structured include-target resolution, the same
/// information the boundary heuristic uses).
fn cpp_macro_candidates(analyzer: &dyn IAnalyzer, file: &ProjectFile, name: &str) -> Vec<CodeUnit> {
    if name.is_empty() || name.contains(':') {
        return Vec::new();
    }
    let include_targets =
        resolve_analyzer::<CppAnalyzer>(analyzer).map(|cpp| cpp.include_target_index());
    analyzer
        .definitions(name)
        .filter(CodeUnit::is_macro)
        .filter(|unit| {
            unit.source() == file
                || analyzer.import_statements(file).iter().any(|import| {
                    cpp_include_paths(std::slice::from_ref(import))
                        .iter()
                        .any(|include| {
                            let targets = match include_targets {
                                Some(index) => {
                                    resolve_include_targets_with_index(file, include, index)
                                }
                                None => resolve_include_targets(analyzer.project(), file, include),
                            };
                            targets.iter().any(|target| target == unit.source())
                        })
                })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn resolve_cpp_type_without_focused_qualifier(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    visibility: &CppVisibilityIndex,
    source: &str,
    node: Node<'_>,
    text: &str,
    class_ranges: Option<&ClassRangeIndex>,
) -> DefinitionLookupOutcome {
    let dispatch = CppDispatch::new(analyzer);
    let declaration_type_context = cpp_type_node_is_declaration_type(node);
    if node.kind() == "type_identifier"
        && let Some(alias_node) = cpp_active_block_type_alias_node(node, text, source)
    {
        if let Some(alias) =
            cpp_indexed_type_alias_for_node(analyzer, support, file, alias_node, text)
        {
            return candidates_outcome(vec![alias]);
        }
        return no_definition(
            "unresolved_local_type",
            format!("`{text}` names a local C++ type alias without a resolved definition"),
        );
    }
    if cpp_active_template_parameter_reference(node, source) {
        return no_definition(
            "unresolved_template_parameter",
            format!("`{text}` is an active C++ template parameter without an indexed definition"),
        );
    }
    if node.kind() == "type_identifier"
        && let Some(alias) = cpp_malformed_class_alias_candidate(
            analyzer,
            support,
            visibility,
            file,
            source,
            node,
            class_ranges,
            text,
        )
    {
        // Sentinel recovery re-owns the malformed class body and records an
        // exact class range even though the original tree leaves its members
        // under a sibling compound_statement. Prefer that recovered owner for
        // aliases in the body; retain the unresolved outcome when no indexed
        // class range proves the ownership.
        return candidates_outcome(vec![alias]);
    }
    if node.kind() == "type_identifier"
        && let Some(owner) = cpp_out_of_line_function_owner_for_type(
            analyzer, support, visibility, file, source, node,
        )
    {
        let candidates = cpp_direct_type_member_candidates(analyzer, support, &owner, text)
            .into_iter()
            .filter(|candidate| {
                !declaration_type_context
                    || cpp_unit_matches_kind(analyzer, support, candidate, CppTargetKind::Type)
            })
            .collect::<Vec<_>>();
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }
    let mut qualified_owner_lookup_attempted = false;
    if node.kind() == "qualified_identifier"
        && let Some(mut components) = cpp_type_name_components(node, source)
        && let Some(member) = components.pop()
        && !components.is_empty()
    {
        qualified_owner_lookup_attempted = declaration_type_context;
        let globally_qualified = is_globally_qualified_cpp_name(node);
        let owner_reference = components.join("::");
        let fallback_owner = || {
            let rendered = if globally_qualified {
                format!("::{owner_reference}")
            } else {
                owner_reference.clone()
            };
            cpp_resolve_type_unit_in_namespace(
                analyzer,
                visibility,
                file,
                &rendered,
                cpp_lexical_namespace(node, source).as_deref(),
            )
        };
        let owner = match cpp_enclosing_lexical_scope_components(
            node, dispatch.source(), visibility, file, source,
        ) {
            CppLexicalScopeResolution::Resolved(lexical_scope) => {
                match visibility.resolve_type_components_lexically_for_forward(
                    dispatch.source(),
                    file,
                    &components,
                    globally_qualified,
                    &lexical_scope,
                ) {
                    CppLexicalTypeResolution::Resolved { unit, .. } => Some(unit),
                    CppLexicalTypeResolution::Ambiguous => {
                        return ambiguous_definition(format!(
                            "`{owner_reference}` resolves ambiguously in its enclosing C++ class or namespace"
                        ));
                    }
                    CppLexicalTypeResolution::Missing => fallback_owner(),
                }
            }
            CppLexicalScopeResolution::Ambiguous => {
                return ambiguous_definition(format!(
                    "enclosing C++ scope for `{owner_reference}` is ambiguous"
                ));
            }
            CppLexicalScopeResolution::Missing => fallback_owner(),
        }
        .filter(|owner| {
            visibility.external_type_candidate_visible_at(file, owner, node.start_byte())
        });
        if let Some(owner) = owner {
            let type_candidates =
                cpp_direct_type_member_candidates(analyzer, support, &owner, &member);
            let candidates = if declaration_type_context {
                type_candidates
            } else {
                let member_candidates = cpp_direct_member_candidates(
                    analyzer,
                    support,
                    std::slice::from_ref(&owner),
                    &member,
                );
                if member_candidates.is_empty() {
                    type_candidates
                } else {
                    member_candidates
                }
            }
            .into_iter()
            .filter(|candidate| {
                !declaration_type_context
                    || cpp_unit_matches_kind(analyzer, support, candidate, CppTargetKind::Type)
            })
            .collect::<Vec<_>>();
            let mut specialization_failure = None;
            let candidates = match cpp_template_reference_arguments(node, source) {
                Some(arguments) if declaration_type_context => candidates
                    .into_iter()
                    .flat_map(|candidate| {
                        match visibility.resolve_template_arguments(file, candidate, &arguments) {
                            Ok(resolved) => cpp_type_definition_candidates(
                                analyzer, visibility, file, support, resolved,
                            ),
                            Err(error) => {
                                specialization_failure = Some(error);
                                Vec::new()
                            }
                        }
                    })
                    .collect(),
                _ => candidates,
            };
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            if let Some(error) = specialization_failure {
                return ambiguous_definition(cpp_template_resolution_message(text, &error));
            }
        } else {
            // A template type parameter names no indexed type but is
            // lexically visible inside its own template (cutlass's
            // `OperandLayout::packed` inside OperandSharedStorage). The
            // enclosing-scope walk finds the parameter's declaration when
            // it is indexed; without it the qualifier fell through to a
            // dishonest include-boundary claim (tier-4 DeepSpeed).
            if let Some(parameter) = resolve_in_enclosing_scopes(
                analyzer,
                file,
                &owner_reference,
                node.start_byte(),
                |unit| unit.source() == file,
            ) {
                let candidates = cpp_direct_member_candidates(
                    analyzer,
                    support,
                    std::slice::from_ref(&parameter),
                    &member,
                )
                .into_iter()
                .filter(|candidate| {
                    !declaration_type_context
                        || cpp_unit_matches_kind(analyzer, support, candidate, CppTargetKind::Type)
                })
                .collect::<Vec<_>>();
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
                // Only a parameter-like scope hit (a field, not a real
                // type) may stand in for the qualified reference: its
                // members are unknowable statically. A class scope with no
                // such member is an ordinary no-definition, not evidence
                // the owner resolves (cpp_macro_decorated_out_of_line
                // regression).
                if parameter.is_field() {
                    return candidates_outcome(vec![parameter]);
                }
            }
        }
    }
    if matches!(
        node.kind(),
        "qualified_identifier" | "scoped_type_identifier"
    ) {
        // Preserve a qualified template-id's arguments while re-opening the
        // visible-name fallback.  The owner/member probe above intentionally
        // handles nested types, but a namespace-qualified template alias (for
        // example `base::android::ScopedJavaGlobalRef<int>`) has no type owner
        // to resolve.  Falling back on the terminal spelling alone would let an
        // unrelated visible alias win (`std::remove_reference_t` ->
        // `absl::remove_reference_t`), so derive the lookup spelling from the
        // structured components and require an exact qualified-path match.
        let qualified_reference = cpp_type_name_components(node, source)
            .map(|components| components.join("::"))
            .unwrap_or_else(|| text.to_string());
        let template_arguments = cpp_template_reference_arguments(node, source);
        let mut specialization_failure = None;
        let candidates = cpp_visible_name_candidates(
            analyzer,
            visibility,
            file,
            support,
            &qualified_reference,
            Some(CppTargetKind::Type),
            cpp_lexical_namespace(node, source).as_deref(),
        )
        .into_iter()
        .filter(|candidate| {
            (!qualified_owner_lookup_attempted
                || cpp_qualified_type_candidate_matches_reference(node, source, candidate))
                && visibility.external_type_candidate_visible_at(file, candidate, node.start_byte())
        })
        .flat_map(|unit| {
            let resolved = match template_arguments.as_deref() {
                Some(arguments) => {
                    match visibility.resolve_template_arguments(file, unit, arguments) {
                        Ok(unit) => Some(unit),
                        Err(error) => {
                            specialization_failure = Some(error);
                            None
                        }
                    }
                }
                None => Some(unit),
            };
            resolved.into_iter().flat_map(|unit| {
                cpp_type_definition_candidates(analyzer, visibility, file, support, unit)
            })
        })
        .collect::<Vec<_>>();
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        if let Some(error) = specialization_failure {
            return ambiguous_definition(cpp_template_resolution_message(text, &error));
        }
        // #1163 (was pinned at cpp.rs:2402): a `::`-qualified/scoped identifier
        // whose qualifier names a *sibling* nested namespace now resolves through
        // the segment-based namespace-outward net. Nested-namespace declarations
        // are keyed `outer::inner.Gizmo`; the net re-interns the reference with
        // namespace-aware kinds and descends the scope's `::`-joined namespace
        // head, composing `outer::inner.Gizmo` exactly — which C++'s
        // mixed-separator store no longer obstructs now segments are authoritative
        // (M4). A hit is a real indexed declaration.
        if let Some(unit) = cpp_resolve_qualified_via_enclosing_namespaces(
            analyzer,
            file,
            text,
            node.start_byte(),
            |unit| {
                unit.is_class()
                    && visibility.external_type_candidate_visible_at(file, unit, node.start_byte())
            },
        ) {
            return candidates_outcome(cpp_type_definition_candidates(
                analyzer, visibility, file, support, unit,
            ));
        }
        // Only a genuinely-external qualified identifier reaches the include
        // boundary. `gated_boundary` makes the workspace-internal check structural:
        // if the namespace-outward net finds a *visible* indexed declaration for the
        // qualifier, the honest outcome is no_definition, never a boundary.
        return gated_boundary(
            || {
                cpp_resolve_qualified_via_enclosing_namespaces(
                    analyzer,
                    file,
                    text,
                    node.start_byte(),
                    |unit| {
                        visibility.external_type_candidate_visible_at(file, unit, node.start_byte())
                    },
                )
                .is_some()
                    || !cpp_unresolved_include_boundary(analyzer, file, text)
            },
            format!(
                "`{text}` appears to cross a C++ include boundary not indexed in this workspace"
            ),
            "no_indexed_definition",
            format!("`{text}` did not resolve to an indexed C++ type"),
        );
    }
    // Prefer a type declared in the lexically enclosing scope (namespace/class)
    // over the scope-blind visibility index, so a bare `Config` inside `namespace B`
    // resolves to `B::Config` rather than a same-named sibling namespace's (#431).
    if node.kind() == "type_identifier" {
        match cpp_enclosing_lexical_scope_components(
            node,
            dispatch.source(),
            visibility,
            file,
            source,
        ) {
            CppLexicalScopeResolution::Resolved(scope) => {
                match visibility.resolve_type_components_lexically_for_forward(
                    dispatch.source(),
                    file,
                    &[text.to_string()],
                    false,
                    &scope,
                ) {
                    CppLexicalTypeResolution::Resolved { unit, .. }
                        if visibility.external_type_candidate_visible_at(
                            file,
                            &unit,
                            node.start_byte(),
                        ) =>
                    {
                        return candidates_outcome(cpp_type_definition_candidates(
                            analyzer, visibility, file, support, unit,
                        ));
                    }
                    CppLexicalTypeResolution::Ambiguous => {
                        return ambiguous_definition(format!(
                            "`{text}` resolves ambiguously in its enclosing C++ class or namespace"
                        ));
                    }
                    CppLexicalTypeResolution::Resolved { .. }
                    | CppLexicalTypeResolution::Missing => {}
                }
            }
            CppLexicalScopeResolution::Ambiguous => {
                return ambiguous_definition(format!(
                    "the enclosing C++ owner of `{text}` resolves ambiguously"
                ));
            }
            CppLexicalScopeResolution::Missing => {
                // A file-scope definition such as
                // `bool ValueFlow::isLifetimeBorrowed()` has a qualified
                // namespace owner, but no namespace AST ancestor. The normal
                // scope reconstruction resolves only type owners, so it
                // reports Missing for this valid namespace path. Recover the
                // indexed namespace owner before the terminal-name fallback;
                // otherwise a nested same-named type can win by index order.
                if let Some(scope) = cpp_out_of_line_namespace_scope(support, source, node) {
                    match visibility.resolve_type_components_lexically_for_forward(
                        dispatch.source(),
                        file,
                        &[text.to_string()],
                        false,
                        &scope,
                    ) {
                        CppLexicalTypeResolution::Resolved { unit, .. }
                            if visibility.external_type_candidate_visible_at(
                                file,
                                &unit,
                                node.start_byte(),
                            ) =>
                        {
                            return candidates_outcome(cpp_type_definition_candidates(
                                analyzer, visibility, file, support, unit,
                            ));
                        }
                        CppLexicalTypeResolution::Ambiguous => {
                            return ambiguous_definition(format!(
                                "`{text}` resolves ambiguously in its enclosing C++ namespace"
                            ));
                        }
                        CppLexicalTypeResolution::Resolved { .. }
                        | CppLexicalTypeResolution::Missing => {}
                    }
                }
            }
        }
        if let Some(unit) =
            resolve_in_enclosing_scopes(analyzer, file, text, node.start_byte(), |unit| {
                unit.is_class() || cpp_unit_is_type_alias(analyzer, unit)
            })
        {
            return candidates_outcome(vec![unit]);
        }
    }
    if let Some(unit) = visibility.resolve_type(file, text)
        && visibility.external_type_candidate_visible_at(file, &unit, node.start_byte())
    {
        return candidates_outcome(cpp_type_definition_candidates(
            analyzer, visibility, file, support, unit,
        ));
    }
    let namespace = cpp_lexical_namespace(node, source);
    let candidates = cpp_visible_name_candidates(
        analyzer,
        visibility,
        file,
        support,
        text,
        Some(CppTargetKind::Type),
        namespace.as_deref(),
    )
    .into_iter()
    .filter(|candidate| {
        visibility.external_type_candidate_visible_at(file, candidate, node.start_byte())
    })
    .collect::<Vec<_>>();
    if !candidates.is_empty() {
        let candidates = candidates
            .into_iter()
            .flat_map(|unit| {
                cpp_type_definition_candidates(analyzer, visibility, file, support, unit)
            })
            .collect();
        return candidates_outcome(candidates);
    }
    let macros = cpp_macro_candidates(analyzer, file, text);
    if !macros.is_empty() {
        return candidates_outcome(macros);
    }
    // gated upstream: the type_identifier branch already ran the enclosing-scope
    // member fallback and the visible-name/lexical resolvers; a workspace-owned
    // bare type would have resolved there, so only an external one reaches here.
    if cpp_unresolved_include_boundary(analyzer, file, text) {
        return boundary_unchecked(format!(
            "`{text}` appears to cross a C++ include boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{text}` did not resolve to an indexed C++ type"),
    )
}

fn cpp_type_alias_declaration_contains_node(
    analyzer: &dyn IAnalyzer,
    candidate: &CodeUnit,
    node: Node<'_>,
) -> bool {
    cpp_unit_is_type_alias(analyzer, candidate)
        && analyzer
            .ranges(candidate)
            .into_iter()
            .any(|range| range.start_byte <= node.start_byte() && node.end_byte() <= range.end_byte)
}

fn cpp_active_template_parameter_reference(node: Node<'_>, source: &str) -> bool {
    let Some(components) = cpp_type_name_components(node, source) else {
        return false;
    };
    let Some(name) = components.first() else {
        return false;
    };
    if node.child(0).is_some_and(|child| child.kind() == "::") {
        return false;
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "template_declaration"
            && parent
                .child_by_field_name("parameters")
                .is_some_and(|parameters| {
                    parameters
                        .named_children(&mut parameters.walk())
                        .filter_map(|parameter| cpp_template_parameter_name(parameter, source))
                        .any(|parameter| parameter == *name)
                })
        {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn cpp_template_parameter_name(node: Node<'_>, source: &str) -> Option<String> {
    let candidate = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("declarator"))
        .or_else(|| {
            node.named_children(&mut node.walk()).find(|child| {
                matches!(
                    child.kind(),
                    "identifier" | "type_identifier" | "field_identifier"
                )
            })
        })?;
    if matches!(
        candidate.kind(),
        "identifier" | "type_identifier" | "field_identifier"
    ) {
        let name = cpp_node_text(candidate, source).trim();
        return (!name.is_empty()).then(|| name.to_string());
    }
    extract_variable_name(candidate, source)
}

fn cpp_active_block_type_alias_node<'tree>(
    node: Node<'tree>,
    name: &str,
    source: &str,
) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "compound_statement" | "function_definition") {
            for child in parent.named_children(&mut parent.walk()) {
                if child.end_byte() > node.start_byte() {
                    continue;
                }
                if cpp_type_alias_declaration_name(child, source).as_deref() == Some(name) {
                    return Some(child);
                }
            }
        }
        if parent.kind() == "function_definition" {
            break;
        }
        current = parent;
    }
    None
}

fn cpp_indexed_type_alias_for_node(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    alias_node: Node<'_>,
    name: &str,
) -> Option<CodeUnit> {
    support
        .file_identifier(file, name)
        .into_iter()
        .filter(|candidate| {
            candidate.source() == file && cpp_unit_is_type_alias(analyzer, candidate)
        })
        .find(|candidate| {
            analyzer.ranges(candidate).into_iter().any(|range| {
                range.start_byte <= alias_node.start_byte()
                    && alias_node.end_byte() <= range.end_byte
            })
        })
}

fn cpp_type_alias_declaration_name(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(node.kind(), "alias_declaration" | "type_definition") {
        return None;
    }
    let candidate = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("declarator"))?;
    if matches!(
        candidate.kind(),
        "identifier" | "type_identifier" | "field_identifier"
    ) {
        let name = cpp_node_text(candidate, source).trim();
        return (!name.is_empty()).then(|| name.to_string());
    }
    extract_variable_name(candidate, source)
}

#[allow(clippy::too_many_arguments)]
fn cpp_malformed_class_alias_candidate(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    class_ranges: Option<&ClassRangeIndex>,
    name: &str,
) -> Option<CodeUnit> {
    let mut function = node;
    loop {
        let parent = function.parent()?;
        if parent.kind() == "function_definition" {
            if !parent.child_by_field_name("type").is_some_and(|type_node| {
                type_node.start_byte() <= node.start_byte()
                    && node.end_byte() <= type_node.end_byte()
            }) {
                return None;
            }
            function = parent;
            break;
        }
        if matches!(
            parent.kind(),
            "compound_statement" | "parameter_list" | "parameter_declaration"
        ) {
            return None;
        }
        function = parent;
    }

    let mut class_body = function;
    while let Some(parent) = class_body.parent() {
        if parent.kind() == "compound_statement"
            && parent
                .parent()
                .is_some_and(|owner| owner.kind() == "declaration_list")
            && parent.start_byte() <= function.start_byte()
        {
            class_body = parent;
            break;
        }
        class_body = parent;
    }
    if class_body.kind() != "compound_statement" {
        return None;
    }
    let header = class_body.prev_named_sibling()?;
    if header.kind() != "ERROR"
        || header.end_byte() > class_body.start_byte()
        || class_body.child(0).is_none_or(|child| child.kind() != "{")
        || !cpp_error_contains_class_header(header)
    {
        return None;
    }

    let mut root = node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let owner = class_ranges.map_or_else(
        || {
            cpp_enclosing_class(
                analyzer,
                support,
                visibility,
                file,
                source,
                root,
                node.start_byte(),
            )
        },
        |ranges| {
            cpp_enclosing_class_with_ranges(
                analyzer,
                support,
                visibility,
                file,
                source,
                root,
                node.start_byte(),
                ranges,
            )
        },
    )?;
    cpp_direct_type_member_candidates(analyzer, support, &owner, name)
        .into_iter()
        .find(|candidate| {
            analyzer.ranges(candidate).into_iter().any(|range| {
                range.start_byte < node.start_byte() && range.end_byte <= node.start_byte()
            })
        })
}

fn cpp_error_contains_class_header(node: Node<'_>) -> bool {
    let mut pending = vec![(node, 0usize)];
    while let Some((current, depth)) = pending.pop() {
        if matches!(current.kind(), "class" | "struct" | "union") {
            let mut sibling = current.next_sibling();
            let mut saw_name = false;
            while let Some(candidate) = sibling {
                match candidate.kind() {
                    "comment" => {}
                    "{" | "base_class_clause" | ":" => return saw_name,
                    "identifier" | "type_identifier" if !saw_name => saw_name = true,
                    _ if !candidate.is_named() => {}
                    _ => break,
                }
                sibling = candidate.next_sibling();
            }
        }
        if depth >= 1 {
            continue;
        }
        let mut cursor = current.walk();
        pending.extend(
            current
                .children(&mut cursor)
                .filter(|child| child.kind() != "compound_statement")
                .map(|child| (child, depth + 1)),
        );
    }
    false
}

fn cpp_out_of_line_function_owner_for_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<CodeUnit> {
    let mut current = node.parent();
    while let Some(candidate) = current {
        if candidate.kind() == "function_definition" {
            return cpp_function_definition_owner(
                analyzer,
                support,
                visibility,
                file,
                source,
                candidate,
                node.start_byte(),
            );
        }
        current = candidate.parent();
    }
    None
}

fn cpp_direct_type_member_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: &CodeUnit,
    member: &str,
) -> Vec<CodeUnit> {
    let query = format!("{}${member}", owner.fq_name());
    let mut candidates = support
        .fqn(&query)
        .into_iter()
        .filter(|candidate| {
            candidate.identifier() == member
                && candidate.source() == owner.source()
                && cpp_unit_matches_kind(analyzer, support, candidate, CppTargetKind::Type)
        })
        .collect::<Vec<_>>();
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

struct CppFocusedQualifier {
    reference: String,
    identifier: String,
    components: Vec<String>,
    globally_qualified: bool,
}

/// Returns the type path denoted by a focused `::` qualifier. Tree-sitter nests
/// the components after the first one through successive `name` fields, so walk
/// those structural parents and prepend each preceding `scope` field. A terminal
/// member is deliberately excluded from the returned path.
fn cpp_focused_type_qualifier(node: Node<'_>, source: &str) -> Option<CppFocusedQualifier> {
    let mut current = node.parent();
    let access = loop {
        let parent = current?;
        if parent.kind() == "qualified_identifier"
            && qualified_access_focus(node, parent, &["scope"], &["name"])
                == Some(QualifiedAccessFocus::Qualifier)
        {
            break parent;
        }
        current = parent.parent();
    };

    let focused = cpp_qualifier_scope_component(node, source)?;
    let mut scopes = Vec::new();
    let mut nested_access = access;
    let mut globally_qualified = false;
    while let Some(parent) = nested_access.parent() {
        if parent.kind() != "qualified_identifier"
            || qualified_access_focus(nested_access, parent, &["scope"], &["name"])
                != Some(QualifiedAccessFocus::Member)
        {
            break;
        }
        if let Some(scope) = parent.child_by_field_name("scope") {
            scopes.push(cpp_qualifier_scope_component(scope, source)?);
        } else {
            globally_qualified = true;
        }
        nested_access = parent;
    }
    scopes.reverse();
    scopes.push(focused);
    let components = scopes.iter().map(|scope| (*scope).to_string()).collect();
    Some(CppFocusedQualifier {
        reference: scopes.join("::"),
        identifier: focused.to_string(),
        components,
        globally_qualified,
    })
}

fn cpp_qualifier_scope_component<'a>(scope: Node<'_>, source: &'a str) -> Option<&'a str> {
    let scope = if scope.kind() == "template_type" {
        scope.child_by_field_name("name")?
    } else {
        scope
    };
    let component = cpp_node_text(scope, source).trim();
    (!component.is_empty()).then_some(component)
}

fn cpp_focused_type_qualifier_candidates(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    qualifier: &CppFocusedQualifier,
    lexical_namespace: Option<&str>,
    enclosing_class_tiers: &[Vec<CodeUnit>],
) -> Vec<CodeUnit> {
    let candidates = visibility
        .visible_identifier_candidates(file, &qualifier.identifier)
        .filter(|unit| unit.is_class() || cpp_unit_is_type_alias(analyzer, unit))
        .cloned()
        .collect::<Vec<_>>();
    for lookup_paths in
        cpp_qualifier_lookup_tiers(qualifier, lexical_namespace, enclosing_class_tiers)
    {
        let mut tier = candidates
            .iter()
            .filter(|unit| {
                lookup_paths.iter().any(|lookup_path| {
                    cpp_type_qualifier_matches_exact_path(analyzer, context, unit, lookup_path)
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        if !tier.is_empty() {
            sort_units(&mut tier);
            tier.dedup();
            return tier;
        }
    }
    Vec::new()
}

fn cpp_focused_type_enclosing_class_tiers(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    enclosing_owner: Option<CodeUnit>,
) -> Vec<Vec<CodeUnit>> {
    let Some(owner) = enclosing_owner else {
        return Vec::new();
    };
    let lexical_owners = context
        .enclosing_owner_chain(owner, CodeUnit::is_class)
        .as_ref()
        .clone();
    let hierarchy = analyzer.type_hierarchy_provider();
    let mut tiers = Vec::new();
    for lexical_owner in lexical_owners {
        tiers.push(vec![lexical_owner.clone()]);
        let Some(hierarchy) = hierarchy else {
            continue;
        };
        let mut seen = HashSet::default();
        seen.insert(lexical_owner.clone());
        let mut frontier = hierarchy.get_direct_ancestors(&lexical_owner);
        loop {
            frontier.retain(|base| seen.insert(base.clone()));
            sort_units(&mut frontier);
            frontier.dedup();
            if frontier.is_empty() {
                break;
            }
            let next = frontier
                .iter()
                .flat_map(|base| hierarchy.get_direct_ancestors(base))
                .collect();
            tiers.push(frontier);
            frontier = next;
        }
    }
    tiers
}

fn cpp_qualifier_lookup_tiers(
    qualifier: &CppFocusedQualifier,
    lexical_namespace: Option<&str>,
    enclosing_class_tiers: &[Vec<CodeUnit>],
) -> Vec<Vec<String>> {
    if qualifier.globally_qualified {
        return vec![vec![qualifier.reference.clone()]];
    }

    let mut tiers = Vec::new();
    for owner_tier in enclosing_class_tiers {
        let mut paths = Vec::new();
        for owner in owner_tier {
            let owner_name = cpp_name_for(owner);
            let path = if qualifier
                .components
                .first()
                .is_some_and(|component| component == owner.identifier())
            {
                let suffix = qualifier.components[1..].join("::");
                if suffix.is_empty() {
                    owner_name
                } else {
                    format!("{owner_name}::{suffix}")
                }
            } else {
                format!("{owner_name}::{}", qualifier.reference)
            };
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        if !paths.is_empty() {
            tiers.push(paths);
        }
    }
    let mut namespace = lexical_namespace.map(str::to_string);
    while let Some(current) = namespace {
        let path = format!("{current}::{}", qualifier.reference);
        if !tiers.iter().flatten().any(|existing| existing == &path) {
            tiers.push(vec![path]);
        }
        // A C++ namespace chain is `::`-joined with no embedded delimiters in any
        // single component, so re-tokenizing it with the shared structured
        // splitter and dropping the innermost component reproduces
        // `rsplit_once("::")`'s outward walk exactly.
        let mut parts = crate::analyzer::symbol_lookup::parse_symbol_path(Language::Cpp, &current);
        namespace = if parts.len() > 1 {
            parts.pop();
            Some(parts.join("::"))
        } else {
            None
        };
    }
    if !tiers
        .iter()
        .flatten()
        .any(|existing| existing == &qualifier.reference)
    {
        tiers.push(vec![qualifier.reference.clone()]);
    }
    tiers
}

fn cpp_type_qualifier_matches_exact_path(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    unit: &CodeUnit,
    lookup_path: &str,
) -> bool {
    if cpp_name_for(unit) == lookup_path {
        return true;
    }
    if !cpp_unit_is_type_alias(analyzer, unit) {
        return false;
    }
    cpp_structural_alias_paths(context, analyzer, unit)
        .iter()
        .any(|path| path == lookup_path)
}

fn cpp_structural_alias_paths(
    context: &mut DefinitionBatchContext<'_>,
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Vec<String> {
    if let Some(paths) = context.cpp_structural_alias_paths.get(unit) {
        return paths.clone();
    }
    let Some(source) = context.cpp_indexed_source(unit.source()) else {
        context
            .cpp_structural_alias_paths
            .insert(unit.clone(), Vec::new());
        return Vec::new();
    };
    let Some(tree) = context.cpp_indexed_tree(unit.source()) else {
        context
            .cpp_structural_alias_paths
            .insert(unit.clone(), Vec::new());
        return Vec::new();
    };
    let root = tree.root_node();
    let mut paths = Vec::new();
    for range in analyzer.ranges(unit) {
        let Some(mut declaration) =
            smallest_named_node_covering(root, range.start_byte, range.end_byte)
        else {
            continue;
        };
        while !matches!(declaration.kind(), "alias_declaration" | "type_definition") {
            let Some(parent) = declaration.parent() else {
                break;
            };
            declaration = parent;
        }
        if !matches!(declaration.kind(), "alias_declaration" | "type_definition") {
            continue;
        }

        let mut owners = Vec::new();
        let mut current = declaration.parent();
        while let Some(parent) = current {
            if matches!(
                parent.kind(),
                "namespace_definition"
                    | "class_specifier"
                    | "struct_specifier"
                    | "union_specifier"
                    | "enum_specifier"
            ) && let Some(name) = parent.child_by_field_name("name")
            {
                let name = cpp_node_text(name, &source).trim();
                if !name.is_empty() {
                    owners.push(name);
                }
            }
            current = parent.parent();
        }
        owners.reverse();
        owners.push(unit.identifier());
        paths.push(owners.join("::"));
    }
    paths.sort();
    paths.dedup();
    context
        .cpp_structural_alias_paths
        .insert(unit.clone(), paths.clone());
    paths
}

fn cpp_type_definition_candidates(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    support: &dyn BoundedDefinitionLookup,
    unit: CodeUnit,
) -> Vec<CodeUnit> {
    let mut seen = HashSet::default();
    let target =
        cpp_alias_target_unit(analyzer, visibility, file, &unit, &mut seen).unwrap_or(unit);
    let indexed = support
        .fqn(&target.fq_name())
        .into_iter()
        .filter(|candidate| {
            cpp_unit_matches_kind(analyzer, support, candidate, CppTargetKind::Type)
        })
        .collect::<Vec<_>>();
    if indexed.is_empty() {
        vec![target]
    } else {
        indexed
    }
}

fn cpp_selected_type_definition_candidates(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    support: &dyn BoundedDefinitionLookup,
    unit: CodeUnit,
) -> Vec<CodeUnit> {
    let mut seen = HashSet::default();
    let target =
        cpp_alias_target_unit(analyzer, visibility, file, &unit, &mut seen).unwrap_or(unit);
    let indexed = support
        .fqn(&target.fq_name())
        .into_iter()
        .filter(|candidate| {
            candidate.source() == target.source()
                && cpp_unit_matches_kind(analyzer, support, candidate, CppTargetKind::Type)
        })
        .collect::<Vec<_>>();
    if indexed.is_empty() {
        vec![target]
    } else {
        indexed
    }
}

fn resolve_cpp_call(ctx: CppLookupCtx<'_, '_>, call: Node<'_>) -> DefinitionLookupOutcome {
    let ctx_dispatch = CppDispatch::new(ctx.analyzer);
    let Some(function) = call.child_by_field_name("function") else {
        return no_definition("no_function_name", "C++ call expression has no function");
    };
    let call_arity = ctx
        .visibility
        .call_arity_evidence(ctx.file, call, ctx.source)
        .exact();
    if let Some(operator) = cpp_explicit_operator_name(call) {
        let member = cpp_node_text(operator, ctx.source);
        let owners = cpp_receiver_type_units(ctx, function, false);
        let candidates = cpp_member_candidates_lazy(ctx, owners, member, call_arity, || {
            cpp_call_argument_types(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                ctx.root,
                call,
            )
        });
        return if candidates.is_empty() {
            no_definition(
                "unsupported_cpp_receiver",
                format!("receiver for C++ operator `{member}` is not resolved"),
            )
        } else {
            cpp_callable_candidates_outcome(candidates)
        };
    }
    match function.kind() {
        "field_expression" => {
            let call_arg_types = cpp_call_argument_types(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                ctx.root,
                call,
            );
            resolve_cpp_field(ctx, function, call_arity, call_arg_types.as_deref())
        }
        "type_identifier" | "template_type" | "scoped_type_identifier" => {
            resolve_cpp_construction_type(ctx, call)
        }
        "qualified_identifier" => {
            let text = cpp_callable_reference_text(function, ctx.source);
            let construction = resolve_cpp_construction_type(ctx, call);
            let construction_boundary =
                construction.status == DefinitionLookupStatus::UnresolvableImportBoundary;
            // A qualified call `Scope::name(...)` is only genuinely constructor-shaped when
            // the trailing path segment names the constructed type itself: either a
            // self-named constructor call (`Type::Type(...)`) or a namespace-qualified bare
            // type construction (`ns::Type()`), where the type's own identifier is that
            // trailing segment. `resolve_cpp_construction_type` resolves the qualified scope
            // text as a type reference, which -- for a *templated* scope followed by an
            // unrelated trailing member (`Loader<int>::parse()`) -- can coincidentally match
            // the scope's own class: template-argument text swallows the trailing
            // `::member` before the type lookup ever sees it (issue #935). Guard against that
            // by requiring the resolved type's identifier to actually match the call's
            // trailing segment; otherwise fall through to the static/owner-member routing
            // below, which resolves the scope independently of the trailing member name.
            let construction_names_trailing_segment =
                cpp_callable_name_node(function).is_none_or(|name| {
                    let trailing = cpp_node_text(name, ctx.source);
                    !construction.definitions.is_empty()
                        && construction.definitions.iter().all(|unit| {
                            unit.is_class() || cpp_unit_is_type_alias(ctx.analyzer, unit)
                        })
                        && construction
                            .definitions
                            .iter()
                            .all(|unit| unit.identifier() == trailing)
                });
            if construction.status != DefinitionLookupStatus::NoDefinition
                && !construction_boundary
                && construction_names_trailing_segment
            {
                return construction;
            }
            let mut candidates = cpp_visible_name_candidates(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.support,
                &text,
                Some(CppTargetKind::FreeFunction),
                cpp_lexical_namespace(function, ctx.source).as_deref(),
            );
            candidates.retain(|candidate| {
                ctx.visibility.declaration_visible_at(
                    ctx_dispatch.source(),
                    ctx.file,
                    candidate,
                    call.start_byte(),
                )
            });
            if !candidates.is_empty() {
                candidates = cpp_filter_candidates_by_call_lazy(
                    candidates,
                    call_arity,
                    || {
                        cpp_call_argument_types(
                            ctx.analyzer,
                            ctx.support,
                            ctx.visibility,
                            ctx.file,
                            ctx.source,
                            ctx.root,
                            call,
                        )
                    },
                    ctx.analyzer,
                    ctx.visibility,
                    ctx.file,
                );
                if qualified_call_has_applicable_arity(&candidates, call_arity, ctx.analyzer) {
                    return cpp_callable_candidates_outcome(candidates);
                }
                candidates.clear();
            }
            if let Some(scope) = function.child_by_field_name("scope")
                && let Some(name) = function
                    .child_by_field_name("name")
                    .and_then(cpp_callable_name_node)
            {
                let member = cpp_node_text(name, ctx.source);
                let scope_text = cpp_node_text(scope, ctx.source);
                let mut owners = ctx
                    .visibility
                    .resolve_type(ctx.file, scope_text)
                    .into_iter()
                    .collect::<Vec<_>>();
                owners.extend(cpp_visible_name_candidates(
                    ctx.analyzer,
                    ctx.visibility,
                    ctx.file,
                    ctx.support,
                    scope_text,
                    Some(CppTargetKind::Type),
                    cpp_lexical_namespace(scope, ctx.source).as_deref(),
                ));
                sort_units(&mut owners);
                owners.dedup();
                candidates = cpp_member_candidates_lazy(ctx, owners, member, call_arity, || {
                    cpp_call_argument_types(
                        ctx.analyzer,
                        ctx.support,
                        ctx.visibility,
                        ctx.file,
                        ctx.source,
                        ctx.root,
                        call,
                    )
                });
                sort_units(&mut candidates);
                candidates.dedup();
                if !candidates.is_empty() {
                    return cpp_callable_candidates_outcome(candidates);
                }
            }
            if construction_boundary {
                return construction;
            }
            // gated upstream: the owner/member candidate resolution above is the
            // workspace check; a workspace-declared callable resolves there, so
            // only an external one (with an unresolved include) reaches here.
            if cpp_unresolved_include_boundary(ctx.analyzer, ctx.file, &text) {
                return boundary_unchecked(format!(
                    "`{text}` appears to cross a C++ include boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed C++ callable"),
            )
        }
        "identifier"
        | "field_identifier"
        | "dependent_name"
        | "template_function"
        | "template_method"
        | "operator_name"
        | "operator_cast"
        | "destructor_name"
        | "literal_operator_name" => {
            let Some(name_node) = cpp_callable_name_node(function) else {
                return no_definition("no_function_name", "C++ call name is blank");
            };
            let name = cpp_node_text(name_node, ctx.source);
            if name.is_empty() {
                return no_definition("no_function_name", "C++ call name is blank");
            }
            let bindings = cpp_local_bindings_before(ctx, name_node, name_node.start_byte());
            if bindings.is_shadowed(name) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{name}` is a local C++ value"),
                );
            }
            if let Some(owner) = cpp_enclosing_class(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                ctx.root,
                name_node.start_byte(),
            ) {
                let (member_candidates, had_member_callable) = if call_arity.is_none() {
                    cpp_member_candidates_lazy_with_presence(ctx, vec![owner], name, None, || None)
                } else {
                    cpp_member_candidates_lazy_with_presence(
                        ctx,
                        vec![owner],
                        name,
                        call_arity,
                        || {
                            cpp_call_argument_types(
                                ctx.analyzer,
                                ctx.support,
                                ctx.visibility,
                                ctx.file,
                                ctx.source,
                                ctx.root,
                                call,
                            )
                        },
                    )
                };
                if !member_candidates.is_empty() {
                    if call_arity.is_none() {
                        return ambiguous_definition(format!(
                            "the argument count for C++ call `{name}` is unknown after macro expansion"
                        ));
                    }
                    return cpp_callable_candidates_outcome(member_candidates);
                }
                if had_member_callable {
                    return no_definition(
                        "no_applicable_overload",
                        format!("member `{name}` has no applicable C++ overload"),
                    );
                }
            }
            let imports = cpp_initialized_effective_using_imports(
                ctx.root,
                ctx_dispatch.source(),
                ctx.visibility,
                ctx.file,
                ctx.source,
            );
            match cpp_resolve_bare_call_target(
                call,
                function,
                ctx_dispatch.source(),
                ctx.visibility,
                &imports,
                ctx.file,
                ctx.source,
            ) {
                CppBareCallTargetResolution::FreeFunctions(units) => {
                    let mut candidates =
                        cpp_bare_free_function_definition_candidates(ctx, units, call.start_byte());
                    candidates = cpp_filter_candidates_by_call_lazy(
                        candidates,
                        call_arity,
                        || {
                            cpp_call_argument_types(
                                ctx.analyzer,
                                ctx.support,
                                ctx.visibility,
                                ctx.file,
                                ctx.source,
                                ctx.root,
                                call,
                            )
                        },
                        ctx.analyzer,
                        ctx.visibility,
                        ctx.file,
                    );
                    return cpp_callable_candidates_outcome(candidates);
                }
                CppBareCallTargetResolution::UnprovenFreeFunctions(units) => {
                    if units.len() < 2 {
                        return ambiguous_definition(format!(
                            "the argument count for C++ call `{name}` is unknown after macro expansion"
                        ));
                    }
                    let candidates =
                        cpp_bare_free_function_definition_candidates(ctx, units, call.start_byte());
                    return ambiguous_candidates_outcome(
                        candidates,
                        format!(
                            "the argument count for C++ call `{name}` is unknown after macro expansion"
                        ),
                    );
                }
                CppBareCallTargetResolution::Type(unit) => {
                    let owners = cpp_type_definition_candidates(
                        ctx.analyzer,
                        ctx.visibility,
                        ctx.file,
                        ctx.support,
                        unit,
                    );
                    return candidates_outcome(owners);
                }
                CppBareCallTargetResolution::CallableShadow => {
                    return no_definition(
                        "no_applicable_overload",
                        format!("`{name}` is declared but has no applicable overload"),
                    );
                }
                CppBareCallTargetResolution::Ambiguous => {
                    return ambiguous_definition(format!(
                        "C++ bare call `{name}` has ambiguous lookup candidates"
                    ));
                }
                CppBareCallTargetResolution::Missing => {}
            }
            let macros = cpp_macro_candidates(ctx.analyzer, ctx.file, name);
            if !macros.is_empty() {
                return candidates_outcome(macros);
            }
            no_definition(
                "no_indexed_definition",
                format!("`{name}` did not resolve to an indexed C++ callable"),
            )
        }
        _ => no_definition(
            "unsupported_cpp_reference_shape",
            format!(
                "C++ `{}` call targets are not resolved by get_definition yet",
                function.kind()
            ),
        ),
    }
}

fn cpp_bare_free_function_definition_candidates(
    ctx: CppLookupCtx<'_, '_>,
    units: Vec<CodeUnit>,
    reference_byte: usize,
) -> Vec<CodeUnit> {
    let ctx_dispatch = CppDispatch::new(ctx.analyzer);
    let mut candidates: Vec<_> = units
        .into_iter()
        .flat_map(|unit| {
            let indexed = ctx
                .support
                .fqn(&unit.fq_name())
                .into_iter()
                .filter(|candidate| {
                    cpp_unit_matches_kind(
                        ctx.analyzer,
                        ctx.support,
                        candidate,
                        CppTargetKind::FreeFunction,
                    ) && cpp_callable_definitions_share_identity_evidence(
                        ctx.analyzer,
                        &unit,
                        candidate,
                    )
                })
                .collect::<Vec<_>>();
            if indexed.is_empty() {
                vec![unit]
            } else {
                indexed
            }
        })
        .collect();
    candidates.retain(|candidate| {
        ctx.visibility.declaration_visible_at(
            ctx_dispatch.source(),
            ctx.file,
            candidate,
            reference_byte,
        )
    });
    candidates
}

fn cpp_explicit_operator_name(call: Node<'_>) -> Option<Node<'_>> {
    if call.kind() != "call_expression" {
        return None;
    }
    let arguments = call.child_by_field_name("arguments");
    let mut cursor = call.walk();
    let errors = call
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "ERROR" && Some(*child) != arguments);
    for error in errors {
        let mut stack = vec![error];
        while let Some(node) = stack.pop() {
            if matches!(
                node.kind(),
                "operator_name" | "operator_cast" | "literal_operator_name"
            ) {
                return Some(node);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
    }
    None
}

fn cpp_callable_name_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    loop {
        current = match current.kind() {
            "identifier"
            | "field_identifier"
            | "type_identifier"
            | "namespace_identifier"
            | "operator_name"
            | "operator_cast"
            | "destructor_name"
            | "literal_operator_name"
            | "primitive_type" => return Some(current),
            "dependent_name" | "template_function" | "template_method" | "template_type" => {
                current.child_by_field_name("name")?
            }
            "qualified_identifier" | "scoped_identifier" | "scoped_type_identifier" => {
                let mut cursor = current.walk();
                current
                    .children_by_field_name("name", &mut cursor)
                    .filter(|child| child.is_named())
                    .last()?
            }
            "field_expression" => current.child_by_field_name("field")?,
            "parenthesized_expression" => {
                let mut cursor = current.walk();
                let mut children = current.named_children(&mut cursor);
                let child = children.next()?;
                if children.next().is_some() {
                    return None;
                }
                child
            }
            _ => return None,
        };
    }
}

fn cpp_callable_reference_text(node: Node<'_>, source: &str) -> String {
    if node.kind() == "qualified_identifier"
        && let (Some(scope), Some(name)) = (
            node.child_by_field_name("scope"),
            node.child_by_field_name("name")
                .and_then(cpp_callable_name_node),
        )
    {
        return format!(
            "{}::{}",
            cpp_node_text(scope, source),
            cpp_node_text(name, source)
        );
    }
    let name = cpp_callable_name_node(node).unwrap_or(node);
    cpp_node_text(name, source).to_string()
}

fn resolve_cpp_construction_type(
    ctx: CppLookupCtx<'_, '_>,
    construction: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(type_node) = cpp_constructor_type_node(construction) else {
        return no_definition("no_reference_text", "C++ constructor call has no type");
    };
    let text = normalize_cpp_type_text(cpp_node_text(type_node, ctx.source));
    if text.is_empty() {
        return no_definition("no_reference_text", "C++ constructor type is blank");
    }

    if cpp_type_node_is_unqualified_name(type_node) {
        if let Some(alias_node) = (type_node.kind() == "type_identifier")
            .then(|| cpp_active_block_type_alias_node(type_node, &text, ctx.source))
            .flatten()
        {
            if let Some(alias) = cpp_indexed_type_alias_for_node(
                ctx.analyzer,
                ctx.support,
                ctx.file,
                alias_node,
                &text,
            ) {
                return candidates_outcome(vec![alias]);
            }
            return no_definition(
                "unresolved_local_type",
                format!("`{text}` names a local C++ type alias without a resolved definition"),
            );
        }
        if cpp_active_template_parameter_reference(type_node, ctx.source) {
            return no_definition(
                "unresolved_template_parameter",
                format!(
                    "`{text}` is an active C++ template parameter without an indexed definition"
                ),
            );
        }
        let member_candidates = cpp_enclosing_class_member_candidates(
            ctx.analyzer,
            ctx.support,
            ctx.visibility,
            ctx.file,
            type_node,
            ctx.class_ranges,
            &text,
        );
        if !member_candidates.is_empty() {
            return candidates_outcome(member_candidates);
        }
        if let Some(unit) = resolve_in_enclosing_scopes(
            ctx.analyzer,
            ctx.file,
            &text,
            type_node.start_byte(),
            |unit| unit.is_class() || cpp_unit_is_type_alias(ctx.analyzer, unit),
        ) {
            return candidates_outcome(vec![unit]);
        }
    }

    let mut owners = Vec::new();
    if let Some(owner) = ctx.visibility.resolve_type(ctx.file, &text) {
        owners.push(owner);
    }
    owners.extend(cpp_visible_name_candidates(
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
        ctx.support,
        &text,
        Some(CppTargetKind::Type),
        cpp_lexical_namespace(type_node, ctx.source).as_deref(),
    ));
    owners = owners
        .into_iter()
        .flat_map(|unit| {
            cpp_type_definition_candidates(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.support,
                unit,
            )
        })
        .filter(|unit| cpp_unit_matches_kind(ctx.analyzer, ctx.support, unit, CppTargetKind::Type))
        .collect();
    sort_units(&mut owners);
    owners.dedup();

    // C++ constructors do not have names. The focused token in `Service(args)`,
    // `Service{args}`, or `new Service(args)` names the constructed type, so
    // ordinary navigation belongs to that type. Constructor-call attribution
    // remains a separate usage-graph concern.
    if !owners.is_empty() {
        return candidates_outcome(owners);
    }
    resolve_cpp_type_without_focused_qualifier(
        ctx.analyzer,
        ctx.support,
        ctx.file,
        ctx.visibility,
        ctx.source,
        type_node,
        &text,
        ctx.class_ranges,
    )
}

fn resolve_cpp_field(
    ctx: CppLookupCtx<'_, '_>,
    field: Node<'_>,
    arity: Option<usize>,
    arg_types: Option<&[Option<CppType>]>,
) -> DefinitionLookupOutcome {
    let Some(name_node) = field.child_by_field_name("field") else {
        return no_definition("no_member_name", "C++ field expression has no member name");
    };
    let Some(name_node) = cpp_callable_name_node(name_node) else {
        return no_definition(
            "unsupported_cpp_reference_shape",
            format!(
                "C++ `{}` member names are not resolved by get_definition yet",
                name_node.kind()
            ),
        );
    };
    let member = cpp_node_text(name_node, ctx.source);
    let Some(receiver) = field
        .child_by_field_name("argument")
        .or_else(|| field.named_child(0))
    else {
        return no_definition("no_member_receiver", "C++ field expression has no receiver");
    };
    let owners = cpp_field_receiver_type_units(
        ctx.analyzer,
        ctx.support,
        ctx.visibility,
        ctx.file,
        ctx.source,
        ctx.root,
        field,
        receiver,
    );
    let candidates = cpp_member_candidates(ctx, owners, member, arity, arg_types);
    if candidates.is_empty() {
        no_definition(
            "unsupported_cpp_receiver",
            format!("receiver for C++ member `{member}` is not resolved"),
        )
    } else {
        if arity.is_some() {
            cpp_callable_candidates_outcome(candidates)
        } else {
            candidates_outcome(candidates)
        }
    }
}

fn cpp_visible_name_candidates(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    support: &dyn BoundedDefinitionLookup,
    raw_name: &str,
    kind: Option<CppTargetKind>,
    lexical_namespace: Option<&str>,
) -> Vec<CodeUnit> {
    let normalized = raw_name.trim().trim_start_matches("::");
    let namespace_relative = lexical_namespace
        .filter(|namespace| !namespace.is_empty() && normalized.contains("::"))
        .map(|namespace| format!("{namespace}::{normalized}"));

    let mut candidates: Vec<CodeUnit> = if normalized.contains("::") {
        let mut fqns = Vec::new();
        for reference in [Some(normalized), namespace_relative.as_deref()]
            .into_iter()
            .flatten()
        {
            if let Some(kind) = kind {
                fqns.extend(cpp_reference_fqn_candidates(reference, kind));
            } else {
                for candidate_kind in [
                    CppTargetKind::Type,
                    CppTargetKind::Constructor,
                    CppTargetKind::FreeFunction,
                    CppTargetKind::Method,
                    CppTargetKind::GlobalField,
                    CppTargetKind::MemberField,
                ] {
                    fqns.extend(cpp_reference_fqn_candidates(reference, candidate_kind));
                }
            }
        }
        fqns.sort();
        fqns.dedup();
        support
            .fqn_candidates(fqns)
            .into_iter()
            .filter(|unit| visibility.is_physically_visible(file, unit))
            .filter(|unit| {
                let cpp_name = cpp_name_for(unit);
                cpp_name == normalized
                    || namespace_relative
                        .as_deref()
                        .is_some_and(|relative| cpp_name == relative)
            })
            .collect()
    } else {
        visibility
            .visible_identifier_candidates(file, normalized)
            .filter(|unit| unit.identifier() == normalized)
            .cloned()
            .collect()
    };

    if let Some(kind) = kind {
        candidates.retain(|unit| cpp_unit_matches_kind(analyzer, support, unit, kind));
    }
    candidates = candidates
        .into_iter()
        .flat_map(|unit| {
            let mut indexed = support.fqn(&unit.fq_name());
            indexed.retain(|candidate| {
                cpp_callable_definitions_share_identity_evidence(analyzer, &unit, candidate)
            });
            if indexed.is_empty() {
                vec![unit]
            } else {
                indexed
            }
        })
        .collect();
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

/// Cross-file C/C++ callable bodies selected from include evidence are useful
/// targets, but their link-unit identity remains unproven without build graph
/// metadata. Preserve the candidates while making that uncertainty explicit.
fn cpp_callable_candidates_outcome(candidates: Vec<CodeUnit>) -> DefinitionLookupOutcome {
    let mut callable_sources = HashSet::default();
    for candidate in &candidates {
        if candidate.is_callable() {
            callable_sources.insert(candidate.source().clone());
        }
    }
    let link_unit_unproven = callable_sources.len() > 1;
    let mut outcome = candidates_outcome(candidates);
    if link_unit_unproven {
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: CPP_UNPROVEN_LINK_UNIT_DIAGNOSTIC.to_string(),
            message: "the include graph relates this C/C++ declaration and body, but no build graph proves one link unit"
                .to_string(),
        });
    }
    outcome
}

fn cpp_unit_matches_kind(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    unit: &CodeUnit,
    kind: CppTargetKind,
) -> bool {
    match kind {
        CppTargetKind::FreeFunction => unit.is_function() && !cpp_parent_is_class(support, unit),
        CppTargetKind::Type => unit.is_class() || cpp_unit_is_type_alias(analyzer, unit),
        CppTargetKind::GlobalField => {
            unit.is_field() && cpp_is_unqualified_field(analyzer, support, unit)
        }
        CppTargetKind::MemberField => unit.is_field(),
        CppTargetKind::Constructor | CppTargetKind::Method => true,
    }
}

fn cpp_is_non_reference_type_declaration_site(mut node: Node<'_>) -> bool {
    loop {
        if cpp_is_non_reference_declaration_name(node) {
            return true;
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        if matches!(
            parent.kind(),
            "template_type" | "qualified_identifier" | "scoped_type_identifier"
        ) && parent
            .child_by_field_name("name")
            .is_some_and(|name| cpp_same_node(name, node))
        {
            node = parent;
            continue;
        }
        return parent
            .child_by_field_name("name")
            .is_some_and(|name| cpp_same_node(name, node))
            && matches!(
                parent.kind(),
                "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
            )
            && cpp_tag_specifier_declares_name(parent);
    }
}

fn cpp_expand_tagged_type_scope_reference(node: Node<'_>) -> Option<Node<'_>> {
    let qualified = node.parent().filter(|parent| {
        matches!(
            parent.kind(),
            "qualified_identifier" | "scoped_type_identifier"
        ) && parent.child_by_field_name("scope") == Some(node)
    })?;
    let specifier = qualified.parent()?;
    (matches!(
        specifier.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
    ) && specifier.child_by_field_name("name") == Some(qualified)
        && !cpp_tag_specifier_declares_name(specifier))
    .then_some(qualified)
}

fn cpp_is_non_reference_declaration_name(node: Node<'_>) -> bool {
    if cpp_is_out_of_line_destructor_type_name(node) {
        return false;
    }
    cpp_is_declaration_name(node)
        || cpp_is_recovered_template_forward_declaration_name(node)
        || cpp_is_terminal_declarator_name(node)
        || cpp_is_range_for_binding_name(node)
}

fn cpp_is_recovered_template_forward_declaration_name(node: Node<'_>) -> bool {
    let Some(specifier) = node.parent() else {
        return false;
    };
    if !matches!(
        specifier.kind(),
        "class_specifier" | "struct_specifier" | "union_specifier"
    ) || specifier.child_by_field_name("name") != Some(node)
        || specifier.child_by_field_name("body").is_some()
    {
        return false;
    }
    let mut current = specifier.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "type_descriptor"
            | "parameter_declaration"
            | "optional_parameter_declaration"
            | "template_argument_list"
            | "cast_expression" => return false,
            "template_declaration" => return true,
            "declaration" | "field_declaration" | "translation_unit" => return false,
            _ => current = ancestor.parent(),
        }
    }
    false
}

fn cpp_is_out_of_line_destructor_type_name(node: Node<'_>) -> bool {
    let destructor = if node.kind() == "destructor_name" {
        node
    } else {
        let Some(parent) = node.parent() else {
            return false;
        };
        if parent.kind() != "destructor_name" {
            return false;
        }
        parent
    };
    destructor.parent().is_some_and(|qualified| {
        qualified.kind() == "qualified_identifier"
            && qualified.child_by_field_name("name") == Some(destructor)
            && qualified.child_by_field_name("scope").is_some()
    })
}

fn cpp_is_terminal_declarator_name(node: Node<'_>) -> bool {
    if !matches!(
        node.kind(),
        "identifier" | "field_identifier" | "qualified_identifier"
    ) {
        return false;
    }
    let mut current = Some(node);
    while let Some(candidate) = current {
        let Some(parent) = candidate.parent() else {
            break;
        };
        if matches!(
            parent.kind(),
            "init_declarator"
                | "function_declarator"
                | "pointer_declarator"
                | "array_declarator"
                | "attributed_declarator"
                | "reference_declarator"
                | "parenthesized_declarator"
                | "parameter_declaration"
                | "optional_parameter_declaration"
                | "declaration"
                | "field_declaration"
                | "function_definition"
                | "type_definition"
                | "alias_declaration"
        ) && cpp_declares_terminal_name(parent, node)
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "parameter_declaration"
                | "optional_parameter_declaration"
                | "declaration"
                | "field_declaration"
                | "function_definition"
                | "type_definition"
                | "alias_declaration"
                | "translation_unit"
        ) {
            return false;
        }
        current = Some(parent);
    }
    false
}

fn cpp_declares_terminal_name(container: Node<'_>, target: Node<'_>) -> bool {
    let target = cpp_terminal_declarator_name_target(target);
    let mut cursor = container.walk();
    for declarator in container.children_by_field_name("declarator", &mut cursor) {
        if cpp_declarator_name_node(declarator).is_some_and(|name| cpp_same_node(name, target)) {
            return true;
        }
    }
    container
        .child_by_field_name("name")
        .and_then(cpp_declarator_name_node)
        .is_some_and(|name| cpp_same_node(name, target))
}

fn cpp_terminal_declarator_name_target(node: Node<'_>) -> Node<'_> {
    if node.kind() == "qualified_identifier" {
        node.child_by_field_name("name").unwrap_or(node)
    } else {
        node
    }
}

fn cpp_same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.id() == right.id()
        && left.start_byte() == right.start_byte()
        && left.end_byte() == right.end_byte()
}

fn cpp_tag_specifier_declares_name(specifier: Node<'_>) -> bool {
    if specifier.child_by_field_name("body").is_some() {
        return true;
    }
    let mut current = specifier.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "type_descriptor"
            | "parameter_declaration"
            | "optional_parameter_declaration"
            | "template_argument_list"
            | "cast_expression" => return false,
            "declaration" | "field_declaration" => {
                let mut cursor = ancestor.walk();
                return ancestor
                    .children_by_field_name("declarator", &mut cursor)
                    .next()
                    .is_none();
            }
            "translation_unit" => return true,
            _ => current = ancestor.parent(),
        }
    }
    false
}

fn cpp_is_non_reference_preprocessor_token(node: Node<'_>) -> bool {
    cpp_is_non_reference_preprocessor_body_token(node)
        || cpp_is_non_reference_preprocessor_recovery_tail_token(node)
}

fn cpp_is_non_reference_preprocessor_body_token(node: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        let Some(parent) = candidate.parent() else {
            break;
        };
        if matches!(parent.kind(), "preproc_def" | "preproc_function_def") {
            return parent.child_by_field_name("value").is_some_and(|value| {
                value.start_byte() <= node.start_byte() && node.end_byte() <= value.end_byte()
            });
        }
        if matches!(
            parent.kind(),
            "translation_unit" | "function_definition" | "compound_statement"
        ) {
            return false;
        }
        current = Some(parent);
    }
    false
}

fn cpp_is_non_reference_preprocessor_recovery_tail_token(node: Node<'_>) -> bool {
    let Some(top_level) = cpp_translation_unit_child(node) else {
        return false;
    };
    if top_level.kind() != "ERROR" && !cpp_has_error_ancestor_before_translation_unit(node) {
        return false;
    }
    if !cpp_is_recovered_preprocessor_tail_segment(top_level) {
        return false;
    }
    let mut current = Some(top_level);
    while let Some(sibling) = current {
        if sibling.kind() == "preproc_function_def" {
            return sibling.child_by_field_name("value").is_some();
        }
        if !cpp_is_recovered_preprocessor_tail_segment(sibling) {
            return false;
        }
        current = sibling.prev_named_sibling();
    }
    false
}

fn cpp_has_error_ancestor_before_translation_unit(mut node: Node<'_>) -> bool {
    loop {
        let Some(parent) = node.parent() else {
            return false;
        };
        if parent.kind() == "translation_unit" {
            return false;
        }
        if parent.kind() == "ERROR" {
            return true;
        }
        node = parent;
    }
}

fn cpp_is_recovered_preprocessor_tail_segment(node: Node<'_>) -> bool {
    if node.kind() == "ERROR" {
        return true;
    }
    matches!(
        node.kind(),
        "declaration" | "field_declaration" | "expression_statement"
    ) && node.has_error()
}

fn cpp_translation_unit_child(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        let parent = node.parent()?;
        if parent.kind() == "translation_unit" {
            return Some(node);
        }
        node = parent;
    }
}

fn cpp_parent_is_class(support: &dyn BoundedDefinitionLookup, unit: &CodeUnit) -> bool {
    // The unit's owner is a pure segment pop on its own structured `fq()`
    // (`default_parent_fq_name`, shared with `CodeUnitIndex::parent_of`), not a
    // re-guess of where the legacy fqn string's last `.` falls.
    let Some(parent_fqn) = crate::analyzer::default_parent_fq_name(unit) else {
        return false;
    };
    support
        .fqn(&parent_fqn)
        .into_iter()
        .any(|parent| parent.is_class())
}

fn cpp_is_unqualified_field(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    unit: &CodeUnit,
) -> bool {
    if !unit.short_name().contains('.') {
        return true;
    }
    // Same structured owner pop as `cpp_parent_is_class` above.
    let Some(parent_fqn) = crate::analyzer::default_parent_fq_name(unit) else {
        return false;
    };
    support.fqn(&parent_fqn).into_iter().any(|parent| {
        parent
            .signature()
            .is_some_and(cpp_signature_is_unscoped_enum)
            || analyzer
                .signatures(&parent)
                .iter()
                .any(|signature| cpp_signature_is_unscoped_enum(signature))
    })
}

fn cpp_signature_is_unscoped_enum(signature: &str) -> bool {
    let signature = signature.trim_start();
    signature.starts_with("enum ")
        && !signature.starts_with("enum class ")
        && !signature.starts_with("enum struct ")
}

fn cpp_unit_is_type_alias(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    analyzer
        .type_alias_provider()
        .is_some_and(|provider| provider.is_type_alias(unit))
        || unit.signature().is_some_and(cpp_signature_is_type_alias)
}

fn cpp_signature_is_type_alias(signature: &str) -> bool {
    let signature = signature.trim_start();
    signature.starts_with("typedef ")
        || signature.starts_with("using ") && signature.contains('=')
        || signature.starts_with("template ")
            && signature.contains(" using ")
            && signature.contains('=')
}

fn cpp_member_candidates(
    ctx: CppLookupCtx<'_, '_>,
    owners: Vec<CodeUnit>,
    member: &str,
    arity: Option<usize>,
    arg_types: Option<&[Option<CppType>]>,
) -> Vec<CodeUnit> {
    let mut candidates = cpp_direct_member_candidates(ctx.analyzer, ctx.support, &owners, member);
    if candidates.is_empty() {
        let mut seen = HashSet::default();
        candidates = cpp_inherited_member_candidates(ctx, &owners, member, &mut seen);
    }
    candidates = cpp_filter_candidates_by_call(
        candidates,
        arity,
        arg_types,
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
    );
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn cpp_member_candidates_lazy<F>(
    ctx: CppLookupCtx<'_, '_>,
    owners: Vec<CodeUnit>,
    member: &str,
    arity: Option<usize>,
    resolve_arg_types: F,
) -> Vec<CodeUnit>
where
    F: FnOnce() -> Option<Vec<Option<CppType>>>,
{
    let mut candidates = cpp_direct_member_candidates(ctx.analyzer, ctx.support, &owners, member);
    if candidates.is_empty() {
        let mut seen = HashSet::default();
        candidates = cpp_inherited_member_candidates(ctx, &owners, member, &mut seen);
    }
    candidates.retain(CodeUnit::is_callable);
    candidates = cpp_filter_candidates_by_call_lazy(
        candidates,
        arity,
        resolve_arg_types,
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
    );
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn cpp_member_candidates_lazy_with_presence<F>(
    ctx: CppLookupCtx<'_, '_>,
    owners: Vec<CodeUnit>,
    member: &str,
    arity: Option<usize>,
    resolve_arg_types: F,
) -> (Vec<CodeUnit>, bool)
where
    F: FnOnce() -> Option<Vec<Option<CppType>>>,
{
    let mut candidates = cpp_direct_member_candidates(ctx.analyzer, ctx.support, &owners, member);
    if candidates.is_empty() {
        let mut seen = HashSet::default();
        candidates = cpp_inherited_member_candidates(ctx, &owners, member, &mut seen);
    }
    candidates.retain(CodeUnit::is_callable);
    let had_callable = !candidates.is_empty();
    candidates = cpp_filter_candidates_by_call_lazy_strict(
        candidates,
        arity,
        resolve_arg_types,
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
    );
    sort_units(&mut candidates);
    candidates.dedup();
    (candidates, had_callable)
}

fn cpp_filter_candidates_by_call_lazy_strict<F>(
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
    resolve_arg_types: F,
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
) -> Vec<CodeUnit>
where
    F: FnOnce() -> Option<Vec<Option<CppType>>>,
{
    let arity_filtered = cpp_filter_candidates_by_arity_strict(candidates, arity, analyzer);
    if arity_filtered.len() <= 1 {
        return arity_filtered;
    }
    let Some(arg_types) = resolve_arg_types() else {
        return arity_filtered;
    };
    cpp_filter_candidates_by_call_arg_types(arity_filtered, &arg_types, analyzer, visibility, file)
}

fn cpp_direct_member_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owners: &[CodeUnit],
    member: &str,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for owner in owners {
        candidates.extend(
            support
                .fqn(&format!("{}.{}", owner.fq_name(), member))
                .into_iter()
                .filter(|candidate| {
                    candidate.source() == owner.source()
                        || (matches!(
                            cpp_indexed_callable_linkage(analyzer, candidate),
                            Some(crate::analyzer::CallableLinkage::External)
                        ) && cpp_header_body_files_are_related(
                            analyzer,
                            owner.source(),
                            candidate.source(),
                        ))
                }),
        );
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn cpp_inherited_member_candidates(
    ctx: CppLookupCtx<'_, '_>,
    owners: &[CodeUnit],
    member: &str,
    seen: &mut HashSet<String>,
) -> Vec<CodeUnit> {
    let mut bases = Vec::new();
    for owner in owners {
        for base in cpp_direct_base_types(ctx.analyzer, ctx.visibility, ctx.file, owner) {
            if seen.insert(base.fq_name()) {
                bases.push(base);
            }
        }
    }
    if bases.is_empty() {
        return Vec::new();
    }
    let direct = cpp_direct_member_candidates(ctx.analyzer, ctx.support, &bases, member);
    if !direct.is_empty() {
        return direct;
    }
    let mut inherited = cpp_inherited_member_candidates(ctx, &bases, member, seen);
    sort_units(&mut inherited);
    inherited.dedup();
    inherited
}

fn cpp_filter_candidates_by_call(
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
    arg_types: Option<&[Option<CppType>]>,
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
) -> Vec<CodeUnit> {
    let arity_filtered = cpp_filter_candidates_by_arity(candidates, arity, analyzer);
    let Some(arg_types) = arg_types else {
        return arity_filtered;
    };
    cpp_filter_candidates_by_call_arg_types(arity_filtered, arg_types, analyzer, visibility, file)
}

fn cpp_filter_candidates_by_call_lazy<F>(
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
    resolve_arg_types: F,
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
) -> Vec<CodeUnit>
where
    F: FnOnce() -> Option<Vec<Option<CppType>>>,
{
    let arity_filtered = cpp_filter_candidates_by_arity(candidates, arity, analyzer);
    if arity_filtered.len() <= 1 {
        return arity_filtered;
    }
    let Some(arg_types) = resolve_arg_types() else {
        return arity_filtered;
    };
    cpp_filter_candidates_by_call_arg_types(arity_filtered, &arg_types, analyzer, visibility, file)
}

/// Keep qualified-call lookup open when every free-function candidate has a known,
/// non-matching arity. The caller can then resolve the structured owner/member
/// path instead of returning a non-applicable candidate from the conservative
/// arity filter.
fn qualified_call_has_applicable_arity(
    candidates: &[CodeUnit],
    arity: Option<usize>,
    analyzer: &dyn IAnalyzer,
) -> bool {
    let Some(expected) = arity else {
        return true;
    };
    candidates.iter().any(|candidate| {
        cpp_known_callable_arity(analyzer, candidate).is_none_or(|known| known.accepts(expected))
    })
}

fn cpp_filter_candidates_by_call_arg_types(
    candidates: Vec<CodeUnit>,
    arg_types: &[Option<CppType>],
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
) -> Vec<CodeUnit> {
    let shared_arg_types: Vec<_> = arg_types
        .iter()
        .map(|arg| arg.as_ref().map(CppType::as_arg_type))
        .collect();
    cpp_filter_candidates_by_args(
        candidates,
        &shared_arg_types,
        &|name| cpp_resolve_type_unit(analyzer, visibility, file, name),
        &|arg_type, param_type| {
            cpp_type_assignable_to(
                analyzer,
                visibility,
                file,
                arg_type,
                param_type,
                &mut HashSet::default(),
            )
        },
    )
}

fn cpp_filter_candidates_by_arity(
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
    analyzer: &dyn IAnalyzer,
) -> Vec<CodeUnit> {
    let Some(expected) = arity else {
        return candidates;
    };
    let filtered = candidates
        .iter()
        .filter(|unit| {
            unit.is_function()
                && cpp_known_callable_arity(analyzer, unit)
                    .is_none_or(|arity| arity.accepts(expected))
        })
        .cloned()
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        candidates
    } else {
        candidates
            .into_iter()
            .filter(|candidate| {
                filtered.contains(candidate)
                    || filtered.iter().any(|declaration| {
                        cpp_callable_overload_identity_matches(analyzer, declaration, candidate)
                            && cpp_known_callable_arity(analyzer, candidate)
                                .is_none_or(|candidate_arity| candidate_arity.accepts(expected))
                    })
            })
            .collect()
    }
}

fn cpp_callable_overload_identity_matches(
    analyzer: &dyn IAnalyzer,
    left: &CodeUnit,
    right: &CodeUnit,
) -> bool {
    left.fq_name() == right.fq_name()
        && cpp_callable_definitions_share_identity_evidence(analyzer, left, right)
        && left.signature().and_then(cpp_signature_param_types)
            == right.signature().and_then(cpp_signature_param_types)
}

fn cpp_filter_candidates_by_arity_strict(
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
    analyzer: &dyn IAnalyzer,
) -> Vec<CodeUnit> {
    let Some(expected) = arity else {
        return candidates;
    };
    candidates
        .into_iter()
        .filter(|unit| {
            unit.is_function()
                && cpp_known_callable_arity(analyzer, unit)
                    .is_none_or(|arity| arity.accepts(expected))
        })
        .collect()
}

fn cpp_known_callable_arity(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
) -> Option<crate::analyzer::CallableArity> {
    if let Some(arity) = analyzer
        .signature_metadata(unit)
        .into_iter()
        .find_map(|metadata| metadata.callable_arity())
    {
        return Some(arity);
    }
    let signature = unit.signature()?;
    let open = signature.find('(')?;
    signature[open + 1..].find(')')?;
    Some(crate::analyzer::CallableArity::exact(cpp_signature_arity(
        Some(signature),
    )))
}

fn cpp_type_assignable_to(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    arg_type: &CodeUnit,
    param_type: &CodeUnit,
    seen: &mut HashSet<String>,
) -> bool {
    if arg_type.fq_name() == param_type.fq_name() {
        return true;
    }
    if !seen.insert(arg_type.fq_name()) {
        return false;
    }
    cpp_direct_base_types(analyzer, visibility, file, arg_type)
        .into_iter()
        .any(|base| {
            base.fq_name() == param_type.fq_name()
                || cpp_type_assignable_to(analyzer, visibility, file, &base, param_type, seen)
        })
}

fn cpp_direct_base_types(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    unit: &CodeUnit,
) -> Vec<CodeUnit> {
    let signature = unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.get_source(unit, false));
    let Some(signature) = signature else {
        return Vec::new();
    };
    let Some((_, bases)) = signature.split_once(':') else {
        return Vec::new();
    };
    let bases = bases.split('{').next().unwrap_or(bases);
    // Base-class specifiers are frequently written relative to the enclosing namespace
    // (`struct Derived : PCM::Base` inside `namespace Outer`, meaning `Outer::PCM::Base`).
    // Resolve them the same namespace-relative way `cpp_resolve_type_unit_in_namespace`
    // already resolves other qualified type references in this file (issue #939) --
    // without this, a relatively-qualified base silently fails to resolve and every
    // inherited-member lookup through it (bare calls here, and overload-assignability
    // checks in `cpp_type_assignable_to`) fails forward.
    let lexical_namespace = (!unit.package_name().is_empty()).then(|| unit.package_name());
    cpp_split_top_level_commas(bases)
        .filter_map(|base| {
            cpp_resolve_type_unit_in_namespace(
                analyzer,
                visibility,
                file,
                &cpp_base_type_text(base),
                lexical_namespace,
            )
        })
        .collect()
}

fn cpp_base_type_text(base: &str) -> String {
    let filtered = base
        .split_whitespace()
        .filter(|token| !matches!(*token, "public" | "private" | "protected" | "virtual"))
        .collect::<Vec<_>>()
        .join(" ");
    normalize_cpp_type_text(&filtered)
}

/// A C++ value type paired with its pointer indirection depth: 0 for a value or
/// reference, 1 for `T*`, 2 for `T**`, and so on. References bind from values, so
/// they contribute depth 0; only `*` levels must agree between an argument and a
/// parameter for overload matching.
#[derive(Clone, PartialEq, Eq, Hash)]
struct CppType {
    name: String,
    unit: Option<CodeUnit>,
    indirection: i32,
    pointee_const: bool,
    alias_unit: Option<CodeUnit>,
}

impl CppType {
    fn from_text(
        analyzer: &dyn IAnalyzer,
        visibility: &CppVisibilityIndex,
        file: &ProjectFile,
        type_text: &str,
        indirection: i32,
    ) -> Self {
        let name = normalize_cpp_type_name(type_text);
        Self {
            name: name.clone(),
            unit: cpp_resolve_type_unit(analyzer, visibility, file, &name),
            indirection,
            pointee_const: false,
            alias_unit: cpp_resolve_type_alias_unit(analyzer, visibility, file, &name),
        }
    }

    fn from_unit(unit: CodeUnit, indirection: i32) -> Self {
        Self {
            name: cpp_name_for(&unit),
            unit: Some(unit),
            indirection,
            pointee_const: false,
            alias_unit: None,
        }
    }

    fn as_arg_type(&self) -> CppArgType {
        CppArgType {
            name: self.name.clone(),
            unit: self.unit.clone(),
            indirection: self.indirection,
            pointee_const: self.pointee_const,
        }
    }
}

/// Pointer depth contributed by a declarator: one per `pointer_declarator`
/// wrapping the name. `reference_declarator` contributes nothing.
fn cpp_declarator_pointer_depth(declarator: Node<'_>) -> i32 {
    let mut depth = 0;
    let mut current = declarator;
    loop {
        if current.kind() == "pointer_declarator" {
            depth += 1;
        }
        match current.child_by_field_name("declarator") {
            Some(inner) => current = inner,
            None => return depth,
        }
    }
}

/// Indirection change of a `pointer_expression`: `&x` adds a pointer level, `*x`
/// removes one. `None` for any other unary operator sharing this node kind.
fn cpp_pointer_expression_delta(node: Node<'_>) -> Option<i32> {
    match node.child_by_field_name("operator")?.kind() {
        "&" => Some(1),
        "*" => Some(-1),
        _ => None,
    }
}

fn cpp_call_argument_types(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
) -> Option<Vec<Option<CppType>>> {
    let args = call
        .child_by_field_name("arguments")
        .or_else(|| call.child_by_field_name("parameters"))
        .or_else(|| call.child_by_field_name("value"))?;
    Some(
        cpp_argument_children(args)
            .map(|arg| cpp_expression_type(analyzer, support, visibility, file, source, root, arg))
            .collect(),
    )
}

fn cpp_expression_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> Option<CppType> {
    match node.kind() {
        "number_literal" | "true" | "false" | "char_literal" | "string_literal"
        | "unary_expression" => cpp_literal_arg_type(node, source).map(|literal| CppType {
            unit: cpp_resolve_type_unit(analyzer, visibility, file, &literal.name),
            alias_unit: cpp_resolve_type_alias_unit(analyzer, visibility, file, &literal.name),
            name: literal.name,
            indirection: literal.indirection,
            pointee_const: literal.pointee_const,
        }),
        "identifier" => {
            let name = cpp_node_text(node, source);
            let ctx = CppLookupCtx {
                analyzer,
                support,
                file,
                visibility,
                source,
                root,
                class_ranges: None,
            };
            let bindings = cpp_bindings_before(ctx, root, node.start_byte());
            first_precise(&bindings, name)
        }
        "field_expression" => {
            cpp_field_expression_type(analyzer, support, visibility, file, source, root, node)
        }
        "new_expression" | "call_expression" => cpp_infer_type_from_value(
            analyzer,
            support,
            visibility,
            file,
            source,
            Some(root),
            node,
        ),
        "parenthesized_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .and_then(|inner| {
                cpp_expression_type(analyzer, support, visibility, file, source, root, inner)
            }),
        "pointer_expression" => {
            let delta = cpp_pointer_expression_delta(node)?;
            let inner = node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))?;
            let mut inner_type =
                cpp_expression_type(analyzer, support, visibility, file, source, root, inner)?;
            inner_type.indirection += delta;
            Some(inner_type)
        }
        _ => None,
    }
}

fn cpp_field_expression_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    field: Node<'_>,
) -> Option<CppType> {
    let member = field
        .child_by_field_name("field")
        .map(|field| cpp_node_text(field, source))?;
    let receiver = field
        .child_by_field_name("argument")
        .or_else(|| field.named_child(0))?;
    let owners = cpp_field_receiver_type_units(
        analyzer, support, visibility, file, source, root, field, receiver,
    );
    let candidates = cpp_member_candidates(
        CppLookupCtx {
            analyzer,
            support,
            file,
            visibility,
            source,
            root,
            class_ranges: None,
        },
        owners,
        member,
        None,
        None,
    );
    candidates
        .into_iter()
        .filter(|unit| unit.is_field())
        .find_map(|unit| cpp_field_declared_type(analyzer, visibility, file, &unit))
}

fn cpp_field_declared_type(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    field: &CodeUnit,
) -> Option<CppType> {
    let dispatch = CppDispatch::new(analyzer);
    let (name, unit, indirection) =
        cpp_field_declared_type_binding(dispatch.source(), visibility, file, field)?;
    Some(CppType {
        alias_unit: cpp_resolve_type_alias_unit(analyzer, visibility, file, &name),
        name,
        unit,
        indirection,
        pointee_const: false,
    })
}

fn cpp_receiver_type_units(
    ctx: CppLookupCtx<'_, '_>,
    receiver: Node<'_>,
    unwrap_template_alias: bool,
) -> Vec<CodeUnit> {
    match receiver.kind() {
        "identifier" => {
            let name = cpp_node_text(receiver, ctx.source);
            let bindings = cpp_bindings_before(ctx, ctx.root, receiver.start_byte());
            if let Some(cpp_type) = first_precise(&bindings, name) {
                return cpp_receiver_unit_for_access(ctx, cpp_type, unwrap_template_alias)
                    .into_iter()
                    .collect();
            }
            if bindings.is_shadowed(name) {
                Vec::new()
            } else if let Some(cpp_type) = cpp_enclosing_member_field_type(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                ctx.root,
                receiver,
                name,
            ) {
                cpp_receiver_unit_for_access(ctx, cpp_type, unwrap_template_alias)
                    .into_iter()
                    .collect()
            } else {
                ctx.visibility
                    .resolve_type(ctx.file, name)
                    .into_iter()
                    .collect()
            }
        }
        "this" => cpp_enclosing_class(
            ctx.analyzer,
            ctx.support,
            ctx.visibility,
            ctx.file,
            ctx.source,
            ctx.root,
            receiver.start_byte(),
        )
        .into_iter()
        .collect(),
        "field_expression" => cpp_field_expression_type(
            ctx.analyzer,
            ctx.support,
            ctx.visibility,
            ctx.file,
            ctx.source,
            ctx.root,
            receiver,
        )
        .and_then(|cpp_type| cpp_type.unit)
        .into_iter()
        .collect(),
        // `Foo().member` / `(new Foo())->member` — a temporary-construction or
        // call receiver is typed by the constructed class or the call's return.
        "call_expression" | "new_expression" => cpp_expression_type(
            ctx.analyzer,
            ctx.support,
            ctx.visibility,
            ctx.file,
            ctx.source,
            ctx.root,
            receiver,
        )
        .and_then(|cpp_type| cpp_type.unit)
        .into_iter()
        .collect(),
        "parenthesized_expression" | "pointer_expression" => receiver
            .child_by_field_name("argument")
            .or_else(|| receiver.named_child(0))
            .map(|inner| cpp_receiver_type_units(ctx, inner, unwrap_template_alias))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn cpp_field_receiver_type_units(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    field: Node<'_>,
    receiver: Node<'_>,
) -> Vec<CodeUnit> {
    let ctx = CppLookupCtx {
        analyzer,
        support,
        file,
        visibility,
        source,
        root,
        class_ranges: None,
    };
    cpp_receiver_type_units(
        ctx,
        receiver,
        cpp_field_expression_uses_arrow(field, source),
    )
}

fn cpp_receiver_unit_for_access(
    ctx: CppLookupCtx<'_, '_>,
    cpp_type: CppType,
    unwrap_template_alias: bool,
) -> Option<CodeUnit> {
    if unwrap_template_alias
        && let Some(alias) = cpp_type.alias_unit.as_ref()
        && let Some(target) = cpp_alias_arrow_target_unit(ctx, alias)
    {
        return Some(target);
    }
    cpp_type.unit
}

fn cpp_field_expression_uses_arrow(field: Node<'_>, source: &str) -> bool {
    let Some(receiver) = field
        .child_by_field_name("argument")
        .or_else(|| field.named_child(0))
    else {
        return false;
    };
    let Some(name) = field.child_by_field_name("field") else {
        return false;
    };
    source
        .get(receiver.end_byte()..name.start_byte())
        .is_some_and(|between| between.contains("->"))
}

fn cpp_enclosing_class(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    byte: usize,
) -> Option<CodeUnit> {
    let class_ranges = ClassRangeIndex::build(analyzer, file);
    cpp_enclosing_class_with_ranges(
        analyzer,
        support,
        visibility,
        file,
        source,
        root,
        byte,
        &class_ranges,
    )
}

fn cpp_enclosing_class_member_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    node: Node<'_>,
    class_ranges: Option<&ClassRangeIndex>,
    name: &str,
) -> Vec<CodeUnit> {
    let dispatch = CppDispatch::new(analyzer);
    let candidates_for_owner = |owner: &CodeUnit| {
        cpp_direct_type_member_candidates(analyzer, support, owner, name)
            .into_iter()
            .filter(|candidate| {
                !cpp_type_alias_declaration_contains_node(analyzer, candidate, node)
                    && visibility.external_type_candidate_visible_in_context(
                        dispatch.source(),
                        file,
                        candidate,
                        node,
                    )
            })
            .collect::<Vec<_>>()
    };
    let Some(ranges) = class_ranges else {
        return Vec::new();
    };
    let mut owner = ranges.enclosing_unit(node.start_byte()).cloned();
    while let Some(current) = owner {
        let candidates = candidates_for_owner(&current);
        if !candidates.is_empty() {
            return candidates;
        }
        owner = analyzer.parent_of(&current).filter(CodeUnit::is_class);
    }
    Vec::new()
}

#[allow(clippy::too_many_arguments)]
fn cpp_enclosing_class_with_ranges(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    byte: usize,
    class_ranges: &ClassRangeIndex,
) -> Option<CodeUnit> {
    if let Some(fqn) = class_ranges.enclosing(byte) {
        let candidates = support
            .fqn(fqn)
            .into_iter()
            .filter(CodeUnit::is_class)
            .filter(|candidate| {
                visibility.external_type_declaration_visible_at(file, candidate, byte)
            })
            .collect::<Vec<_>>();
        let local = candidates
            .iter()
            .filter(|candidate| candidate.source() == file)
            .cloned()
            .collect::<Vec<_>>();
        if let Some(owner) = cpp_choose_canonical_type(analyzer, local) {
            return Some(owner);
        }
        if let Some(owner) = cpp_choose_canonical_type(analyzer, candidates) {
            return Some(owner);
        }
    }
    if let Some(owner) =
        cpp_out_of_line_function_owner(analyzer, support, visibility, file, source, root, byte)
    {
        return Some(owner);
    }

    let line_starts = compute_line_starts(source);
    let line = find_line_index_for_offset(&line_starts, byte) + 1;
    let range = Range {
        start_byte: byte,
        end_byte: byte.saturating_add(1),
        start_line: line,
        end_line: line,
    };
    let enclosing = analyzer.enclosing_code_unit(file, &range)?;
    // Structured owner pop on `enclosing`'s own `fq()` (shared with
    // `CodeUnitIndex::parent_of`), not a re-split of its rendered fqn string.
    let owner_fqn = crate::analyzer::default_parent_fq_name(&enclosing)?;
    support
        .fqn(&owner_fqn)
        .into_iter()
        .find(|unit| unit.is_class())
}

fn cpp_out_of_line_function_owner(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    byte: usize,
) -> Option<CodeUnit> {
    let selected = smallest_named_node_covering(root, byte, byte)?;
    let mut node = selected;
    loop {
        if node.kind() == "function_definition" {
            let declarator = node.child_by_field_name("declarator")?;
            if declarator.start_byte() <= selected.start_byte()
                && selected.end_byte() <= declarator.end_byte()
                && !cpp_declarator_name_path_contains(declarator, selected)
            {
                return None;
            }
            return cpp_function_definition_owner(
                analyzer, support, visibility, file, source, node, byte,
            );
        }
        node = node.parent()?;
    }
}

#[allow(clippy::too_many_arguments)]
fn cpp_function_definition_owner(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
    byte: usize,
) -> Option<CodeUnit> {
    let declarator = function.child_by_field_name("declarator")?;
    let qualified = cpp_declarator_qualified_name_node(declarator)?;
    let mut owner_parts = cpp_type_name_components(qualified, source)?;
    owner_parts.pop()?;
    if owner_parts.is_empty() {
        return None;
    }
    let owner = owner_parts.join("::");
    let globally_qualified = is_globally_qualified_cpp_name(qualified);
    cpp_resolve_owner_type_in_lexical_namespace(
        analyzer,
        support,
        visibility,
        file,
        source,
        function,
        &owner,
        globally_qualified,
        byte,
    )
}

/// Recover the namespace scope of an out-of-line function definition.
///
/// A qualified namespace owner is not a type owner. Therefore, the normal
/// lexical-scope resolver cannot resolve it as a class or alias. Use the
/// indexed module declaration to distinguish this case from an unresolved
/// class owner, then return the structured namespace components for ordinary
/// unqualified lookup inside the function body.
fn cpp_out_of_line_namespace_scope(
    support: &dyn BoundedDefinitionLookup,
    source: &str,
    node: Node<'_>,
) -> Option<Vec<String>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "function_definition"
            && let Some(scope) = cpp_namespace_scope_for_function(support, source, candidate)
        {
            return Some(scope);
        }
        current = candidate.parent();
    }
    None
}

fn cpp_namespace_scope_for_function(
    support: &dyn BoundedDefinitionLookup,
    source: &str,
    function: Node<'_>,
) -> Option<Vec<String>> {
    let declarator = function.child_by_field_name("declarator")?;
    let qualified = cpp_declarator_qualified_name_node(declarator)?;
    let mut owner_parts = cpp_type_name_components(qualified, source)?;
    owner_parts.pop()?;
    if owner_parts.is_empty() {
        return None;
    }
    // C++ module FQNs use dot-separated package components in the indexed
    // declaration key. The parts come from the tree-sitter qualified name.
    let owner_fqn = owner_parts.join(".");
    support
        .fqn(&owner_fqn)
        .into_iter()
        .any(|unit| unit.is_module())
        .then_some(owner_parts)
}

fn cpp_declarator_qualified_name_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "qualified_identifier" | "scoped_identifier" => Some(node),
        _ => node
            .child_by_field_name("declarator")
            .and_then(cpp_declarator_qualified_name_node),
    }
}

#[allow(clippy::too_many_arguments)]
fn cpp_resolve_owner_type_in_lexical_namespace(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    owner: &str,
    globally_qualified: bool,
    byte: usize,
) -> Option<CodeUnit> {
    let dispatch = CppDispatch::new(analyzer);
    // Keep the complete owner path during lookup.  `resolve_type(file, name)`
    // is intentionally terminal-name based for compatibility with older
    // callers; it can therefore select an unrelated nested type when the
    // owner is a global class with the same short name (for example global
    // `ValueType` versus `ValueFlow::Value::ValueType`).
    let owner_components = crate::analyzer::symbol_lookup::parse_symbol_path(Language::Cpp, owner);
    if owner_components.is_empty() {
        return None;
    }
    let lexical_scope = cpp_lexical_namespace(node, source)
        .map(|namespace| {
            crate::analyzer::symbol_lookup::parse_symbol_path(Language::Cpp, &namespace)
        })
        .unwrap_or_default();
    let resolved = match visibility.resolve_type_components_lexically_for_forward(
        dispatch.source(),
        file,
        &owner_components,
        globally_qualified,
        &lexical_scope,
    ) {
        CppLexicalTypeResolution::Resolved { unit, .. } => Some(unit),
        CppLexicalTypeResolution::Ambiguous | CppLexicalTypeResolution::Missing => None,
    }
    .or_else(|| {
        // A `using namespace` can make an owner visible even when the
        // structural namespace walk has no matching tier.  Retry only with
        // exact structured paths; never fall back to a terminal-name lookup.
        let names = if globally_qualified {
            vec![owner.to_string()]
        } else {
            cpp_lexical_namespace(node, source)
                .into_iter()
                .flat_map(|namespace| cpp_namespace_relative_names(&namespace, owner))
                .chain(std::iter::once(owner.to_string()))
                .collect::<Vec<_>>()
        };
        names.into_iter().find_map(|name| {
            let components = crate::analyzer::symbol_lookup::parse_symbol_path(
                Language::Cpp,
                name.trim_start_matches("::"),
            );
            if components.is_empty() {
                return None;
            }
            let expected = components.join("::");
            visibility
                .visible_identifier_candidates(file, components.last()?)
                .filter(|candidate| candidate.is_class() && cpp_name_for(candidate) == expected)
                .find(|candidate| {
                    visibility.external_type_declaration_visible_at(file, candidate, byte)
                })
                .cloned()
        })
    })
    .or_else(|| {
        // A macro namespace wrapper can hide the namespace that contains an
        // out-of-line member from the parser-derived lexical scope. Recover
        // the owner from the indexed callable's direct parent. Match the full
        // owner path, not only its terminal name, so an unrelated nested type
        // cannot win (for example `Cord::CharIterator` for `btree<P>::iterator`).
        let declarator = node.child_by_field_name("declarator")?;
        let qualified = cpp_declarator_qualified_name_node(declarator)?;
        let mut function_components = cpp_type_name_components(qualified, source)?;
        let function_name = function_components.pop()?;
        let lexical_scope = crate::analyzer::symbol_lookup::parse_symbol_path(
            Language::Cpp,
            &cpp_lexical_namespace(node, source).unwrap_or_default(),
        );
        let mut owners = support
            .file_identifier(file, &function_name)
            .into_iter()
            .filter(|candidate| candidate.is_function())
            .filter_map(|candidate| analyzer.parent_of(&candidate))
            .filter(|candidate| {
                if !candidate.is_class()
                    || !visibility.external_type_declaration_visible_at(file, candidate, byte)
                {
                    return false;
                }
                let candidate_components = canonical_cpp_scope_components(candidate);
                candidate_components.ends_with(&owner_components)
                    && (lexical_scope.is_empty()
                        || candidate_components.starts_with(&lexical_scope))
            })
            .collect::<Vec<_>>();
        sort_units(&mut owners);
        owners.dedup();
        cpp_choose_canonical_type(analyzer, owners)
    })?;
    let candidates = support
        .fqn(&resolved.fq_name())
        .into_iter()
        .filter(CodeUnit::is_class)
        .filter(|candidate| visibility.external_type_declaration_visible_at(file, candidate, byte))
        .collect::<Vec<_>>();
    cpp_choose_canonical_type(analyzer, candidates).or(Some(resolved))
}

#[allow(clippy::too_many_arguments)]
fn cpp_enclosing_member_field_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
    name: &str,
) -> Option<CppType> {
    let owner = cpp_enclosing_class(
        analyzer,
        support,
        visibility,
        file,
        source,
        root,
        node.start_byte(),
    )?;
    let ctx = CppLookupCtx {
        analyzer,
        support,
        file,
        visibility,
        source,
        root,
        class_ranges: None,
    };
    cpp_member_candidates(ctx, vec![owner], name, None, None)
        .into_iter()
        .filter(|unit| unit.is_field())
        .find_map(|unit| cpp_field_declared_type(analyzer, visibility, file, &unit))
}

const CPP_SCOPE_NODES: &[&str] = &[
    "compound_statement",
    "function_definition",
    "lambda_expression",
    "for_range_loop",
    "for_statement",
    "while_statement",
    "if_statement",
];

fn cpp_bindings_before(
    ctx: CppLookupCtx<'_, '_>,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CppType> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    cpp_seed_active_path(ctx, root, cutoff_start, &mut bindings);
    bindings
}

fn cpp_local_bindings_before(
    ctx: CppLookupCtx<'_, '_>,
    node: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CppType> {
    let Some(local_root) = cpp_enclosing_local_scope(node) else {
        return LocalInferenceEngine::new(LocalInferenceConfig::default());
    };
    cpp_bindings_before(ctx, local_root, cutoff_start)
}

fn cpp_enclosing_local_scope(mut node: Node<'_>) -> Option<Node<'_>> {
    let mut fallback = None;
    while let Some(parent) = node.parent() {
        // Seed from the callable scope when one is available, rather than
        // starting at the innermost compound statement.  C++ declarations in
        // a control-statement initializer (for example `if (auto value =
        // make_value())`) are visible in that statement's body, while the
        // initializer itself is a sibling of the body's compound node.  A
        // body-only walk therefore misses the initializer and can incorrectly
        // fall through to a same-named global.  Walking the function node also
        // retains parameters and declarations from earlier statements, with
        // the normal nested scope enter/exit handling preserving their actual
        // visibility.
        if matches!(parent.kind(), "function_definition" | "lambda_expression") {
            // A malformed top-level wrapper can contain a real recovered
            // function declaration in its body.  The wrapper's declarator is
            // not callable, so keep the narrower recovered declaration as
            // the local scope instead of letting the wrapper swallow it.
            if parent.kind() == "function_definition"
                && cpp_malformed_wrapper_function_definition(parent)
                && fallback.is_some()
            {
                return fallback;
            }
            return Some(parent);
        }
        if fallback.is_none() && cpp_local_scope_node(parent) {
            fallback = Some(parent);
        }
        if fallback.is_none() && parent.kind() == "compound_statement" {
            fallback = Some(parent);
        }
        node = parent;
    }
    fallback
}

fn cpp_seed_active_path(
    ctx: CppLookupCtx<'_, '_>,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    if node.start_byte() >= cutoff_start {
        return;
    }
    let enters_scope = cpp_local_scope_node(node);
    if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
        return;
    }
    if enters_scope {
        bindings.enter_scope();
    }
    match node.kind() {
        "parameter_declaration" | "optional_parameter_declaration"
            if node.end_byte() <= cutoff_start =>
        {
            cpp_seed_typed_binding(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                node,
                bindings,
            )
        }
        "for_range_loop" if node.start_byte() < cutoff_start => {
            cpp_seed_for_range_binding(ctx, node, cutoff_start, bindings)
        }
        "declaration" | "field_declaration" if node.start_byte() < cutoff_start => {
            cpp_seed_variable_declaration(ctx, node, cutoff_start, bindings)
        }
        "expression_statement" if node.end_byte() <= cutoff_start => {
            cpp_seed_recovered_statement_declaration(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                node,
                bindings,
            )
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        cpp_seed_active_path(ctx, child, cutoff_start, bindings);
    }
}

fn cpp_local_scope_node(node: Node<'_>) -> bool {
    CPP_SCOPE_NODES.contains(&node.kind()) || cpp_recovered_function_declaration_scope(node)
}

fn cpp_recovered_function_declaration_scope(node: Node<'_>) -> bool {
    // An opaque macro wrapper can make a real member function parse as a
    // declaration whose recovered body is a direct trailing ERROR child.
    if node.kind() != "declaration" || !node.has_error() {
        return false;
    }
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return false;
    };
    if declarator.kind() != "function_declarator" {
        return false;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == "ERROR" && child.start_byte() >= declarator.end_byte())
}

fn cpp_malformed_wrapper_function_definition(node: Node<'_>) -> bool {
    node.has_error()
        && node
            .child_by_field_name("declarator")
            .is_some_and(|declarator| {
                declarator.kind() != "function_declarator"
                    && !subtree_contains(declarator, |candidate| {
                        candidate.kind() == "function_declarator"
                    })
            })
}

fn cpp_seed_typed_binding(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_variable_name(declarator, source) else {
        return;
    };
    let type_text =
        cpp_declaration_type_text_for_declarator(visibility, file, node, declarator, source)
            .or_else(|| cpp_declaration_type_text(visibility, file, node, source));
    let type_node = node
        .child_by_field_name("type")
        .or_else(|| cpp_first_type_child(node));
    cpp_seed_binding(
        analyzer,
        support,
        visibility,
        file,
        source,
        cpp_lexical_namespace(node, source).as_deref(),
        &name,
        type_text.as_deref(),
        type_node,
        cpp_declarator_pointer_depth(declarator),
        None,
        None,
        bindings,
    );
}

fn cpp_seed_for_range_binding(
    ctx: CppLookupCtx<'_, '_>,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    if node
        .child_by_field_name("body")
        .is_none_or(|body| body.start_byte() > cutoff_start)
    {
        return;
    }
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_variable_name(declarator, ctx.source) else {
        return;
    };
    let type_text = node
        .child_by_field_name("type")
        .or_else(|| cpp_first_type_child(node))
        .map(|type_node| cpp_normalize_declared_type_text(cpp_node_text(type_node, ctx.source)));
    let type_node = node
        .child_by_field_name("type")
        .or_else(|| cpp_first_type_child(node));
    cpp_seed_binding(
        ctx.analyzer,
        ctx.support,
        ctx.visibility,
        ctx.file,
        ctx.source,
        cpp_lexical_namespace(node, ctx.source).as_deref(),
        &name,
        type_text.as_deref(),
        type_node,
        cpp_declarator_pointer_depth(declarator),
        None,
        None,
        bindings,
    );
}

fn cpp_seed_variable_declaration(
    ctx: CppLookupCtx<'_, '_>,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    let declaration_type_text =
        cpp_declaration_type_text(ctx.visibility, ctx.file, node, ctx.source);
    let declaration_type_node = node
        .child_by_field_name("type")
        .or_else(|| cpp_first_type_child(node));
    let mut seeded_structured_declarator = false;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let declarator = if child.kind() == "init_declarator" {
            child.child_by_field_name("declarator")
        } else if cpp_is_declarator_node(child) {
            Some(child)
        } else {
            None
        };
        let Some(declarator) = declarator else {
            continue;
        };
        if declarator.start_byte() >= cutoff_start {
            continue;
        }
        let type_text = cpp_declaration_type_text_for_declarator(
            ctx.visibility,
            ctx.file,
            node,
            declarator,
            ctx.source,
        )
        .or_else(|| declaration_type_text.clone());
        if declarator.kind() == "function_declarator"
            && !cpp_constructor_style_local_declaration(
                ctx.visibility,
                ctx.file,
                ctx.source,
                declarator,
                type_text.as_deref(),
                bindings,
            )
        {
            if cpp_enclosing_local_scope(node).is_some()
                && let Some(name) = extract_variable_name(declarator, ctx.source)
            {
                bindings.declare_shadow(name);
            }
            continue;
        }
        if let Some(name) = extract_variable_name(declarator, ctx.source) {
            seeded_structured_declarator = true;
            let value = child
                .child_by_field_name("value")
                .filter(|value| value.end_byte() <= cutoff_start);
            cpp_seed_binding(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                cpp_lexical_namespace(node, ctx.source).as_deref(),
                &name,
                type_text.as_deref(),
                declaration_type_node,
                cpp_declarator_pointer_depth(declarator),
                Some(ctx.root),
                value,
                bindings,
            );
        }
    }
    // An object-like annotation macro is parsed as the declaration's type,
    // the real type as a structured declarator, and the actual variable tail
    // as a direct ERROR child. Preserve recovery for that explicit AST gap,
    // while ordinary fully structured declarations must not be reseeded by
    // the less precise statement recovery path.
    let has_direct_declarator_error = (0..node.named_child_count()).any(|index| {
        node.named_child(index)
            .is_some_and(|child| child.kind() == "ERROR")
    });
    if (!seeded_structured_declarator || has_direct_declarator_error)
        && node.end_byte() <= cutoff_start
    {
        cpp_seed_recovered_statement_declaration(
            ctx.analyzer,
            ctx.support,
            ctx.visibility,
            ctx.file,
            ctx.source,
            node,
            bindings,
        );
    }
}

fn cpp_seed_recovered_statement_declaration(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    for (name, type_text, pointer_depth) in
        cpp_recover_macro_decorated_statement_declarations(visibility, file, node, source)
    {
        cpp_seed_binding(
            analyzer,
            support,
            visibility,
            file,
            source,
            cpp_lexical_namespace(node, source).as_deref(),
            &name,
            Some(&type_text),
            None,
            pointer_depth,
            None,
            None,
            bindings,
        );
    }
}

fn cpp_recover_macro_decorated_statement_declarations(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    node: Node<'_>,
    source: &str,
) -> Vec<(String, String, i32)> {
    let statement = cpp_node_text(node, source)
        .trim()
        .trim_end_matches(';')
        .trim();
    if statement.is_empty()
        || statement.contains(['=', '{', '}'])
        || statement.starts_with("return ")
    {
        return Vec::new();
    }
    let declarators: Vec<_> = cpp_split_top_level_commas(statement).collect();
    let Some(first) = declarators.first().map(|part| part.trim()) else {
        return Vec::new();
    };
    let Some((first_name, first_start, first_end)) = cpp_last_identifier_span(first) else {
        return Vec::new();
    };
    if !first[first_end..]
        .trim()
        .chars()
        .all(|ch| matches!(ch, '*' | '&'))
    {
        return Vec::new();
    }
    let prefix = first[..first_start].trim();
    if prefix.is_empty() {
        return Vec::new();
    }
    let shared_prefix = prefix.trim_end_matches(['*', '&', ' ', '\t', '\n', '\r']);
    let first_declarator_prefix = prefix[shared_prefix.len()..].trim();
    if first_declarator_prefix
        .chars()
        .any(|ch| !matches!(ch, '*' | '&' | ' ' | '\t' | '\n' | '\r'))
    {
        return Vec::new();
    }
    let normalized = cpp_normalize_declared_type_text(shared_prefix);
    let Some(type_text) = cpp_resolvable_declared_type_suffix(visibility, file, &normalized) else {
        return Vec::new();
    };
    let mut recovered = vec![(
        first_name.to_string(),
        type_text.clone(),
        cpp_type_text_pointer_depth(first_declarator_prefix),
    )];

    for declarator in declarators.iter().skip(1).map(|part| part.trim()) {
        let Some((name, start, end)) = cpp_last_identifier_span(declarator) else {
            continue;
        };
        if !declarator[end..]
            .trim()
            .chars()
            .all(|ch| matches!(ch, '*' | '&'))
        {
            continue;
        }
        let declarator_prefix = declarator[..start].trim();
        if declarator_prefix
            .chars()
            .any(|ch| !matches!(ch, '*' | '&' | ' ' | '\t' | '\n' | '\r'))
        {
            continue;
        }
        recovered.push((
            name.to_string(),
            type_text.clone(),
            cpp_type_text_pointer_depth(declarator_prefix),
        ));
    }

    recovered
}

fn cpp_last_identifier_span(text: &str) -> Option<(&str, usize, usize)> {
    let (end_start, end_ch) = text
        .char_indices()
        .rev()
        .find(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_')?;
    let end = end_start + end_ch.len_utf8();
    let start = text[..end]
        .char_indices()
        .rev()
        .find(|(_, ch)| !(ch.is_ascii_alphanumeric() || *ch == '_'))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    let ident = &text[start..end];
    ident
        .chars()
        .next()
        .filter(|ch| ch.is_ascii_alphabetic() || *ch == '_')?;
    Some((ident, start, end))
}

fn cpp_declaration_type_text(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    cpp_declaration_prefix_before_first_declarator(node, source)
        .or_else(|| {
            node.child_by_field_name("type")
                .or_else(|| cpp_first_type_child(node))
                .map(|type_node| cpp_node_text(type_node, source).to_string())
        })
        .map(|text| cpp_normalize_declared_type_for_visibility(visibility, file, &text))
        .filter(|text| !text.is_empty())
}

fn cpp_declaration_type_text_for_declarator(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    declaration: Node<'_>,
    declarator: Node<'_>,
    source: &str,
) -> Option<String> {
    let name = cpp_declarator_name_node(declarator)?;
    let prefix = source
        .get(declaration.start_byte()..name.start_byte())?
        .trim();
    if prefix.contains(',') {
        return cpp_declaration_type_text(visibility, file, declaration, source);
    }
    (!prefix.is_empty())
        .then(|| cpp_normalize_declared_type_for_visibility(visibility, file, prefix))
        .filter(|text| !text.is_empty())
}

fn cpp_declarator_name_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" | "field_identifier" => Some(node),
        "abstract_array_declarator"
        | "abstract_function_declarator"
        | "abstract_parenthesized_declarator"
        | "abstract_pointer_declarator"
        | "abstract_reference_declarator" => None,
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.named_child(node.named_child_count().saturating_sub(1)))
            .and_then(cpp_declarator_name_node),
    }
}

fn cpp_declarator_name_path_contains(declarator: Node<'_>, candidate: Node<'_>) -> bool {
    let Some(name) = cpp_declarator_name_node(declarator) else {
        return false;
    };
    let mut current = Some(declarator);
    while let Some(node) = current {
        if cpp_same_node(node, candidate) {
            return true;
        }
        if cpp_same_node(node, name) {
            return false;
        }
        current = node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.child_by_field_name("field"));
    }
    false
}

fn cpp_normalize_declared_type_for_visibility(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    text: &str,
) -> String {
    let normalized = cpp_normalize_declared_type_text(text);
    cpp_resolvable_declared_type_suffix(visibility, file, &normalized).unwrap_or(normalized)
}

fn cpp_resolvable_declared_type_suffix(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    text: &str,
) -> Option<String> {
    if visibility.resolve_type(file, text).is_some() {
        return Some(text.to_string());
    }
    let tokens: Vec<_> = text.split_whitespace().collect();
    for index in 1..tokens.len() {
        let suffix = tokens[index..].join(" ");
        if visibility.resolve_type(file, &suffix).is_some() {
            return Some(suffix);
        }
    }
    None
}

fn cpp_declaration_prefix_before_first_declarator(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    let first_declarator = node.named_children(&mut cursor).find_map(|child| {
        if child.kind() == "init_declarator" {
            child.child_by_field_name("declarator")
        } else if cpp_is_declarator_node(child) {
            Some(child)
        } else {
            None
        }
    })?;
    source
        .get(node.start_byte()..first_declarator.start_byte())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn cpp_normalize_declared_type_text(text: &str) -> String {
    const DECLARATION_SPECIFIERS: [&str; 10] = [
        "const ",
        "volatile ",
        "static ",
        "extern ",
        "mutable ",
        "constexpr ",
        "constinit ",
        "inline ",
        "register ",
        "thread_local ",
    ];

    let mut normalized = normalize_cpp_type_text(text);
    loop {
        let Some(stripped) = DECLARATION_SPECIFIERS
            .iter()
            .find_map(|specifier| normalized.strip_prefix(specifier))
        else {
            return normalized;
        };
        normalized = normalize_cpp_type_text(stripped);
    }
}

fn cpp_constructor_style_local_declaration(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    declarator: Node<'_>,
    type_text: Option<&str>,
    bindings: &LocalInferenceEngine<CppType>,
) -> bool {
    let Some(parameters) = declarator.child_by_field_name("parameters") else {
        return false;
    };
    if parameters.named_child_count() == 0 {
        return false;
    }
    if extract_variable_name(declarator, source).is_none() {
        return false;
    }
    if !type_text
        .and_then(|text| visibility.resolve_type(file, text))
        .is_some_and(|unit| unit.is_class())
    {
        return false;
    }
    cpp_constructor_arguments_look_like_expressions(visibility, file, source, parameters, bindings)
}

fn cpp_constructor_arguments_look_like_expressions(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    parameters: Node<'_>,
    bindings: &LocalInferenceEngine<CppType>,
) -> bool {
    let text = cpp_node_text(parameters, source);
    let inner = text.trim().trim_start_matches('(').trim_end_matches(')');
    cpp_split_top_level_commas(inner).any(|argument| {
        let argument = argument.trim();
        !argument.is_empty()
            && !cpp_argument_looks_like_parameter_declaration(visibility, file, argument, bindings)
    })
}

fn cpp_argument_looks_like_parameter_declaration(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    argument: &str,
    bindings: &LocalInferenceEngine<CppType>,
) -> bool {
    let without_default = argument.split('=').next().unwrap_or(argument).trim();
    if without_default.is_empty() {
        return false;
    }
    if is_cpp_local_symbol_expression(without_default, bindings) {
        return false;
    }
    if cpp_builtin_type_text(without_default) {
        return true;
    }
    visibility
        .resolve_type(file, &cpp_parameter_type_text(without_default))
        .is_some()
}

fn is_cpp_local_symbol_expression(
    argument: &str,
    bindings: &LocalInferenceEngine<CppType>,
) -> bool {
    argument
        .chars()
        .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && !bindings.resolve_symbol(argument).is_unknown()
}

fn cpp_builtin_type_text(text: &str) -> bool {
    // Builtin-ness is a property of the base type, independent of pointer depth,
    // so drop the trailing `*` markers that `cpp_parameter_type_text` appends.
    let normalized = cpp_parameter_type_text(text);
    let normalized = normalized.trim_end_matches('*');
    let tokens: Vec<_> = normalized.split_whitespace().collect();
    !tokens.is_empty()
        && tokens.iter().all(|token| {
            matches!(
                *token,
                "auto"
                    | "bool"
                    | "char"
                    | "char8_t"
                    | "char16_t"
                    | "char32_t"
                    | "const"
                    | "double"
                    | "float"
                    | "int"
                    | "long"
                    | "short"
                    | "signed"
                    | "size_t"
                    | "unsigned"
                    | "void"
                    | "volatile"
                    | "wchar_t"
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn cpp_seed_binding(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    lexical_namespace: Option<&str>,
    name: &str,
    type_text: Option<&str>,
    type_node: Option<Node<'_>>,
    declarator_depth: i32,
    root: Option<Node<'_>>,
    value: Option<Node<'_>>,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    if name.is_empty() {
        return;
    }
    let resolved = type_text
        .filter(|text| *text != "auto")
        .map(|text| {
            let name = normalize_cpp_type_name(text);
            let structured_template_node = type_node.filter(|node| cpp_contains_template_id(*node));
            let unit = match structured_template_node
                .map(|node| visibility.resolve_type_node_result(file, node, source))
            {
                Some(Ok(Some(unit))) => Some(unit),
                Some(Err(_)) => None,
                Some(Ok(None)) | None => cpp_resolve_type_unit_in_namespace(
                    analyzer,
                    visibility,
                    file,
                    &name,
                    lexical_namespace,
                ),
            };
            CppType {
                name: name.clone(),
                unit,
                indirection: 0,
                pointee_const: false,
                alias_unit: cpp_resolve_type_alias_unit(analyzer, visibility, file, &name),
            }
        })
        .or_else(|| {
            value.and_then(|value| {
                cpp_infer_type_from_value(analyzer, support, visibility, file, source, root, value)
            })
        });
    match resolved {
        Some(mut cpp_type) => {
            // The declarator (`T* p`, `T** pp`) adds to whatever the type spelling
            // or inferred value contributed.
            cpp_type.indirection += declarator_depth;
            bindings.seed_symbol(name.to_string(), cpp_type);
        }
        None => bindings.declare_shadow(name.to_string()),
    }
}

fn cpp_contains_template_id(node: Node<'_>) -> bool {
    subtree_contains(node, |current| current.kind() == "template_type")
}

fn cpp_resolve_type_unit(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    type_text: &str,
) -> Option<CodeUnit> {
    cpp_resolve_type_unit_in_namespace(analyzer, visibility, file, type_text, None)
}

fn cpp_resolve_type_unit_in_namespace(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    type_text: &str,
    lexical_namespace: Option<&str>,
) -> Option<CodeUnit> {
    let name = normalize_cpp_type_text(type_text);
    if name.contains("::")
        && !type_text.trim_start().starts_with("::")
        && let Some(unit) = lexical_namespace
            .into_iter()
            .flat_map(|namespace| cpp_namespace_relative_names(namespace, &name))
            .find_map(|candidate| {
                let mut seen = HashSet::default();
                cpp_resolve_type_unit_inner(analyzer, visibility, file, &candidate, &mut seen)
            })
    {
        return Some(unit);
    }
    let mut seen = HashSet::default();
    cpp_resolve_type_unit_inner(analyzer, visibility, file, type_text, &mut seen)
}

fn cpp_resolve_type_alias_unit(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    type_text: &str,
) -> Option<CodeUnit> {
    let name = normalize_cpp_type_text(type_text);
    visibility
        .type_name_candidates(file, &name)
        .into_iter()
        .find_map(|unit| {
            (cpp_unit_is_type_alias(analyzer, unit) && cpp_type_unit_matches_name(unit, &name))
                .then(|| unit.clone())
        })
}

fn cpp_resolve_type_unit_inner(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    type_text: &str,
    seen: &mut HashSet<String>,
) -> Option<CodeUnit> {
    let name = normalize_cpp_type_text(type_text);
    if !seen.insert(name.clone()) {
        return None;
    }
    let mut targets = visibility
        .type_name_candidates(file, &name)
        .into_iter()
        .filter(|unit| {
            (unit.is_class() || cpp_unit_is_type_alias(analyzer, unit))
                && cpp_type_unit_matches_name(unit, &name)
        })
        .filter_map(|unit| {
            cpp_alias_target_unit(analyzer, visibility, file, unit, seen)
                .or_else(|| (!cpp_unit_is_type_alias(analyzer, unit)).then(|| unit.clone()))
        })
        .collect::<Vec<_>>();
    if targets.is_empty()
        && let Some(unit) = visibility.resolve_type(file, type_text)
    {
        targets
            .push(cpp_alias_target_unit(analyzer, visibility, file, &unit, seen).unwrap_or(unit));
    }
    cpp_choose_canonical_type(analyzer, targets)
}

fn cpp_type_unit_matches_name(unit: &CodeUnit, name: &str) -> bool {
    if name.contains("::") {
        cpp_name_for(unit) == name
    } else {
        unit.identifier() == name
    }
}

fn cpp_namespace_relative_names(namespace: &str, name: &str) -> Vec<String> {
    let parts = crate::analyzer::symbol_lookup::parse_symbol_path(Language::Cpp, namespace);
    (1..=parts.len())
        .rev()
        .map(|len| format!("{}::{name}", parts[..len].join("::")))
        .collect()
}

fn cpp_choose_canonical_type(
    analyzer: &dyn IAnalyzer,
    mut candidates: Vec<CodeUnit>,
) -> Option<CodeUnit> {
    sort_units(&mut candidates);
    candidates.dedup();
    let first = candidates.first()?.clone();
    let cpp_name = cpp_name_for(&first);
    if !candidates
        .iter()
        .all(|candidate| cpp_name_for(candidate) == cpp_name)
    {
        return (candidates.len() == 1).then_some(first);
    }
    candidates
        .iter()
        .max_by_key(|candidate| {
            analyzer
                .ranges(candidate)
                .into_iter()
                .map(|range| range.end_byte.saturating_sub(range.start_byte))
                .max()
                .unwrap_or_default()
        })
        .or(Some(&first))
        .cloned()
}

fn cpp_alias_target_unit(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    unit: &CodeUnit,
    seen: &mut HashSet<String>,
) -> Option<CodeUnit> {
    if !cpp_unit_is_type_alias(analyzer, unit) {
        return None;
    }
    cpp_alias_target_texts(analyzer, unit)
        .find_map(|rhs| cpp_resolve_type_unit_inner(analyzer, visibility, file, &rhs, seen))
}

/// Resolve the receiver type reached by `receiver->member` when `receiver` has a template
/// alias type such as `using NodeDefPtr = shared_ptr<NodeDef>`. `->` is governed by the
/// wrapper's `operator->` return type, so we resolve the wrapper class, read that operator's
/// declared return type, substitute the alias's template arguments for the wrapper's
/// parameters, and resolve the pointee. This models the language rule rather than assuming the
/// wrapper exposes its first template argument.
fn cpp_alias_arrow_target_unit(ctx: CppLookupCtx<'_, '_>, alias: &CodeUnit) -> Option<CodeUnit> {
    let ctx_dispatch = CppDispatch::new(ctx.analyzer);
    cpp_alias_target_texts(ctx.analyzer, alias).find_map(|rhs| {
        let head = rhs.split('<').next()?.trim();
        let args = cpp_angle_group_items(&rhs);
        let mut wrapper_seen = HashSet::default();
        let wrapper = cpp_resolve_type_unit_inner(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            head,
            &mut wrapper_seen,
        )?;
        let params = cpp_template_parameter_names(ctx.analyzer, &wrapper);
        let arrow = cpp_member_candidates(ctx, vec![wrapper], "operator->", None, None)
            .into_iter()
            .next()?;
        let return_text = cpp_function_return_type_text(ctx_dispatch.source(), &arrow)?;
        // `receiver->member` follows one level of pointer indirection from operator->'s result.
        if cpp_type_text_pointer_depth(&return_text) < 1 {
            return None;
        }
        let pointee = return_text
            .trim()
            .strip_suffix('*')
            .unwrap_or(&return_text)
            .trim();
        let pointee = cpp_substitute_template_param(&params, &args, pointee);
        let mut pointee_seen = HashSet::default();
        cpp_resolve_type_unit_inner(
            ctx.analyzer,
            ctx.visibility,
            ctx.file,
            &pointee,
            &mut pointee_seen,
        )
    })
}

/// Substitute a wrapper template parameter name appearing in `type_text` with the matching
/// argument supplied by the alias, by declaration order. Non-parameter text (a concrete return
/// type) is returned unchanged.
fn cpp_substitute_template_param(params: &[String], args: &[String], type_text: &str) -> String {
    let target = type_text.trim();
    params
        .iter()
        .position(|param| param == target)
        .and_then(|index| args.get(index))
        .map(|arg| arg.trim().to_string())
        .unwrap_or_else(|| target.to_string())
}

/// Names of the template parameters a class/alias unit declares, e.g. `["T"]` for
/// `template <class T> class shared_ptr`. Empty when the unit is not a template.
fn cpp_template_parameter_names(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Vec<String> {
    let signature = unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures(unit).first().cloned())
        .unwrap_or_default();
    let Some(group) = cpp_first_angle_group(&signature) else {
        return Vec::new();
    };
    cpp_split_top_level_commas(group)
        .filter_map(|param| cpp_trailing_identifier(param.split('=').next().unwrap_or(param)))
        .collect()
}

/// Top-level comma-separated items inside the first balanced `<...>` group of `text`, e.g. the
/// template arguments of `shared_ptr<NodeDef>`.
fn cpp_angle_group_items(text: &str) -> Vec<String> {
    cpp_first_angle_group(text)
        .map(|group| {
            cpp_split_top_level_commas(group)
                .map(|item| item.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Contents of the first balanced `<...>` group in `text`, ignoring nested angle brackets.
fn cpp_first_angle_group(text: &str) -> Option<&str> {
    let open = text.find('<')?;
    let mut depth = 0i32;
    for (offset, ch) in text[open..].char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[open + 1..open + offset].trim());
                }
            }
            _ => {}
        }
    }
    None
}

/// The trailing identifier of a template parameter declaration, e.g. `T` from `class T`.
fn cpp_trailing_identifier(text: &str) -> Option<String> {
    let name: String = text
        .trim()
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    (!name.is_empty()).then_some(name)
}

fn cpp_alias_target_texts<'a>(
    analyzer: &'a dyn IAnalyzer,
    unit: &'a CodeUnit,
) -> impl Iterator<Item = String> + 'a {
    let mut signatures: Vec<String> = unit.signature().map(str::to_string).into_iter().collect();
    signatures.extend(analyzer.signatures(unit));
    signatures.extend(analyzer.get_source(unit, false));
    signatures
        .into_iter()
        .filter_map(|signature| cpp_alias_target_text(&signature))
}

fn cpp_alias_target_text(signature: &str) -> Option<String> {
    let signature = signature.trim();
    let rhs = if let Some((_, rhs)) = signature.split_once('=') {
        rhs
    } else {
        let rest = signature.strip_prefix("typedef ")?;
        rest.rsplit_once(char::is_whitespace)?.0
    };
    Some(rhs.trim().trim_end_matches(';').trim().to_string())
}

fn cpp_infer_type_from_value(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Option<Node<'_>>,
    node: Node<'_>,
) -> Option<CppType> {
    match node.kind() {
        "new_expression" => {
            let text = cpp_node_text(node, source).trim();
            let rest = text.strip_prefix("new ").unwrap_or(text);
            let type_text = rest.split(['(', '{']).next().unwrap_or(rest);
            Some(CppType::from_text(analyzer, visibility, file, type_text, 1))
        }
        "call_expression" => cpp_call_return_type(
            analyzer, support, visibility, file, source, root, node,
        )
        .or_else(|| {
            node.child_by_field_name("function")
                .and_then(|function| visibility.resolve_type(file, cpp_node_text(function, source)))
                .map(|unit| CppType::from_unit(unit, 0))
        }),
        _ => None,
    }
}

fn cpp_call_return_type(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Option<Node<'_>>,
    call: Node<'_>,
) -> Option<CppType> {
    let function = call.child_by_field_name("function")?;
    let CallArityEvidence::Exact(arity) = visibility.call_arity_evidence(file, call, source) else {
        return None;
    };
    let candidates = match function.kind() {
        "qualified_identifier" => {
            let scope = function.child_by_field_name("scope")?;
            let name = function
                .child_by_field_name("name")
                .and_then(cpp_callable_name_node)?;
            let owner = visibility.resolve_type(file, cpp_node_text(scope, source))?;
            cpp_filter_candidates_by_arity(
                cpp_direct_member_candidates(
                    analyzer,
                    support,
                    &[owner],
                    cpp_node_text(name, source),
                ),
                Some(arity),
                analyzer,
            )
        }
        "identifier" | "dependent_name" | "template_function" | "template_method" => {
            let name = cpp_callable_name_node(function)?;
            cpp_filter_candidates_by_arity(
                cpp_visible_name_candidates(
                    analyzer,
                    visibility,
                    file,
                    support,
                    cpp_node_text(name, source),
                    Some(CppTargetKind::FreeFunction),
                    None,
                ),
                Some(arity),
                analyzer,
            )
        }
        "field_expression" => {
            let root = root?;
            let member = function
                .child_by_field_name("field")
                .and_then(cpp_callable_name_node)
                .map(|field| cpp_node_text(field, source))?;
            let receiver = function
                .child_by_field_name("argument")
                .or_else(|| function.named_child(0))?;
            let owners = cpp_field_receiver_type_units(
                analyzer, support, visibility, file, source, root, function, receiver,
            );
            cpp_member_candidates(
                CppLookupCtx {
                    analyzer,
                    support,
                    file,
                    visibility,
                    source,
                    root,
                    class_ranges: None,
                },
                owners,
                member,
                Some(arity),
                None,
            )
        }
        _ => Vec::new(),
    };
    cpp_unanimous_function_return_type(analyzer, visibility, file, &candidates)
}

fn cpp_unanimous_function_return_type(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    candidates: &[CodeUnit],
) -> Option<CppType> {
    let mut resolved_return: Option<CppType> = None;
    for candidate in candidates {
        let return_type = cpp_function_return_type(analyzer, visibility, file, candidate)?;
        if let Some(existing) = resolved_return.as_ref()
            && (existing.name != return_type.name
                || existing.indirection != return_type.indirection)
        {
            return None;
        }
        resolved_return = Some(return_type);
    }
    resolved_return
}

fn cpp_function_return_type(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    function: &CodeUnit,
) -> Option<CppType> {
    let dispatch = CppDispatch::new(analyzer);
    let type_text = cpp_function_return_type_text(dispatch.source(), function)?;
    let indirection = cpp_type_text_pointer_depth(&type_text);
    let type_text = normalize_cpp_type_text(&type_text);
    Some(CppType::from_text(
        analyzer,
        visibility,
        file,
        &type_text,
        indirection,
    ))
}

fn cpp_unresolved_include_boundary(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    if !reference.contains("::") && !reference.chars().next().is_some_and(char::is_uppercase) {
        return false;
    }
    let include_targets =
        resolve_analyzer::<CppAnalyzer>(analyzer).map(|cpp| cpp.include_target_index());
    analyzer.import_statements(file).iter().any(|import| {
        cpp_include_paths(std::slice::from_ref(import)).iter().any(
            |include| match include_targets {
                Some(index) => resolve_include_targets_with_index(file, include, index).is_empty(),
                None => resolve_include_targets(analyzer.project(), file, include).is_empty(),
            },
        )
    })
}

fn cpp_lexical_namespace(node: Node<'_>, source: &str) -> Option<String> {
    let mut names = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "namespace_definition"
            && let Some(name) = parent.child_by_field_name("name")
        {
            names.push(cpp_node_text(name, source).trim().to_string());
        }
        current = parent.parent();
    }
    names.reverse();
    (!names.is_empty()).then(|| names.join("::"))
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use crate::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    use crate::path_utils::rel_path_string;
    use crate::test_support::AnalyzerFixture;

    fn wide_deep_member_fixture() -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
        let statements = (0..96)
            .map(|index| format!("    int value{index} = {index};\n"))
            .collect::<String>();
        let expression = format!("{}service{}->run()", "(".repeat(24), ")".repeat(24));
        let source = format!(
            "struct Service {{ void run() {{}} }};\n\n\
             void use(Service* service) {{\n{statements}    {expression};\n}}\n"
        );
        let fixture =
            AnalyzerFixture::new_for_language(Language::Cpp, &[("receiver.cpp", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "receiver.cpp");
        let tree = parse_cpp_tree(&source).expect("C++ tree");
        let expression_start = source.rfind(&expression).expect("C++ member call");
        let start_byte = expression_start + expression.rfind("run").expect("member name");
        let end_byte = start_byte + "run".len();
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "run".to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        };
        (fixture, file, source, tree, site)
    }

    #[test]
    fn recovered_function_declaration_is_a_local_scope() {
        let source =
            "namespace n {\nprivate:\nvoid flatten(const T& value) BROKEN {\n{ value.type(); }\n";
        let tree = parse_cpp_tree(source).expect("C++ recovery tree");
        let focus = source.find("value.type").expect("parameter receiver");
        let node = tree
            .root_node()
            .named_descendant_for_byte_range(focus, focus + "value".len())
            .expect("focused receiver node");
        let scope = cpp_enclosing_local_scope(node).expect("recovered function scope");

        assert_eq!(scope.kind(), "declaration");
        assert!(cpp_recovered_function_declaration_scope(scope));
        assert_eq!(
            scope
                .child_by_field_name("declarator")
                .map(|node| node.kind()),
            Some("function_declarator")
        );
    }

    #[test]
    fn class_alias_is_not_visible_in_its_own_template_argument() {
        let source = r#"
namespace lib {
template<typename T> struct wrapper {};
struct value_type {};
struct holder {
    using value_type = wrapper<value_type>;
};
}
"#;
        let fixture = AnalyzerFixture::new_for_language(Language::Cpp, &[("alias.hpp", source)]);
        let analyzer = fixture.analyzer.analyzer();
        let alias = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.fq_name().ends_with("holder$value_type"))
            .expect("member alias");
        let tree = parse_cpp_tree(source).expect("C++ tree");
        let start = source
            .find("wrapper<value_type>")
            .expect("alias right-hand type")
            + "wrapper<".len();
        let node = tree
            .root_node()
            .named_descendant_for_byte_range(start, start + "value_type".len())
            .expect("alias right-hand type node");

        assert_eq!(node.kind(), "type_identifier");
        assert!(cpp_type_alias_declaration_contains_node(
            analyzer, &alias, node
        ));
    }

    #[test]
    fn bounded_cpp_wide_deep_walk_stops_without_partial_result() {
        let (fixture, file, source, tree, site) = wide_deep_member_fixture();
        let outcome = resolve_cpp_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::tiny(),
            None,
        );

        assert!(matches!(
            outcome,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                ..
            }
        ));
    }

    #[test]
    fn bounded_cpp_wide_deep_walk_honors_mid_walk_cancellation() {
        let (fixture, file, source, tree, site) = wide_deep_member_fixture();
        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        let outcome = resolve_cpp_bounded(
            fixture.analyzer.analyzer(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );

        assert!(matches!(outcome, BoundedResolution::Cancelled { .. }));
    }
}
