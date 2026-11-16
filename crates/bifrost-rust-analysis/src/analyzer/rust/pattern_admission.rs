//! Selected proof for one guarded Rust tuple-struct field binding.
//!
//! This module is answer-inert until the query-time overlay consumes its
//! `AdmittedTupleBinding` record. It never mutates or republishes source IR.

use super::call_conversion::selected_type::{
    ExternalRoute, alias_type_expr, exact_node, lookup_leaf, selected_external_route,
    selected_formal_route, structured_route,
};
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::languages::{
    AdmittedTupleBinding, SelectedBindingUnavailable, SelectedPatternSource, SelectedTupleBinding,
    SelectedTupleBindingReads,
};
use brokk_bifrost_analysis::analyzer::semantic::type_flow::source_span_for_node as pattern_span;
use brokk_bifrost_analysis::analyzer::semantic::type_flow::validate_prepared_syntax_source_for_procedure;
use brokk_bifrost_analysis::analyzer::semantic::{
    GuardedPatternProjection, PatternProjectionStep, ProcedureHandle, SemanticProviderError,
    SemanticRequest, SourceSpan,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{TupleFieldSlot, TypeRef};
use brokk_bifrost_analysis::analyzer::structural::provider::StructuralSyntaxLimitedOutcome;
use brokk_bifrost_analysis::analyzer::{Language, ProjectFile, WorkspaceAnalyzer};
use tree_sitter::Node;

fn reject(reason: &'static str, reads: SelectedTupleBindingReads) -> SelectedTupleBinding {
    SelectedTupleBinding::Rejected { reason, reads }
}

/// How the pattern's written name reached the resolved route.
enum ImportHop {
    /// The name is the route itself: a direct import, a local or prelude name.
    Direct,
    /// The import the pattern could see, which resolved on through other hops.
    Hop(String),
    /// The visible binding could not be determined: a qualified path that does
    /// not spell the route, a glob, a namespace alias, or a limit.
    Unknown,
}

/// Find the `use` binding visible at the constructor, innermost scope first,
/// with the crate's scope-aware import lookup, which carries the item path as
/// structured segments. A qualified path is its own written route and consults
/// no `use`. `caches` memoizes the file's `use` scan, so the many binders of one
/// file share one scan.
fn written_import_hop(
    caches: &brokk_bifrost_rust::lexical_scope::RustLexicalCaches,
    root: Node<'_>,
    source: &str,
    constructor: Node<'_>,
    route: &str,
) -> ImportHop {
    use brokk_bifrost_rust::lexical_scope::{RustVisibleUse, visible_use_for_name_with};
    if matches!(
        constructor.kind(),
        "scoped_identifier" | "scoped_type_identifier"
    ) {
        return match structured_route(constructor, source) {
            Some(parts) if super::crate_identity::RustOverlayCrates::pack_name(&parts) == route => {
                ImportHop::Direct
            }
            _ => ImportHop::Unknown,
        };
    }
    let Some(leaf) = lookup_leaf(constructor) else {
        return ImportHop::Unknown;
    };
    let Some(leaf) = source.get(leaf.start_byte()..leaf.end_byte()) else {
        return ImportHop::Unknown;
    };
    let leaf = leaf.strip_prefix("r#").unwrap_or(leaf);
    match visible_use_for_name_with(caches, root, source, constructor.start_byte(), leaf) {
        RustVisibleUse::Unbound => ImportHop::Direct,
        RustVisibleUse::GlobMayBind | RustVisibleUse::Namespace => ImportHop::Unknown,
        RustVisibleUse::Named {
            segments,
            is_global,
        } => {
            if super::crate_identity::RustOverlayCrates::pack_name(&segments) == route {
                ImportHop::Direct
            } else {
                let written = segments.join("::");
                ImportHop::Hop(if is_global {
                    format!("::{written}")
                } else {
                    written
                })
            }
        }
    }
}

/// A declaration route that could not be read stopped for a cancellation or
/// for a lookup limit; the cause is not the same and callers report it.
fn route_unavailable(request: &SemanticRequest<'_>, external: bool) -> SelectedTupleBinding {
    SelectedTupleBinding::Unavailable(if request.cancellation.is_cancelled() {
        SelectedBindingUnavailable::Cancelled
    } else if external {
        SelectedBindingUnavailable::ExternalLimitExceeded("declaration route lookup limit")
    } else {
        SelectedBindingUnavailable::LimitExceeded("declaration route lookup limit")
    })
}

/// Validate every recorded step before selecting the inner field. No step
/// changes the meaning of the candidate's root whole value.
fn selected_field_path<'tree>(
    mut node: Node<'tree>,
    candidate: &GuardedPatternProjection,
    selected: &std::ops::Range<usize>,
    binder: SourceSpan,
    source: &str,
) -> Option<(Node<'tree>, u32, usize, Node<'tree>)> {
    if candidate.path.len() != usize::from(candidate.declared_path_len) {
        return None;
    }
    let mut selected_step = None;
    for (index, step) in candidate.path.iter().enumerate() {
        let parent = node;
        node = match (node.kind(), step) {
            ("tuple_struct_pattern" | "tuple_pattern", PatternProjectionStep::Tuple(ordinal)) => {
                let type_id = node.child_by_field_name("type").map(|ty| ty.id());
                let mut cursor = node.walk();
                let fields = node
                    .children(&mut cursor)
                    .filter(|child| {
                        (child.is_named() || child.kind() == "_")
                            && !child.is_extra()
                            && Some(child.id()) != type_id
                    })
                    .collect::<Vec<_>>();
                if fields
                    .iter()
                    .any(|field| field.kind() == "remaining_field_pattern")
                {
                    return None;
                }
                let child = *fields.get(*ordinal as usize)?;
                if parent.kind() == "tuple_struct_pattern"
                    && child.start_byte() == selected.start
                    && child.end_byte() == selected.end
                {
                    selected_step = Some((parent, *ordinal, index));
                }
                child
            }
            ("struct_pattern", PatternProjectionStep::Named(name)) => {
                let mut cursor = node.walk();
                let field = node.named_children(&mut cursor).find(|field| {
                    field.kind() == "field_pattern"
                        && field.child_by_field_name("name").is_some_and(|field_name| {
                            // Compare only an AST-selected field identifier's value.
                            field_name.utf8_text(source.as_bytes()).ok() == Some(name.as_ref())
                        })
                });
                let field = field?;
                field.child_by_field_name("pattern").or_else(|| {
                    field
                        .child_by_field_name("name")
                        .filter(|name| name.kind() == "shorthand_field_identifier")
                })?
            }
            _ => return None,
        };
    }
    // The full path ends at this exact recorded binder, never at another
    // identifier in the same selected field or at an aggregate/wildcard.
    let identifier = super::semantic::identity_binding_identifier(node)?;
    let (constructor, ordinal, split) = selected_step?;
    (pattern_span(identifier) == binder).then_some((constructor, ordinal, split, identifier))
}

pub(super) fn admit_selected_tuple_binding(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    candidate: &GuardedPatternProjection,
    snapshot: Option<
        &brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot,
    >,
    request: &mut SemanticRequest<'_>,
) -> Result<SelectedTupleBinding, SemanticProviderError> {
    admit_pattern(workspace, procedure, candidate, None, snapshot, request)
}

pub(super) fn admit_selected_pattern_source(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    candidate: &GuardedPatternProjection,
    field: std::ops::Range<usize>,
    snapshot: Option<
        &brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot,
    >,
    request: &mut SemanticRequest<'_>,
) -> Result<SelectedTupleBinding, SemanticProviderError> {
    admit_pattern(
        workspace,
        procedure,
        candidate,
        Some(field),
        snapshot,
        request,
    )
}

fn admit_pattern(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    candidate: &GuardedPatternProjection,
    selected_field: Option<std::ops::Range<usize>>,
    snapshot: Option<
        &brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot,
    >,
    request: &mut SemanticRequest<'_>,
) -> Result<SelectedTupleBinding, SemanticProviderError> {
    if request.cancellation.is_cancelled() {
        return Ok(SelectedTupleBinding::Unavailable(
            SelectedBindingUnavailable::Cancelled,
        ));
    }
    let analyzer = workspace.analyzer();
    let mut reads = SelectedTupleBindingReads {
        constructor: None,
        formal_constructor: None,
        selected_constructor: None,
        selected_pack_digest: None,
        selected_record_id: None,
        import_chain: Vec::new(),
        import_route_complete: true,
        model_set_hash: snapshot
            .map(|snapshot| snapshot.active_models().active_model_set_hash().to_owned()),
        layout: None,
        layout_complete: false,
    };
    if selected_field.is_none() && (candidate.path.len() != 1 || candidate.declared_path_len != 1) {
        return Ok(reject("only one tuple field step is supported", reads));
    }
    let file = ProjectFile::new(
        analyzer.project().root(),
        procedure.artifact().key().path().as_path(),
    );
    let prepared = analyzer
        .structural_fact_providers()
        .into_iter()
        .find(|provider| provider.structural_language() == Language::Rust)
        .map(|provider| {
            provider.structural_syntax_limited(&file, 1_048_576, Some(request.cancellation))
        });
    let prepared = match prepared {
        Some(StructuralSyntaxLimitedOutcome::Available(syntax)) => syntax.into_inner(),
        Some(StructuralSyntaxLimitedOutcome::Cancelled) => {
            return Ok(SelectedTupleBinding::Unavailable(
                SelectedBindingUnavailable::Cancelled,
            ));
        }
        Some(StructuralSyntaxLimitedOutcome::Exceeded { .. }) => {
            return Ok(SelectedTupleBinding::Unavailable(
                SelectedBindingUnavailable::LimitExceeded("syntax size limit"),
            ));
        }
        _ => return Ok(reject("source snapshot unavailable", reads)),
    };
    let Ok(prepared) =
        validate_prepared_syntax_source_for_procedure(workspace, procedure, &file, prepared)
    else {
        return Ok(reject("source revision differs from procedure", reads));
    };
    let source = Arc::<str>::from(prepared.source());
    let tree = prepared.tree();
    let Some(mapping) = procedure
        .semantics()
        .source_mapping(candidate.pattern_source)
    else {
        return Ok(reject("pattern source mapping unavailable", reads));
    };
    let span = mapping.locator.anchor().span();
    let Some(pattern) = tree
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
        .filter(|node| {
            node.start_byte() == span.start_byte() as usize
                && node.end_byte() == span.end_byte() as usize
                && matches!(
                    node.kind(),
                    "tuple_struct_pattern" | "tuple_pattern" | "struct_pattern"
                )
        })
    else {
        return Ok(reject("pattern source is not exact", reads));
    };
    let (pattern, ordinal, path_split, selected_binder) = match selected_field.as_ref() {
        Some(field) => {
            let Some(binder) = procedure
                .semantics()
                .source_mapping(candidate.binder_source)
            else {
                return Ok(reject("binder source mapping unavailable", reads));
            };
            let Some(selected) = selected_field_path(
                pattern,
                candidate,
                field,
                binder.locator.anchor().span(),
                &source,
            ) else {
                return Ok(reject(
                    "selected field does not match the recorded pattern path",
                    reads,
                ));
            };
            (selected.0, selected.1, selected.2, Some(selected.3))
        }
        None => {
            let PatternProjectionStep::Tuple(ordinal) = &candidate.path[0] else {
                return Ok(reject("field is not a tuple ordinal", reads));
            };
            (pattern, *ordinal, 0, None)
        }
    };
    let Some(constructor) = pattern.child_by_field_name("type") else {
        return Ok(reject("pattern constructor unavailable", reads));
    };
    let mut cursor = pattern.walk();
    let fields = pattern
        .children(&mut cursor)
        .filter(|child| {
            (child.is_named() || child.kind() == "_")
                && !child.is_extra()
                && child.id() != constructor.id()
        })
        .collect::<Vec<_>>();
    if fields
        .iter()
        .any(|field| field.kind() == "remaining_field_pattern")
    {
        return Ok(reject("rest pattern has no fixed ordinal", reads));
    }
    let Some(field_pattern) = fields.get(ordinal as usize) else {
        return Ok(reject(
            "field ordinal is outside the written pattern",
            reads,
        ));
    };
    let Some(binder_mapping) = procedure
        .semantics()
        .source_mapping(candidate.binder_source)
    else {
        return Ok(reject("binder source mapping unavailable", reads));
    };
    let binder_span = binder_mapping.locator.anchor().span();
    let binder_node = if let Some(binder) = selected_binder {
        binder
    } else {
        match exact_node(
            *field_pattern,
            "identifier",
            binder_span.start_byte() as usize,
            binder_span.end_byte() as usize,
        ) {
            Ok(Some(node)) => node,
            Ok(None) => return Ok(reject("binder is not the selected field identifier", reads)),
            Err(()) => {
                return Ok(SelectedTupleBinding::Unavailable(
                    SelectedBindingUnavailable::LimitExceeded("syntax walk limit"),
                ));
            }
        }
    };
    let mut binding_shape = binder_node;
    while binding_shape.id() != field_pattern.id() {
        let Some(parent) = binding_shape.parent() else {
            return Ok(reject("binder ancestry unavailable", reads));
        };
        if super::semantic::pattern_binds_by_reference(parent) {
            return Ok(reject("binder is by reference", reads));
        }
        binding_shape = parent;
    }
    let formal = pattern
        .parent()
        .filter(|parent| parent.kind() == "parameter")
        .and_then(|parameter| parameter.child_by_field_name("type"));
    if selected_field.is_none() && formal.is_none() {
        return Ok(reject("pattern is not an ordinary formal", reads));
    }
    // Decide the constructor first. A local struct or enum variant is never a
    // pack-declared extractor, so it must not pay for the formal type walk, and
    // a deeply nested formal on an unrelated local type must not reach its limit.
    reads.constructor = match selected_external_route(
        analyzer,
        &file,
        &source,
        constructor,
        request.cancellation,
    ) {
        ExternalRoute::Selected(route) => Some(route),
        ExternalRoute::LocalDefinition(_) | ExternalRoute::Rejected => {
            return Ok(reject("constructor identity unresolved", reads));
        }
        ExternalRoute::Unavailable => return Ok(route_unavailable(request, false)),
    };
    if let Some(formal) = formal {
        let mut type_budget = 256;
        let Some(formal) = alias_type_expr(formal, &file, &source, &mut type_budget) else {
            use brokk_bifrost_analysis::analyzer::i_analyzer::SELECTED_PATTERN_ALIAS_LIMIT_REASON;
            analyzer.record_query_incomplete(
                brokk_bifrost_analysis::analyzer::QueryReadIncomplete::ProofStopped {
                    reason: SELECTED_PATTERN_ALIAS_LIMIT_REASON,
                    cause: None,
                },
            );
            return Ok(SelectedTupleBinding::Unavailable(
                SelectedBindingUnavailable::ExternalLimitExceeded(
                    SELECTED_PATTERN_ALIAS_LIMIT_REASON,
                ),
            ));
        };
        reads.formal_constructor =
            match selected_formal_route(analyzer, formal, request.cancellation, 0) {
                ExternalRoute::Selected(route) => Some(route),
                ExternalRoute::LocalDefinition(_) => None,
                ExternalRoute::Rejected => None,
                ExternalRoute::Unavailable => return Ok(route_unavailable(request, true)),
            };
        if reads.formal_constructor.is_none() {
            return Ok(reject("formal constructor identity unresolved", reads));
        }
    }
    if request.cancellation.is_cancelled() {
        return Ok(SelectedTupleBinding::Unavailable(
            SelectedBindingUnavailable::Cancelled,
        ));
    }
    let Some(constructor_route) = reads.constructor.as_deref() else {
        return Ok(reject("constructor identity unresolved", reads));
    };
    let Some(snapshot) = snapshot else {
        return Ok(reject("active declaration selection unavailable", reads));
    };
    let Some(overlay) = snapshot.semantic_model_overlay() else {
        return Ok(reject("selected declaration overlay unavailable", reads));
    };
    let crates = super::crate_identity::RustOverlayCrates::new(Some(overlay));
    let Some(symbol) = crates.referenceable_owner(constructor_route) else {
        return Ok(reject("selected constructor is absent or ambiguous", reads));
    };
    if let Some(formal_route) = reads.formal_constructor.as_deref() {
        let Some(formal_symbol) = crates.referenceable_owner(formal_route) else {
            return Ok(reject("selected formal is absent or ambiguous", reads));
        };
        if symbol.id != formal_symbol.id
            || symbol.provenance.pack_digest != formal_symbol.provenance.pack_digest
        {
            return Ok(reject("formal and pattern constructor differ", reads));
        }
    }
    reads.selected_constructor = Some(symbol.qualified_name.clone());
    reads.selected_pack_digest = Some(symbol.provenance.pack_digest.clone());
    reads.selected_record_id = Some(symbol.provenance.record_id.clone());
    let Some(written) = source.get(constructor.start_byte()..constructor.end_byte()) else {
        return Ok(reject("written constructor spelling unavailable", reads));
    };
    reads.import_chain = vec![written.to_owned()];
    // The resolver reports only the final external route, not the hops. Record
    // the import the pattern could see, or say the route is incomplete.
    let transient;
    let caches = match brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
        super::RustAnalyzer,
    >(analyzer)
    {
        Some(rust) => brokk_bifrost_rust::graph_support::RustSource::lexical_caches(rust),
        None => {
            transient = brokk_bifrost_rust::lexical_scope::RustLexicalCaches::new(
                &brokk_bifrost_core::retention_budget::RetentionBudget::retain_nothing(),
            );
            &transient
        }
    };
    match written_import_hop(
        caches,
        tree.root_node(),
        &source,
        constructor,
        constructor_route,
    ) {
        ImportHop::Direct => {}
        ImportHop::Hop(imported) => {
            reads.import_chain.push(imported);
            reads.import_route_complete = false;
        }
        ImportHop::Unknown => reads.import_route_complete = false,
    }
    // [written, (the import the file wrote,) the resolved route, the declaration]:
    // the declaration is always last, even when it equals the route, so the
    // route is always the entry before it.
    reads.import_chain.push(constructor_route.to_owned());
    reads.import_chain.push(symbol.qualified_name.clone());
    let Some(owner) = brokk_bifrost_analysis::analyzer::semantic_model::overlay::owner_declaration(
        snapshot.active_models(),
        &symbol,
    ) else {
        return Ok(reject(
            "selected constructor declaration unavailable",
            reads,
        ));
    };
    reads.layout = owner.tuple_fields.clone();
    reads.layout_complete = reads
        .layout
        .as_ref()
        .is_some_and(|layout| layout.is_complete());
    let Some(layout) = reads.layout.as_ref() else {
        return Ok(reject("tuple field layout unknown", reads));
    };
    if !reads.layout_complete {
        return Ok(reject("tuple field layout incomplete", reads));
    }
    if fields.len() != layout.arity as usize {
        return Ok(reject("pattern arity differs from selected layout", reads));
    }
    let Some(TupleFieldSlot::Public { id, r#type, .. }) = layout.fields.get(ordinal as usize)
    else {
        return Ok(reject("tuple field is not public and in bounds", reads));
    };
    // A field's positional identity does not depend on knowing T. Never
    // publish an unsubstituted generic parameter as the binder's concrete type.
    let mut unselected_argument = false;
    brokk_bifrost_semantic::analyzer::semantic::common::visit_type_refs([r#type], |part| {
        unselected_argument |= matches!(part, TypeRef::TypeParameter { .. } | TypeRef::Unknown);
    });
    let field_type = if unselected_argument {
        TypeRef::Unknown
    } else {
        r#type.clone()
    };
    let binding = AdmittedTupleBinding {
        ordinal,
        field_id: id.clone(),
        field_type,
        reads,
    };
    Ok(match selected_field.as_ref() {
        Some(_) => SelectedTupleBinding::Observed(SelectedPatternSource {
            constructor: pattern_span(constructor),
            field: pattern_span(*field_pattern),
            root_to_constructor: candidate.path[..path_split].into(),
            constructor_to_binding: candidate.path[path_split..].into(),
            binding,
        }),
        None => SelectedTupleBinding::Admitted(binding),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: shorthand field ref tokens bypassed the selected binder reference-mode refusal"
    )]
    fn shorthand_and_positional_reference_modes_have_structured_owners() {
        for (pattern, expected_owner) in [
            ("Query(Payload { ref value })", Some("field_pattern")),
            ("Query(Payload { ref mut value })", Some("field_pattern")),
            ("Query(Payload { mut value })", None),
            ("Query(ref value)", Some("ref_pattern")),
            ("Query(ref mut value)", Some("ref_pattern")),
            ("Query(mut value)", None),
        ] {
            let source = format!("fn handler(q: Query<Payload>) {{ let {pattern} = q; }}");
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(&source, None).unwrap();
            assert!(!tree.root_node().has_error(), "{pattern}");
            let mut pending = vec![tree.root_node()];
            let mut binder = None;
            while let Some(node) = pending.pop() {
                if matches!(node.kind(), "identifier" | "shorthand_field_identifier")
                    && node.utf8_text(source.as_bytes()).unwrap() == "value"
                {
                    assert!(binder.replace(node).is_none(), "one binding per case");
                }
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
            }
            let mut ancestor = binder.expect("parsed binding");
            let mut owner = None;
            while ancestor.kind() != "tuple_struct_pattern" {
                if super::super::semantic::pattern_binds_by_reference(ancestor) {
                    assert!(owner.replace(ancestor.kind()).is_none());
                    if ancestor.kind() == "field_pattern" {
                        let mut cursor = ancestor.walk();
                        assert!(
                            ancestor
                                .children(&mut cursor)
                                .any(|child| child.kind() == "ref")
                        );
                    }
                }
                ancestor = ancestor
                    .parent()
                    .expect("binder belongs to the tuple field");
            }
            assert_eq!(owner, expected_owner, "{pattern}");
        }
    }

    use super::{ImportHop, structured_route, written_import_hop};

    #[test]
    fn structured_route_accepts_raw_and_unicode_segments() {
        let source = "fn h() { pöem::web::r#Query; }";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let scoped = tree
            .root_node()
            .named_descendant_for_byte_range(
                source.find("pöem").unwrap(),
                source.find("r#Query").unwrap() + "r#Query".len(),
            )
            .unwrap();
        assert_eq!(
            structured_route(scoped, source).unwrap(),
            ["pöem", "web", "Query"]
        );
    }

    fn caches() -> brokk_bifrost_rust::lexical_scope::RustLexicalCaches {
        brokk_bifrost_rust::lexical_scope::RustLexicalCaches::new(
            &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
        )
    }

    #[test]
    fn a_very_deep_use_path_does_not_overflow_the_stack() {
        // The import lookup must not recurse per path segment: run it on a
        // stack far smaller than a recursive walk of 5,000 segments needs.
        let handle = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let path = (0..5_000)
                    .map(|index| format!("m{index}"))
                    .collect::<Vec<_>>()
                    .join("::");
                let source = format!("use {path}::Query;\nfn h(Query(x): Query<u8>) {{}}\n");
                let mut parser = tree_sitter::Parser::new();
                parser
                    .set_language(&tree_sitter_rust::LANGUAGE.into())
                    .unwrap();
                let tree = parser.parse(&source, None).unwrap();
                let root = tree.root_node();
                let at = source.find("Query(x)").unwrap();
                let constructor = root.descendant_for_byte_range(at, at + 5).unwrap();
                // The import is a real hop to a path that is not poem's.
                assert!(matches!(
                    written_import_hop(&caches(), root, &source, constructor, "poem.web.Query"),
                    ImportHop::Hop(_)
                ));
            })
            .unwrap();
        handle.join().expect("no stack overflow, no panic");
    }

    #[test]
    fn many_binders_of_one_file_share_one_use_scan() {
        let params = (0..20)
            .map(|index| format!("Query(p{index}): Query<u8>"))
            .collect::<Vec<_>>()
            .join(", ");
        let source = format!("use poem::web::Query;\nfn h({params}) {{}}\n");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let root = tree.root_node();
        let caches = caches();
        let mut constructors = 0;
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "tuple_struct_pattern" {
                let constructor = node.child_by_field_name("type").unwrap();
                assert!(matches!(
                    written_import_hop(&caches, root, &source, constructor, "poem.web.Query"),
                    ImportHop::Direct
                ));
                constructors += 1;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert_eq!(constructors, 20);
        assert_eq!(
            caches.use_statement_scans(),
            1,
            "one file scan serves every binder, not one per binder"
        );
    }

    fn hop_for(source: &str, route: &str) -> ImportHop {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let at = source.rfind("Query(").unwrap();
        let mut node = root.descendant_for_byte_range(at, at + 5).unwrap();
        while node.kind() != "tuple_struct_pattern" {
            node = node.parent().unwrap();
        }
        let constructor = node.child_by_field_name("type").unwrap();
        written_import_hop(&caches(), root, source, constructor, route)
    }

    #[test]
    fn the_hop_is_the_binding_visible_at_the_constructor() {
        let route = "poem.web.Query";
        assert!(matches!(
            hop_for(
                "use poem::web::Query;\nfn h(Query(x): Query<u8>) {}\n",
                route
            ),
            ImportHop::Direct
        ));
        // A sibling module's `use` is not visible at the handler.
        assert!(matches!(
            hop_for(
                "mod a { use other::Query; }\nuse poem::web::Query;\nfn h(Query(x): Query<u8>) {}\n",
                route
            ),
            ImportHop::Direct
        ));
        // The innermost scope that binds the name wins.
        assert!(matches!(
            hop_for(
                "use poem::web::Query;\nmod a { use crate::web::PoemQuery as Query; fn h(Query(x): Query<u8>) {} }\n",
                route
            ),
            ImportHop::Hop(path) if path == "crate::web::PoemQuery"
        ));
        // A glob could supply the name, so no hop is claimed.
        assert!(matches!(
            hop_for("use poem::web::*;\nfn h(Query(x): Query<u8>) {}\n", route),
            ImportHop::Unknown
        ));
        // A qualified path is its own route and ignores unrelated `use`s.
        assert!(matches!(
            hop_for(
                "use other::Query;\nfn h(poem::web::Query(x): poem::web::Query<u8>) {}\n",
                route
            ),
            ImportHop::Direct
        ));
    }
}
