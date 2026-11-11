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
    AdmittedTupleBinding, SelectedBindingUnavailable, SelectedTupleBinding,
    SelectedTupleBindingReads,
};
use brokk_bifrost_analysis::analyzer::semantic::type_flow::validate_prepared_syntax_source_for_procedure;
use brokk_bifrost_analysis::analyzer::semantic::{
    GuardedPatternProjection, PatternProjectionStep, ProcedureHandle, SemanticProviderError,
    SemanticRequest,
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

pub(super) fn admit_selected_tuple_binding(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    candidate: &GuardedPatternProjection,
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
    if candidate.path.len() != 1 || candidate.declared_path_len != 1 {
        return Ok(reject("only one tuple field step is supported", reads));
    }
    let PatternProjectionStep::Tuple(ordinal) = &candidate.path[0] else {
        return Ok(reject("field is not a tuple ordinal", reads));
    };
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
    let pattern = match exact_node(
        tree.root_node(),
        "tuple_struct_pattern",
        span.start_byte() as usize,
        span.end_byte() as usize,
    ) {
        Ok(Some(node)) => node,
        Ok(None) => return Ok(reject("pattern source is not exact", reads)),
        Err(()) => {
            return Ok(SelectedTupleBinding::Unavailable(
                SelectedBindingUnavailable::LimitExceeded("syntax walk limit"),
            ));
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
    let Some(field_pattern) = fields.get(*ordinal as usize) else {
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
    let binder_node = match exact_node(
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
    };
    let mut binding_shape = binder_node;
    while binding_shape.id() != field_pattern.id() {
        let Some(parent) = binding_shape.parent() else {
            return Ok(reject("binder ancestry unavailable", reads));
        };
        if parent.kind() == "ref_pattern" {
            return Ok(reject("binder is by reference", reads));
        }
        binding_shape = parent;
    }
    let Some(parameter) = pattern
        .parent()
        .filter(|parent| parent.kind() == "parameter")
    else {
        return Ok(reject("pattern is not an ordinary formal", reads));
    };
    let Some(formal) = parameter.child_by_field_name("type") else {
        return Ok(reject(
            "formal type is not an exact non-reference constructor",
            reads,
        ));
    };
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
    let mut type_budget = 256;
    let Some(formal) = alias_type_expr(formal, &file, &source, &mut type_budget) else {
        return Ok(SelectedTupleBinding::Unavailable(
            SelectedBindingUnavailable::ExternalLimitExceeded(
                "formal type exceeds the alias budget",
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
    if request.cancellation.is_cancelled() {
        return Ok(SelectedTupleBinding::Unavailable(
            SelectedBindingUnavailable::Cancelled,
        ));
    }
    let Some(constructor_route) = reads.constructor.as_deref() else {
        return Ok(reject("constructor identity unresolved", reads));
    };
    let Some(formal_route) = reads.formal_constructor.as_deref() else {
        return Ok(reject("formal constructor identity unresolved", reads));
    };
    let Some(snapshot) = snapshot else {
        return Ok(reject("active declaration selection unavailable", reads));
    };
    let Some(overlay) = snapshot.semantic_model_overlay() else {
        return Ok(reject("selected declaration overlay unavailable", reads));
    };
    let crates = super::crate_identity::RustOverlayCrates::new(Some(overlay));
    let Some(symbol) = crates.referenceable_symbol(constructor_route) else {
        return Ok(reject("selected constructor is absent or ambiguous", reads));
    };
    let Some(formal_symbol) = crates.referenceable_symbol(formal_route) else {
        return Ok(reject("selected formal is absent or ambiguous", reads));
    };
    if symbol.id != formal_symbol.id
        || symbol.provenance.pack_digest != formal_symbol.provenance.pack_digest
    {
        return Ok(reject("formal and pattern constructor differ", reads));
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
    let Some(TupleFieldSlot::Public { id, r#type, .. }) = layout.fields.get(*ordinal as usize)
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
    Ok(SelectedTupleBinding::Admitted(AdmittedTupleBinding {
        ordinal: *ordinal,
        field_id: id.clone(),
        field_type,
        reads,
    }))
}

#[cfg(test)]
mod tests {
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
