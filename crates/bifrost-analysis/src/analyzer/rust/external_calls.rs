//! External callable evidence from native scope authority and activated models.

use super::{native_points, rust_import_binder_visible_at_byte};
use crate::CancellationToken;
use crate::analyzer::languages::{BoundedReceiverQuery, ExternalCalleeSite};
use crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity;
use crate::analyzer::semantic_model::{
    SemanticModelCallApplication, SemanticModelCallableDisposition, SemanticModelCallableKey,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupStatus, ExactExternalCallProof, ResolvedReferenceSite,
};
use crate::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;
use crate::analyzer::{
    IAnalyzer, ImportInfo, Language, ProjectFile, QueryToken, Range, RustOverlayCrates,
};
use brokk_bifrost_rust::declarations::rust_node_text;
use brokk_bifrost_rust::graph_support::{rust_path_is_leading_absolute, rust_path_segments};
use brokk_bifrost_rust::imports::rust_focused_use_path;
use tree_sitter::{Node, Tree};

/// The callee path that contains the focus, obtained from the call's AST fields.
pub(super) fn call_path(tree: &Tree, byte: usize) -> Option<Node<'_>> {
    let mut node = tree
        .root_node()
        .named_descendant_for_byte_range(byte, byte.saturating_add(1))?;
    loop {
        if node.kind() == "call_expression" {
            let function = node.child_by_field_name("function")?;
            return (function.start_byte() <= byte && byte < function.end_byte())
                .then_some(function);
        }
        node = node.parent()?;
    }
}

#[allow(clippy::too_many_arguments)]
fn native_external_root(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    root: Node<'_>,
    cancellation: Option<&CancellationToken>,
) -> bool {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return false;
    }
    let name = rust_node_text(root, source);
    if matches!(name, "crate" | "self" | "super") {
        return false;
    }
    // A leading :: selects the extern prelude; local binders do not shadow
    // it. The caller still requires the activated model's callable proof.
    if rust_path_is_leading_absolute(root) {
        return true;
    }
    if let Some(imports) = analyzer.import_analysis_provider_for_file(file) {
        for import in imports.import_info_of(token, file) {
            if import.local_name() == Some(name)
                && import
                    .path
                    .as_ref()
                    .is_some_and(|path| rust_import_binder_visible_at_byte(path, root.start_byte()))
            {
                return false;
            }
        }
    }
    let site = ResolvedReferenceSite {
        path: name.to_owned(),
        text: name.to_owned(),
        range: Range {
            start_byte: root.start_byte(),
            end_byte: root.end_byte(),
            start_line: root.start_position().row + 1,
            end_line: root.end_position().row + 1,
        },
        focus_start_byte: root.start_byte(),
        focus_end_byte: root.end_byte(),
    };
    matches!(native_points::resolve_rust_definition_bounded(BoundedReceiverQuery {
        analyzer, file, source, tree: Some(tree), site: &site,
        budget: INTERACTIVE_TYPE_LOOKUP_BUDGET, cancellation,
    }), BoundedResolution::Complete { value, .. }
        if value.status == DefinitionLookupStatus::UnresolvableImportBoundary
            && value.definitions.is_empty() && value.lexical_definition.is_none())
}

pub(crate) fn exact_rust_external_call(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    cancellation: Option<&CancellationToken>,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let callee = call_path(tree, site.focus_start_byte)?;
    let segments = rust_path_segments(callee)?;
    let (terminal, owners) = segments.split_last()?;
    if owners.len() < 2
        || terminal.start_byte() > site.focus_start_byte
        || site.focus_end_byte > terminal.end_byte()
    {
        return None;
    }
    if !native_external_root(analyzer, token, file, source, tree, owners[0], cancellation) {
        return None;
    }
    let parameter_count = rust_call_written_arity(tree, callee.start_byte())?;
    let owner_components = owners
        .iter()
        .map(|node| rust_node_text(*node, source).to_owned())
        .collect::<Vec<_>>();
    let member = rust_node_text(*terminal, source);
    if !rust_external_callable_declaration(analyzer, &owner_components, member, parameter_count)
        || cancellation.is_some_and(CancellationToken::is_cancelled)
    {
        return None;
    }
    Some((
        ExactExternalCallProof::rust_external_call(
            format!("{}::{member}", owner_components.join("::")),
            parameter_count,
        ),
        ResolverOwnedExternalCalleeIdentity::new(
            Language::Rust,
            owner_components.join("."),
            member,
        ),
    ))
}

pub(crate) fn rust_import_binder_external_callee(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    site: &ExternalCalleeSite<'_>,
    import: &ImportInfo,
    member: &str,
    parameter_count: u32,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let source = site.source;
    let tree = site.tree;
    let path = import.path.as_ref()?;
    if path.segments.len() < 2 {
        return None;
    }
    let span = import.binder_span?;
    let mut focused = tree
        .root_node()
        .named_descendant_for_byte_range(span.start_byte, span.end_byte)?;
    if let Some(parent) = focused.parent()
        && parent.kind() == "use_as_clause"
        && parent
            .child_by_field_name("alias")
            .is_some_and(|alias| alias.id() == focused.id())
    {
        focused = parent.child_by_field_name("path")?;
    }
    let written = rust_focused_use_path(focused, source)?;
    if written.segments != path.segments
        || !native_external_root(analyzer, token, file, source, tree, written.root, None)
        || !rust_external_callable_declaration(analyzer, &path.segments, member, parameter_count)
    {
        return None;
    }
    Some((
        ExactExternalCallProof::rust_external_call(
            format!("{}::{member}", path.render_segments("::")),
            parameter_count,
        ),
        ResolverOwnedExternalCalleeIdentity::new(Language::Rust, path.render_segments("."), member),
    ))
}

fn rust_external_callable_declaration(
    analyzer: &dyn IAnalyzer,
    owner_components: &[String],
    member: &str,
    parameter_count: u32,
) -> bool {
    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return false;
    };
    let crates = RustOverlayCrates::new(Some(&overlay));
    let owner = RustOverlayCrates::pack_name(owner_components);
    if crates.referenceable_symbol(&owner).is_none() {
        return false;
    }
    let callable = overlay.callable_for_application(
        SemanticModelCallableKey::new(
            Language::Rust.config_label(),
            &owner,
            member,
            false,
            parameter_count,
        ),
        &SemanticModelCallApplication::positional(parameter_count),
    );
    // Declaring the callable is not the same as publishing it. The member
    // lookup answers "which decl matches this application", so a private or
    // crate-visible member of a public owner would otherwise read as an
    // external API the workspace can call by name. The referenceable-symbol
    // gate above already requires the owner to be externally visible, and the
    // member has to meet the same bar before its summary may stand for the
    // call.
    if !callable
        .records
        .iter()
        .all(|record| record.externally_visible())
    {
        return false;
    }
    match callable.disposition {
        SemanticModelCallableDisposition::Unique => true,
        // Several applicable overloads that share one binding layout still
        // leave the overload identity unresolved. That is exact callable
        // evidence only while the activated model certifies the whole family,
        // which is what mints the domain-separated family identity a summary
        // can be keyed by; an uncertified overload set stays typed
        // uncertainty and the call stays open.
        SemanticModelCallableDisposition::CompatibleLayout => {
            callable.callable_family_id().is_some()
        }
        _ => false,
    }
}

pub(crate) fn rust_call_written_arity(tree: &Tree, callee_start_byte: usize) -> Option<u32> {
    let mut node = tree
        .root_node()
        .named_descendant_for_byte_range(callee_start_byte, callee_start_byte.saturating_add(1))?;
    while node.kind() != "call_expression" {
        node = node.parent()?;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    u32::try_from(arguments.named_children(&mut cursor).count()).ok()
}
