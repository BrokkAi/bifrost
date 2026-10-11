//! External callable evidence from native scope authority and activated models.

use std::sync::Arc;

use super::{native_points, rust_import_binder_visible_at_byte};
use crate::CancellationToken;
use crate::analyzer::languages::{
    BoundedReceiverQuery, ExternalCalleeFileEvidence, ExternalCalleeSite,
};
use crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity;
use crate::analyzer::semantic_model::{
    SemanticModelCallApplication, SemanticModelCallableDisposition, SemanticModelCallableKey,
    SemanticModelCallableMatch, SemanticModelSymbolKind,
};
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupStatus, ExactExternalCallProof, ResolvedReferenceSite,
};
use crate::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;
use crate::analyzer::{
    IAnalyzer, ImportInfo, Language, LanguageDialect, ProjectFile, QueryToken, Range,
    RustOverlayCrates,
};
use brokk_bifrost_rust::declarations::rust_node_text;
use brokk_bifrost_rust::graph_support::{rust_path_is_leading_absolute, rust_path_segments};
use brokk_bifrost_rust::imports::rust_focused_use_path;
use brokk_bifrost_rust::prelude::rust_std_type_fact;
use tree_sitter::{Node, Tree};

/// The callee path that contains the focus, obtained from the call's AST fields.
pub(crate) fn call_path(tree: &Tree, byte: usize) -> Option<Node<'_>> {
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

/// The structured callee field that contains one resolved call-reference
/// span. The span can cover a whole chained callee such as
/// `Command::new("true").spawn`, so choose the outer call whose function
/// contains the complete span rather than the nested `Command::new` call at
/// its first byte.
pub(crate) fn call_path_for_site<'tree>(
    tree: &'tree Tree,
    site: &ResolvedReferenceSite,
) -> Option<Node<'tree>> {
    if site.focus_start_byte >= site.focus_end_byte {
        return None;
    }
    let mut node = tree
        .root_node()
        .named_descendant_for_byte_range(site.focus_start_byte, site.focus_start_byte + 1)?;
    loop {
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
            && function.start_byte() <= site.focus_start_byte
            && site.focus_end_byte <= function.end_byte()
        {
            return Some(function);
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
    operation_factory: Option<&native_points::RustDefinitionOperationFactory<'_>>,
    operation: Option<
        &mut crate::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    >,
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
    let query = BoundedReceiverQuery {
        analyzer,
        file,
        source,
        tree: Some(tree),
        site: &site,
        budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
        cancellation,
    };
    let resolution = match operation {
        Some(operation) => operation_factory
            .expect("a selected Rust operation has its factory")
            .resolve(operation, query),
        None => match operation_factory {
            Some(factory) => factory.resolve_bounded(query),
            None => native_points::resolve_rust_definition_bounded(query),
        },
    };
    if matches!(&resolution, BoundedResolution::Complete { value, .. }
        if !value.definitions.is_empty() || value.lexical_definition.is_some())
    {
        // Rust paths consult lexical bindings before the extern prelude. A
        // local module or type parameter can share a spelling with a modeled
        // crate root; the model must not override the selected resolver's
        // source-backed binding.
        return false;
    }
    if matches!(&resolution, BoundedResolution::Complete { value, .. }
        if value.status == DefinitionLookupStatus::UnresolvableImportBoundary
            && value.definitions.is_empty() && value.lexical_definition.is_none())
    {
        return true;
    }
    if analyzer
        .semantic_model_overlay()
        .as_deref()
        .and_then(|overlay| RustOverlayCrates::new(Some(overlay)).referenceable_symbol(name))
        .is_some_and(|symbol| {
            symbol.kind == crate::analyzer::semantic_model::SemanticModelSymbolKind::Module
        })
    {
        return true;
    }
    // `std`, `core`, and `alloc` are Rust's implicit extern-prelude roots.
    // The selected-context builder records these roots as declared-but-
    // unindexed external dependencies, so an incomplete point lookup for the
    // root must not make an otherwise structured external call disappear.
    // Explicit import binders were rejected above; a leading `::` was handled
    // above as well. This keeps the fallback at the root/prelude boundary and
    // does not classify arbitrary missing paths as external.
    matches!(&resolution, BoundedResolution::Complete { value, .. }
        if value.status == DefinitionLookupStatus::Incomplete
            && value.definitions.is_empty()
            && value.lexical_definition.is_none()
            && matches!(name, "alloc" | "core" | "std"))
}

#[allow(clippy::too_many_arguments)]
fn canonical_rust_external_owner_components(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    owners: &[Node<'_>],
    cancellation: Option<&CancellationToken>,
    operation_factory: Option<&native_points::RustDefinitionOperationFactory<'_>>,
    operation: Option<
        &mut crate::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    >,
) -> Vec<String> {
    let mut components = owners
        .iter()
        .map(|node| rust_node_text(*node, source).to_owned())
        .collect::<Vec<_>>();
    if components.len() != 1 {
        return components;
    }
    let root = owners[0];
    let root_text = components[0].clone();
    let site = ResolvedReferenceSite {
        path: root_text.clone(),
        text: root_text,
        range: Range {
            start_byte: root.start_byte(),
            end_byte: root.end_byte(),
            start_line: root.start_position().row + 1,
            end_line: root.end_position().row + 1,
        },
        focus_start_byte: root.start_byte(),
        focus_end_byte: root.end_byte(),
    };
    let query = BoundedReceiverQuery {
        analyzer,
        file,
        source,
        tree: Some(tree),
        site: &site,
        budget: INTERACTIVE_TYPE_LOOKUP_BUDGET,
        cancellation,
    };
    let resolution = match operation {
        Some(operation) => operation_factory
            .expect("a selected Rust operation has its factory")
            .resolve(operation, query),
        None => match operation_factory {
            Some(factory) => factory.resolve_bounded(query),
            None => native_points::resolve_rust_definition_bounded(query),
        },
    };
    let BoundedResolution::Complete { value, .. } = resolution else {
        return components;
    };
    let Some(prelude) = super::std_types::prelude_item_of(&value, "type") else {
        return components;
    };
    let Some(fact) = rust_std_type_fact(&prelude) else {
        return components;
    };
    components.clear();
    components.extend(fact.path.iter().map(|segment| (*segment).to_owned()));
    components
}

fn external_call_proof_and_identity(
    owner_components: &[String],
    member: &str,
    parameter_count: u32,
) -> (ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity) {
    (
        ExactExternalCallProof::rust_external_call(
            format!("{}::{member}", owner_components.join("::")),
            parameter_count,
        ),
        ResolverOwnedExternalCalleeIdentity::new(
            Language::Rust,
            owner_components.join("."),
            member,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_exact_rust_external_call_with_operation<'analyzer, 'factory>(
    analyzer: &'analyzer dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    receiver_facts: impl FnOnce() -> Option<Arc<super::semantic::RustReceiverTypeFacts>>,
    cancellation: Option<&CancellationToken>,
    operation_factory: Option<&'factory native_points::RustDefinitionOperationFactory<'analyzer>>,
    mut operation: Option<
        &mut crate::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            'factory,
        >,
    >,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let callee = call_path_for_site(tree, site)?;
    if callee.kind() == "field_expression" {
        if let Some(proof) = exact_rust_external_method_call_with_operation(
            analyzer,
            file,
            source,
            site,
            cancellation,
            operation_factory,
            operation.as_deref_mut(),
        ) {
            return Some(proof);
        }
        let receiver_facts = receiver_facts()?;
        return exact_rust_external_receiver_call(
            analyzer,
            source,
            tree,
            site,
            callee,
            &receiver_facts,
            cancellation,
        );
    }
    let segments = rust_path_segments(callee)?;
    let (terminal, owners) = segments.split_last()?;
    // A crate-level free function such as `tokio::spawn` has one owner
    // segment. A bare `spawn` has none and cannot establish an external crate
    // identity; focus must cover only the terminal name.
    if owners.is_empty()
        || terminal.start_byte() > site.focus_start_byte
        || site.focus_end_byte > terminal.end_byte()
    {
        return None;
    }
    // The import binder decides first, for any owner depth: `net::TcpStream::connect`
    // with `use std::net as net;` binds through the leading segment `net` (#3491).
    // A binder that proves nothing leaves the written path to the native root check.
    let file_evidence = ExternalCalleeFileEvidence::default();
    let external_site = ExternalCalleeSite {
        source,
        tree,
        callee_start_byte: site.focus_start_byte,
        file_evidence: &file_evidence,
    };
    if let Some(imported) = super::expand_rust_imported_external_callee_with_operation(
        analyzer,
        file,
        "",
        Some(&external_site),
        operation_factory,
        operation.as_deref_mut(),
    ) {
        return Some((
            imported.exact_external_call?,
            imported.external_callee_identity?,
        ));
    }
    let root = owners.first()?;
    if !native_external_root(
        analyzer,
        token,
        file,
        source,
        tree,
        *root,
        cancellation,
        operation_factory,
        operation.as_deref_mut(),
    ) {
        return None;
    }
    let parameter_count = rust_call_written_arity(tree, callee.start_byte())?;
    let owner_components = canonical_rust_external_owner_components(
        analyzer,
        file,
        source,
        tree,
        owners,
        cancellation,
        operation_factory,
        operation,
    );
    let member = rust_node_text(*terminal, source);
    let declared =
        rust_external_callable_declaration(analyzer, &owner_components, member, parameter_count);
    if !rust_external_identity_is_unmodeled_std_path(
        analyzer,
        rust_node_text(*root, source),
        &owner_components,
        member,
    ) && !declared
    {
        return None;
    }
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return None;
    }
    Some(external_call_proof_and_identity(
        &owner_components,
        member,
        parameter_count,
    ))
}

fn exact_rust_external_receiver_call(
    analyzer: &dyn IAnalyzer,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    callee: Node<'_>,
    receiver_facts: &super::semantic::RustReceiverTypeFacts,
    cancellation: Option<&CancellationToken>,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let receiver = callee.child_by_field_name("value")?;
    let member_node = callee.child_by_field_name("field")?;
    if site.focus_start_byte < callee.start_byte()
        || site.focus_end_byte > callee.end_byte()
        || site.focus_start_byte > member_node.start_byte()
        || member_node.end_byte() > site.focus_end_byte
        || cancellation.is_some_and(CancellationToken::is_cancelled)
    {
        return None;
    }
    let member = rust_node_text(member_node, source);
    let parameter_count = rust_call_written_arity(tree, member_node.start_byte())?;
    let overlay = analyzer.semantic_model_overlay()?;
    let owner = receiver_facts.owner_of_expression(source, tree, receiver, &overlay)?;
    if !rust_external_bound_receiver_callable_declaration(&overlay, &owner, member, parameter_count)
        || cancellation.is_some_and(CancellationToken::is_cancelled)
    {
        return None;
    }
    Some((
        ExactExternalCallProof::rust_bound_external_member(&owner, member, parameter_count),
        ResolverOwnedExternalCalleeIdentity::new(Language::Rust, owner, member),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn rust_import_binder_external_callee(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    site: &ExternalCalleeSite<'_>,
    import: &ImportInfo,
    member: &str,
    owner_components: &[String],
    operation_factory: Option<&native_points::RustDefinitionOperationFactory<'_>>,
    operation: Option<
        &mut crate::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    >,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let source = site.source;
    let tree = site.tree;
    let path = import.path.as_ref()?;
    if path.segments.len() < 2 {
        return None;
    }
    let parameter_count = rust_call_written_arity(tree, site.callee_start_byte)?;
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
        || !native_external_root(
            analyzer,
            token,
            file,
            source,
            tree,
            written.root,
            None,
            operation_factory,
            operation,
        )
        || (!rust_external_identity_is_unmodeled_std_path(
            analyzer,
            rust_node_text(written.root, source),
            owner_components,
            member,
        ) && !rust_external_callable_declaration(
            analyzer,
            owner_components,
            member,
            parameter_count,
        ))
    {
        return None;
    }
    Some(external_call_proof_and_identity(
        owner_components,
        member,
        parameter_count,
    ))
}

/// An exact external identity for the Rust method call whose method name the
/// focus spans, `receiver.member(args)`, when the resolver concluded that no
/// workspace declaration answers it (#3757).
///
/// The receiver's type comes from its written structure through built-in
/// reference dereferences only: a `&str`, a binding of a reviewed std prelude
/// type, or a binding of a `use`-imported external type
/// ([`super::std_types::rust_method_receiver_owner`]). The activated model must
/// declare that owner and one externally visible instance member at the
/// written arity. A concrete Rust receiver type dispatches statically, so the
/// selected member is closed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn exact_rust_external_method_call_with_operation<'analyzer, 'factory>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    cancellation: Option<&CancellationToken>,
    operation_factory: Option<&'factory native_points::RustDefinitionOperationFactory<'analyzer>>,
    operation: Option<
        &mut crate::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            'factory,
        >,
    >,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let method = site.focus_start_byte..site.focus_end_byte;
    let (owner, arity) = match operation {
        Some(operation) => super::std_types::rust_method_receiver_owner_with_operation(
            analyzer,
            file,
            source,
            method,
            operation_factory.expect("a selected Rust operation has its factory"),
            operation,
            cancellation,
        ),
        None => super::std_types::rust_method_receiver_owner(analyzer, file, source, method),
    }?;
    let member = source.get(site.focus_start_byte..site.focus_end_byte)?;
    let owner = owner.key();
    let parameter_count = u32::try_from(arity).ok()?;
    if !rust_external_callable_declared(analyzer, &owner, member, true, parameter_count)
        || cancellation.is_some_and(CancellationToken::is_cancelled)
    {
        return None;
    }
    Some((
        ExactExternalCallProof::rust_bound_external_member(&owner, member, parameter_count),
        ResolverOwnedExternalCalleeIdentity::new(Language::Rust, owner, member),
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
    let owner = RustOverlayCrates::pack_name(owner_components);
    let Some(owner_symbol) = RustOverlayCrates::new(Some(&overlay)).referenceable_symbol(&owner)
    else {
        return false;
    };
    if !matches!(
        owner_symbol.kind,
        SemanticModelSymbolKind::Module
            | SemanticModelSymbolKind::Struct
            | SemanticModelSymbolKind::Enum
            | SemanticModelSymbolKind::Union
    ) {
        return false;
    }
    let Some(callable) =
        rust_external_callable_match_with_overlay(&overlay, &owner, member, parameter_count, false)
    else {
        return false;
    };
    match callable.disposition {
        SemanticModelCallableDisposition::Unique => true,
        SemanticModelCallableDisposition::CompatibleLayout => {
            callable.callable_family_id().is_some()
        }
        _ => false,
    }
}

/// A std/core/alloc extern-prelude path can supply an identity without an
/// activated callable declaration only when no active model speaks to that
/// exact owner/member surface. Any declaration row, extraction gap, or
/// receiverless summary leaves the declaration gate in control, including
/// conflicts, private members, and incomplete overload sets.
fn rust_external_identity_is_unmodeled_std_path(
    analyzer: &dyn IAnalyzer,
    root: &str,
    owner_components: &[String],
    member: &str,
) -> bool {
    if !matches!(root, "alloc" | "core" | "std") {
        return false;
    }
    let owner = RustOverlayCrates::pack_name(owner_components);
    let language = LanguageDialect::from(Language::Rust).semantic_pack_label();
    if analyzer.active_semantic_models().is_some_and(|active| {
        active.has_receiverless_procedure_summary_member(language, &owner, member)
            || active.gapped_member_surface(&owner, member).is_some()
    }) {
        return false;
    }
    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return true;
    };
    let member_name = format!("{owner}.{member}");
    let owner_is_declared = overlay
        .symbols_named(&owner)
        .records
        .into_iter()
        .any(|symbol| symbol.language == language && symbol.qualified_name == owner);
    let member_is_declared = overlay
        .symbols_named(&member_name)
        .records
        .into_iter()
        .any(|symbol| symbol.language == language && symbol.qualified_name == member_name);
    !owner_is_declared && !member_is_declared
}

fn rust_external_callable_declared(
    analyzer: &dyn IAnalyzer,
    owner: &str,
    member: &str,
    has_receiver: bool,
    parameter_count: u32,
) -> bool {
    let Some(overlay) = analyzer.semantic_model_overlay() else {
        return false;
    };
    let Some(callable) = rust_external_callable_match_with_overlay(
        &overlay,
        owner,
        member,
        parameter_count,
        has_receiver,
    ) else {
        return false;
    };
    match callable.disposition {
        SemanticModelCallableDisposition::Unique => true,
        // Several applicable overloads that share one binding layout still
        // leave the overload identity unresolved. That is exact callable
        // evidence only while the activated model certifies the whole family.
        SemanticModelCallableDisposition::CompatibleLayout => {
            callable.callable_family_id().is_some()
        }
        _ => false,
    }
}

fn rust_external_bound_receiver_callable_declaration(
    overlay: &crate::analyzer::semantic_model::SemanticModelOverlay,
    owner: &str,
    member: &str,
    parameter_count: u32,
) -> bool {
    let Some(callable) =
        rust_external_callable_match_with_overlay(overlay, owner, member, parameter_count, true)
    else {
        return false;
    };
    if callable.disposition != SemanticModelCallableDisposition::Unique {
        return false;
    }
    let [callable] = callable.records.as_slice() else {
        return false;
    };
    callable.externally_visible()
        && !callable.provenance.ambiguous
        && callable.provenance.completeness
            == crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
}

fn rust_external_callable_match_with_overlay<'a>(
    overlay: &'a crate::analyzer::semantic_model::SemanticModelOverlay,
    owner: &str,
    member: &str,
    parameter_count: u32,
    has_receiver: bool,
) -> Option<SemanticModelCallableMatch<'a>> {
    RustOverlayCrates::new(Some(overlay)).referenceable_symbol(owner)?;
    let callable = overlay.callable_for_application(
        SemanticModelCallableKey::new(
            Language::Rust.config_label(),
            owner,
            member,
            has_receiver,
            parameter_count,
        ),
        &SemanticModelCallApplication::positional(parameter_count),
    );
    // A private or crate-visible member of a public owner is not an external API.
    callable
        .records
        .iter()
        .all(|record| record.externally_visible())
        .then_some(callable)
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
