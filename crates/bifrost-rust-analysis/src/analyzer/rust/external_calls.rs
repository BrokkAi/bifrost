//! External callable evidence from native scope authority and activated models.

use std::sync::Arc;

use crate::analyzer::rust::native_points;

use crate::analyzer::rust::rust_import_binder_visible_at_byte;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::languages::ExternalCalleeFileEvidence;

use brokk_bifrost_analysis::analyzer::languages::ExternalCalleeSite;

use crate::analyzer::semantic_model::{
    SemanticModelCallApplication, SemanticModelCallableDisposition, SemanticModelCallableKey,
    SemanticModelCallableMatch, SemanticModelSymbolKind,
};
use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity;

use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

use brokk_bifrost_analysis::analyzer::usages::get_definition::UnindexedClaimKind;

use brokk_bifrost_core::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::ImportInfo;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::LanguageDialect;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::query_token::QueryToken;

use brokk_bifrost_core::analyzer::model::Range;

use crate::analyzer::RustOverlayCrates;
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
        &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    >,
) -> bool {
    native_external_root_with_resolver(
        analyzer,
        token,
        file,
        source,
        tree,
        root,
        cancellation,
        |query| match operation {
            Some(operation) => operation_factory
                .expect("a selected Rust operation has its factory")
                .resolve(operation, query),
            None => match operation_factory {
                Some(factory) => factory.resolve_bounded(query),
                None => native_points::resolve_rust_definition_bounded(query),
            },
        },
    )
}

/// The shared external-crate root rule, including visible import binders and
/// selected resolver evidence. Receiver type proofs supply the same operation
/// that proved the nominal head rather than opening an unrelated lookup.
#[allow(clippy::too_many_arguments)]
pub(crate) fn native_external_root_with_resolver(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    root: Node<'_>,
    cancellation: Option<&CancellationToken>,
    resolve: impl FnOnce(BoundedReceiverQuery<'_>) -> BoundedResolution<DefinitionLookupOutcome>,
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
            if !import.is_wildcard
                && import.local_name() == Some(name)
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
    let resolution = resolve(query);
    crate::analyzer::rust::std_types::observe_proof_resolution(&resolution);
    if !matches!(&resolution, BoundedResolution::Complete { .. }) {
        return false;
    }
    if matches!(&resolution, BoundedResolution::Complete { value, .. }
        if value.status == DefinitionLookupStatus::Ambiguous
            || !value.definitions.is_empty() || value.lexical_definition.is_some())
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
        &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    >,
) -> Vec<String> {
    let components = owners
        .iter()
        .map(|node| rust_node_text(*node, source).to_owned())
        .collect::<Vec<_>>();
    let Some(root) = owners.first().copied() else {
        return components;
    };
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
    crate::analyzer::rust::std_types::observe_proof_resolution(&resolution);
    let BoundedResolution::Complete { value, .. } = resolution else {
        return components;
    };
    if let Some(prelude) = crate::analyzer::rust::std_types::prelude_item_of(&value, "type")
        && let Some(fact) = rust_std_type_fact(&prelude)
    {
        return fact
            .path
            .iter()
            .map(|segment| (*segment).to_owned())
            .chain(components.iter().skip(1).cloned())
            .collect();
    }
    if let Some((crate_name, name)) =
        crate::analyzer::rust::std_types::prelude_item_identity_of(&value, "type")
        && let Some(module) = brokk_bifrost_rust::prelude::rust_prelude_trait_module(&name)
    {
        return [crate_name, module.to_owned(), name]
            .into_iter()
            .chain(components.iter().skip(1).cloned())
            .collect();
    }
    if value.status == DefinitionLookupStatus::UnresolvableImportBoundary
        && value.definitions.is_empty()
        && value.lexical_definition.is_none()
    {
        let subjects = value
            .diagnostics
            .iter()
            .filter_map(|diagnostic| diagnostic.claim.as_ref())
            .filter(|claim| claim.kind == UnindexedClaimKind::ExternalBoundary)
            .flat_map(|claim| claim.subjects.iter())
            .collect::<Vec<_>>();
        if let [subject] = subjects.as_slice() {
            // This dotted identity belongs to the resolver, not source syntax.
            return subject
                .split('.')
                .map(str::to_owned)
                .chain(components.iter().skip(1).cloned())
                .collect();
        }
    }
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
pub(crate) fn resolve_exact_rust_external_call_with_operation<'analyzer, 'factory, 'selection>(
    analyzer: &'analyzer dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    receiver_facts: impl FnOnce() -> Option<Arc<crate::analyzer::rust::semantic::RustReceiverTypeFacts>>,
    cancellation: Option<&CancellationToken>,
    operation_factory: Option<&'factory native_points::RustDefinitionOperationFactory<'analyzer>>,
    mut operation: Option<
        &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            'selection,
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
            file,
            source,
            tree,
            site,
            callee,
            &receiver_facts,
            cancellation,
            operation_factory,
            operation,
        );
    }
    if let Some(proof) = exact_rust_external_type_call_with_operation(
        analyzer,
        file,
        source,
        tree,
        site,
        operation_factory,
        operation.as_deref_mut(),
    ) {
        return Some(proof);
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
    if let Some(imported) =
        crate::analyzer::rust::expand_rust_imported_external_callee_with_operation(
            analyzer,
            file,
            "",
            Some(&external_site),
            operation_factory,
            operation.as_deref_mut(),
        )
    {
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

/// Select a member written through a proven nominal type, such as
/// String::from(x), or a structurally normalized UFCS trait call.
#[allow(clippy::too_many_arguments)]
pub(crate) fn exact_rust_external_type_call_with_operation<'analyzer>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    factory: Option<&native_points::RustDefinitionOperationFactory<'analyzer>>,
    mut operation: Option<
        &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            '_,
        >,
    >,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let callee = call_path_for_site(tree, site)?;
    let terminal = callee.child_by_field_name("name")?;
    let mut qualifier = callee.child_by_field_name("path")?;
    let mut trait_node = None;
    if qualifier.kind() == "bracketed_type" {
        qualifier = qualifier.named_child(0)?;
        if qualifier.kind() == "qualified_type" {
            trait_node = Some(qualifier.child_by_field_name("alias")?);
            qualifier = qualifier.child_by_field_name("type")?;
        }
    }
    let overlay = analyzer.semantic_model_overlay()?;
    let resolve_owner = |node: Node<'_>,
                         mut operation: Option<
        &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            '_,
        >,
    >| {
        let owners = rust_path_segments(node)?;
        let root = *owners.first()?;
        let components = canonical_rust_external_owner_components(
            analyzer,
            file,
            source,
            tree,
            &owners,
            None,
            factory,
            operation.as_deref_mut(),
        );
        let scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(analyzer);
        let token = brokk_bifrost_core::analyzer::query_token::QueryScope::token(&scope);
        let written = owners
            .iter()
            .map(|node| rust_node_text(*node, source))
            .collect::<Vec<_>>();
        // Native canonicalization changes the route only after selected
        // prelude/import evidence. Otherwise the external root must prove it.
        if components.iter().map(String::as_str).eq(written)
            && !native_external_root(
                analyzer, token, file, source, tree, root, None, factory, operation,
            )
        {
            return None;
        }
        let owner = components.join(".");
        let symbol = RustOverlayCrates::new(Some(&overlay)).referenceable_symbol(&owner)?;
        if symbol.kind != SemanticModelSymbolKind::Trait {
            if node.kind() == "generic_type" {
                return None;
            }
            let active = analyzer.active_semantic_models()?;
            let declarations = active.types_with_id(&symbol.id);
            if declarations.records.is_empty()
                || declarations
                    .records
                    .iter()
                    .any(|declaration| !declaration.record.type_parameters.is_empty())
            {
                return None;
            }
        }
        Some(symbol.qualified_name.clone())
    };
    let mut owner = crate::analyzer::rust::std_types::rust_nominal_receiver_owner_with_operation(
        analyzer,
        file,
        source,
        qualifier,
        factory,
        operation.as_deref_mut(),
        None,
    )
    .or_else(|| resolve_owner(qualifier, operation.as_deref_mut()))?;
    let mut symbol = RustOverlayCrates::new(Some(&overlay)).referenceable_symbol(&owner)?;
    // A bare/imported trait path fixes the trait, while its explicit self
    // supplies the implementing type. A bracketed type fixes that type itself.
    if trait_node.is_none() && symbol.kind == SemanticModelSymbolKind::Trait {
        trait_node = Some(qualifier);
    }
    let constraint = if let Some(node) = trait_node {
        let trait_owner = resolve_owner(node, operation.as_deref_mut())?;
        let symbol = RustOverlayCrates::new(Some(&overlay)).referenceable_symbol(&trait_owner)?;
        if symbol.kind != SemanticModelSymbolKind::Trait {
            return None;
        }
        let arguments = node.child_by_field_name("type_arguments").map(|arguments| {
            let mut cursor = arguments.walk();
            arguments.named_children(&mut cursor).collect::<Vec<_>>()
        });
        Some(crate::analyzer::rust::modeled_members::UfcsTrait {
            owner: trait_owner,
            arguments,
        })
    } else {
        None
    };
    if symbol.kind == SemanticModelSymbolKind::Trait {
        let member = rust_node_text(terminal, source);
        let members = overlay
            .members_of(&symbol.id)
            .records
            .into_iter()
            .filter(|record| {
                record.name == member
                    && crate::analyzer::semantic_model::symbol_kind_is_callable(record.kind)
            })
            .collect::<Vec<_>>();
        // A receiverless trait function has no self actual from which to
        // infer its implementing type. Keep that missing type structured.
        if members.is_empty() || members.iter().any(|record| !record.has_receiver()) {
            return None;
        }
        let call = callee
            .parent()
            .filter(|node| node.kind() == "call_expression")?;
        let actual = call.child_by_field_name("arguments")?.named_child(0)?;
        owner = crate::analyzer::rust::semantic::RustReceiverTypeFacts::from_tree(source, tree)
            .owner_of_expression(source, tree, actual, &overlay, &mut |ty| {
                crate::analyzer::rust::std_types::rust_nominal_receiver_owner_with_operation(
                    analyzer,
                    file,
                    source,
                    ty,
                    factory,
                    operation.as_deref_mut(),
                    None,
                )
            })?;
        symbol = RustOverlayCrates::new(Some(&overlay)).referenceable_symbol(&owner)?;
    }
    if !matches!(
        symbol.kind,
        SemanticModelSymbolKind::Struct
            | SemanticModelSymbolKind::Enum
            | SemanticModelSymbolKind::Union
    ) {
        return None;
    }
    let arity = rust_call_written_arity(tree, terminal.start_byte())?;
    let mut selected = None;
    for has_receiver in [false, true] {
        let Some(parameter_count) = arity.checked_sub(u32::from(has_receiver)) else {
            continue;
        };
        if let Some(declaring) = crate::analyzer::rust::modeled_members::select(
            analyzer,
            file,
            source,
            site,
            &owner,
            has_receiver,
            parameter_count,
            factory,
            operation.as_deref_mut(),
            constraint.as_ref(),
            None,
        ) {
            if selected.is_some() {
                return None;
            }
            selected = Some((declaring, has_receiver, parameter_count));
        }
    }
    let (declaring_owner, has_receiver, parameter_count) = selected?;
    if has_receiver {
        let actual = callee
            .parent()?
            .child_by_field_name("arguments")?
            .named_child(0)?;
        let actual_owner =
            crate::analyzer::rust::semantic::RustReceiverTypeFacts::from_tree(source, tree)
                .owner_of_expression(source, tree, actual, &overlay, &mut |ty| {
                    crate::analyzer::rust::std_types::rust_nominal_receiver_owner_with_operation(
                        analyzer,
                        file,
                        source,
                        ty,
                        factory,
                        operation.as_deref_mut(),
                        None,
                    )
                })?;
        if actual_owner != owner {
            return None;
        }
    }
    let owner = &declaring_owner.owner;
    let member = rust_node_text(terminal, source);
    let proof = if has_receiver {
        declaring_owner.proof(member, parameter_count)
    } else {
        ExactExternalCallProof::rust_external_call(
            format!("{}::{member}", owner.replace('.', "::")),
            parameter_count,
        )
    };
    Some((
        proof,
        ResolverOwnedExternalCalleeIdentity::new(Language::Rust, declaring_owner.owner, member),
    ))
}

#[allow(clippy::too_many_arguments)]
fn exact_rust_external_receiver_call<'analyzer>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    callee: Node<'_>,
    receiver_facts: &crate::analyzer::rust::semantic::RustReceiverTypeFacts,
    cancellation: Option<&CancellationToken>,
    operation_factory: Option<&native_points::RustDefinitionOperationFactory<'analyzer>>,
    mut operation: Option<
        &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            '_,
        >,
    >,
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
    let owner =
        receiver_facts.owner_of_expression(source, tree, receiver, &overlay, &mut |ty| {
            crate::analyzer::rust::std_types::rust_nominal_receiver_owner_with_operation(
                analyzer,
                file,
                source,
                ty,
                operation_factory,
                operation.as_deref_mut(),
                cancellation,
            )
        })?;
    let owner = crate::analyzer::rust::modeled_members::select(
        analyzer,
        file,
        source,
        site,
        &owner,
        true,
        parameter_count,
        operation_factory,
        operation,
        None,
        None,
    )?;
    if !rust_external_bound_receiver_callable_declaration(
        &overlay,
        &owner.owner,
        member,
        parameter_count,
    ) || cancellation.is_some_and(CancellationToken::is_cancelled)
    {
        return None;
    }
    Some((
        owner.proof(member, parameter_count),
        ResolverOwnedExternalCalleeIdentity::new(Language::Rust, owner.owner, member),
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
        &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    >,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let source = site.source;
    let tree = site.tree;
    let path = import.path.as_ref()?;
    if path.segments.len() < 2 {
        return None;
    }
    let parameter_count = rust_call_written_arity(tree, site.callee_start_byte)?;
    let (written, _) = import_path_in_tree(import, tree, source)?;
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

/// The parser-backed route of one import binder, shared by member selection
/// and exact imported-call proof. The returned focus names the imported
/// declaration (or glob namespace), including when its binder is renamed.
pub(crate) fn import_path_in_tree<'tree>(
    import: &ImportInfo,
    tree: &'tree Tree,
    source: &str,
) -> Option<(
    brokk_bifrost_rust::imports::RustFocusedUsePath<'tree>,
    Node<'tree>,
)> {
    if import.is_wildcard {
        let path = import.path.as_ref()?;
        let declaration = tree.root_node().named_descendant_for_byte_range(
            path.declaration_start_byte,
            path.declaration_start_byte + 1,
        )?;
        let mut pending = vec![declaration];
        while let Some(node) = pending.pop() {
            if node.kind() == "use_wildcard" {
                let focused = node
                    .child_by_field_name("path")
                    .or_else(|| node.named_child(0))
                    .or_else(|| node.parent()?.child_by_field_name("path"));
                if let Some(focused) = focused
                    && let Some(written) = rust_focused_use_path(focused, source)
                    && written.segments == path.segments
                {
                    let terminal = *rust_path_segments(focused)?.last()?;
                    return Some((written, terminal));
                }
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
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
    let terminal = *rust_path_segments(focused)?.last()?;
    Some((written, terminal))
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
pub(crate) fn exact_rust_external_method_call_with_operation<'analyzer, 'factory, 'selection>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    cancellation: Option<&CancellationToken>,
    operation_factory: Option<&'factory native_points::RustDefinitionOperationFactory<'analyzer>>,
    operation: Option<
        &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            'selection,
        >,
    >,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    exact_rust_external_method_call_attempt_with_operation(
        analyzer,
        file,
        source,
        site,
        cancellation,
        operation_factory,
        operation,
    )
    .into_value()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn exact_rust_external_method_call_attempt_with_operation<
    'analyzer,
    'factory,
    'selection,
>(
    analyzer: &'analyzer dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    cancellation: Option<&CancellationToken>,
    operation_factory: Option<&'factory native_points::RustDefinitionOperationFactory<'analyzer>>,
    mut operation: Option<
        &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<
            'analyzer,
            'selection,
        >,
    >,
) -> crate::analyzer::rust::std_types::RustProofAttempt<(
    ExactExternalCallProof,
    ResolverOwnedExternalCalleeIdentity,
)> {
    crate::analyzer::rust::std_types::completed_proof(cancellation, || {
        let method = site.focus_start_byte..site.focus_end_byte;
        let (owner, arity) = match operation.as_deref_mut() {
            Some(operation) => {
                crate::analyzer::rust::std_types::rust_method_receiver_owner_with_operation(
                    analyzer,
                    file,
                    source,
                    method,
                    operation_factory.expect("a selected Rust operation has its factory"),
                    operation,
                    cancellation,
                )
            }
            None => crate::analyzer::rust::std_types::rust_method_receiver_owner(
                analyzer, file, source, method,
            ),
        }?;
        let member = source.get(site.focus_start_byte..site.focus_end_byte)?;
        let owner = owner.key();
        let parameter_count = u32::try_from(arity).ok()?;
        let owner = crate::analyzer::rust::modeled_members::select(
            analyzer,
            file,
            source,
            site,
            &owner,
            true,
            parameter_count,
            operation_factory,
            operation,
            None,
            None,
        )?;
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        Some((
            owner.proof(member, parameter_count),
            ResolverOwnedExternalCalleeIdentity::new(Language::Rust, owner.owner, member),
        ))
    })
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

fn rust_external_bound_receiver_callable_declaration(
    overlay: &brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay,
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
    callable.externally_visible() && !callable.provenance.ambiguous
}

fn rust_external_callable_match_with_overlay(
    overlay: &brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay,
    owner: &str,
    member: &str,
    parameter_count: u32,
    has_receiver: bool,
) -> Option<SemanticModelCallableMatch> {
    let owner = RustOverlayCrates::new(Some(overlay)).referenceable_symbol(owner)?;
    let callable = overlay.callable_for_application(
        SemanticModelCallableKey::new(
            Language::Rust.config_label(),
            &owner.qualified_name,
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
