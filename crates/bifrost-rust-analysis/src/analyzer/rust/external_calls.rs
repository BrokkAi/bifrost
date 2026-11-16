//! External callable evidence from native scope authority and activated models.

use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_rows::RustAbsoluteRoot;
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use std::sync::Arc;

use crate::analyzer::rust::native_points;

use crate::analyzer::rust::rust_import_binder_visible_at_byte;

use brokk_bifrost_core::cancellation::CancellationToken;

use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

use brokk_bifrost_analysis::analyzer::languages::ExternalCalleeFileEvidence;

use brokk_bifrost_analysis::analyzer::languages::ExternalCalleeSite;

use crate::analyzer::semantic_model::{
    SemanticModelCallApplication, SemanticModelCallableDisposition, SemanticModelCallableKey,
    SemanticModelCallableMatch, SemanticModelMemberTargetDisposition, SemanticModelSymbolKind,
};
use brokk_bifrost_analysis::analyzer::semantic::oracle::dispatch::ResolverOwnedExternalCalleeIdentity;
use brokk_bifrost_analysis::analyzer::semantic_model::overlay::{
    RustReexportLookup, RustReexportNamespace,
};

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
    _token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    root: Node<'_>,
    cancellation: Option<&CancellationToken>,
    imports: Option<&[ImportInfo]>,
    operation_factory: &native_points::RustDefinitionOperationFactory<'_>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
) -> bool {
    if rust_path_is_leading_absolute(root) {
        // The root of a written `use ::std::str` path is the scoped identifier
        // `::std`; the extern name is its `name` field. A call path's root is
        // already that identifier.
        let head = root.child_by_field_name("name").unwrap_or(root);
        match selected_absolute_root(
            analyzer,
            operation,
            file,
            rust_node_text(head, source),
            ResolutionNamespace::Type,
            cancellation,
        ) {
            Some(RustAbsoluteRoot::External(_)) => return true,
            Some(RustAbsoluteRoot::Indexed { .. } | RustAbsoluteRoot::CrateRootImport { .. }) => {}
            Some(RustAbsoluteRoot::Unavailable { .. }) | None => return false,
        }
    }
    let selected_imports;
    let imports = if let Some(imports) = imports {
        imports
    } else {
        let cancellation = cancellation.cloned().unwrap_or_default();
        let Some(imports) = crate::analyzer::rust::std_types::selected_import_infos(
            analyzer,
            operation,
            file,
            &cancellation,
        ) else {
            return false;
        };
        selected_imports = imports;
        &selected_imports
    };
    native_external_root_with_resolver(
        analyzer,
        file,
        source,
        tree,
        root,
        cancellation,
        imports,
        |query| operation_factory.resolve(operation, query),
    )
}

/// The shared external-crate root rule, including visible import binders and
/// selected resolver evidence. Receiver type proofs supply the same operation
/// that proved the nominal head rather than opening an unrelated lookup.
#[allow(clippy::too_many_arguments)]
pub(crate) fn native_external_root_with_resolver(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    root: Node<'_>,
    cancellation: Option<&CancellationToken>,
    imports: &[ImportInfo],
    resolve: impl FnOnce(BoundedReceiverQuery<'_>) -> BoundedResolution<DefinitionLookupOutcome>,
) -> bool {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return false;
    }
    let name = rust_node_text(root, source);
    if matches!(name, "crate" | "self" | "super") {
        return false;
    }
    {
        for import in imports {
            if !import.is_wildcard
                && import.local_name() == Some(name)
                && import.path.as_ref().is_some_and(|path| {
                    rust_import_binder_visible_at_byte(path, root.start_byte(), tree)
                })
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
        .semantic_model_overlay_read()
        .published()
        .as_deref()
        .and_then(|overlay| RustOverlayCrates::new(Some(overlay)).referenceable_owner(name))
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
    // does not classify arbitrary missing paths as external. A point
    // operation that could not answer (`native_unavailable`, for example a
    // resolved declaration that has no definition unit) reports Incomplete
    // too, but its target may be a local item spelled `std`, so it never
    // certifies the root.
    matches!(&resolution, BoundedResolution::Complete { value, .. }
        if value.status == DefinitionLookupStatus::Incomplete
            && value.definitions.is_empty()
            && value.lexical_definition.is_none()
            && !value.diagnostics.iter().any(|diagnostic| diagnostic.kind == "native_unavailable")
            && matches!(name, "alloc" | "core" | "std"))
}

pub(super) fn selected_absolute_root(
    analyzer: &dyn IAnalyzer,
    operation: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    file: &ProjectFile,
    name: &str,
    namespace: ResolutionNamespace,
    cancellation: Option<&CancellationToken>,
) -> Option<RustAbsoluteRoot> {
    selected_absolute_root_with_files(analyzer, operation, file, name, namespace, cancellation)
        .map(|(answer, _)| answer)
}

fn selected_absolute_root_with_files(
    analyzer: &dyn IAnalyzer,
    operation: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    file: &ProjectFile,
    name: &str,
    namespace: ResolutionNamespace,
    cancellation: Option<&CancellationToken>,
) -> Option<(RustAbsoluteRoot, Vec<ProjectFile>)> {
    let rust = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
        crate::analyzer::rust::RustAnalyzer,
    >(analyzer)
    .expect("Rust proof requires Rust analyzer");
    // Route derivations record Cargo configuration (including edition), target
    // membership and dependency names. Bind the lookup to this exact selection.
    let _frame = match rust.operation_read_frame(operation) {
        Ok(frame) => frame,
        Err(error) => {
            rust.inner.record_store_error(error);
            crate::analyzer::rust::std_types::operational_proof_stop(
                "absolute root route frame unavailable",
                brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause::Provider,
            );
            return None;
        }
    };
    let keep_going = || !cancellation.is_some_and(CancellationToken::is_cancelled);
    let roots = match rust.file_routes(file, Some(&keep_going)) {
        Ok(routes) => {
            let roots = routes.target_roots(file);
            if !routes.is_complete() {
                crate::analyzer::rust::std_types::operational_proof_stop(
                    "absolute root routes incomplete",
                    brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause::Provider,
                );
            }
            // No Cargo target reaches a detached file; it is its own crate root,
            // and the complete routes just read prove that no target does.
            let import_files = if roots.is_empty() {
                std::slice::from_ref(file)
            } else {
                roots.as_slice()
            };
            for root in import_files {
                // The source key covers extern-crate binders and no_std, even
                // when the import list itself is empty.
                crate::analyzer::rust::std_types::selected_import_infos(
                    analyzer,
                    operation,
                    root,
                    &cancellation.cloned().unwrap_or_default(),
                )?;
            }
            roots
        }
        Err(error) => {
            crate::analyzer::rust::std_types::operational_proof_stop(
                "absolute root routes unavailable",
                crate::analyzer::rust::std_types::cargo_route_execution_cause(&error),
            );
            return None;
        }
    };
    let answer = match operation.rust_absolute_root(
        file,
        name,
        namespace,
        &cancellation.cloned().unwrap_or_default(),
    ) {
        Ok(answer) => answer,
        Err(error) => {
            let rust = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
                crate::analyzer::rust::RustAnalyzer,
            >(analyzer)
            .expect("Rust proof requires Rust analyzer");
            rust.inner.record_store_error(error);
            crate::analyzer::rust::std_types::operational_proof_stop(
                "absolute root store unavailable",
                brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause::Provider,
            );
            return None;
        }
    };
    if let RustAbsoluteRoot::Unavailable { reason, .. } = &answer {
        // Provider until certified (#11510): an unavailable absolute root is
        // refused for retention even when the store marks it content-determined,
        // because no read-closure proof covers that decision yet.
        crate::analyzer::rust::std_types::operational_proof_stop(
            reason,
            brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause::Provider,
        );
    }
    Some((answer, roots))
}

pub(crate) fn absolute_external_components(
    analyzer: &dyn IAnalyzer,
    operation: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    file: &ProjectFile,
    name: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<Vec<String>> {
    match selected_absolute_root(
        analyzer,
        operation,
        file,
        name,
        ResolutionNamespace::Type,
        cancellation,
    )? {
        RustAbsoluteRoot::External(path) => Some(path),
        RustAbsoluteRoot::Indexed { .. }
        | RustAbsoluteRoot::CrateRootImport { .. }
        | RustAbsoluteRoot::Unavailable { .. } => None,
    }
}

fn canonical_absolute_owner(
    analyzer: &dyn IAnalyzer,
    operation: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    file: &ProjectFile,
    head: &str,
    remaining: impl Iterator<Item = String>,
    cancellation: Option<&CancellationToken>,
) -> Option<Vec<String>> {
    Some(
        absolute_external_components(analyzer, operation, file, head, cancellation)?
            .into_iter()
            .chain(remaining)
            .collect(),
    )
}

/// The crate root file whose active top-level `use` binds the leading-`::`
/// head `name` (edition 2015), when the selected absolute root says one does.
///
/// Edition 2015 resolves `::name` in the crate root module, so the binder is a
/// top-level `use` of the crate root file, wherever the call is written. A
/// file that several Cargo targets hold has several roots; they are not
/// proven to agree, so that answer is refused and recorded as a stop rather
/// than dropped.
pub(crate) fn crate_root_import_file(
    analyzer: &dyn IAnalyzer,
    operation: &brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    file: &ProjectFile,
    name: &str,
    namespace: ResolutionNamespace,
    cancellation: Option<&CancellationToken>,
) -> Option<ProjectFile> {
    // Keep the route-derived files together with the absolute-root proof. No
    // second lookup may outlive the selected read frame that certified them.
    let (answer, roots) = selected_absolute_root_with_files(
        analyzer,
        operation,
        file,
        name,
        namespace,
        cancellation,
    )?;
    if !matches!(answer, RustAbsoluteRoot::CrateRootImport { .. }) {
        return None;
    }
    match roots.as_slice() {
        [root] => Some(root.clone()),
        _ => {
            crate::analyzer::rust::std_types::operational_proof_stop(
                "crate-root import has no single crate root",
                brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause::Provider,
            );
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn canonical_rust_external_owner_components(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    owners: &[Node<'_>],
    cancellation: Option<&CancellationToken>,
    operation_factory: &native_points::RustDefinitionOperationFactory<'_>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
) -> Vec<String> {
    if let Some(root) = owners
        .first()
        .filter(|root| rust_path_is_leading_absolute(**root))
    {
        let head = root.child_by_field_name("name").unwrap_or(*root);
        if let Some(owner) = canonical_absolute_owner(
            analyzer,
            operation,
            file,
            rust_node_text(head, source),
            owners
                .iter()
                .skip(1)
                .map(|node| rust_node_text(*node, source).to_owned()),
            cancellation,
        ) {
            return owner;
        }
    }

    canonical_rust_external_owner_components_with_resolver(
        analyzer,
        file,
        source,
        tree,
        owners,
        cancellation,
        |query| operation_factory.resolve(operation, query),
    )
}

pub(crate) fn canonical_rust_external_owner_components_with_resolver(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    owners: &[Node<'_>],
    cancellation: Option<&CancellationToken>,
    resolve: impl FnOnce(BoundedReceiverQuery<'_>) -> BoundedResolution<DefinitionLookupOutcome>,
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
    let resolution = resolve(query);
    crate::analyzer::rust::std_types::observe_proof_resolution(&resolution);
    let BoundedResolution::Complete { value, .. } = resolution else {
        return if rust_path_is_leading_absolute(root) {
            Vec::new()
        } else {
            components
        };
    };
    if let Some(path) = crate::analyzer::rust::std_types::standard_wrapper_owner(&value) {
        return path
            .into_iter()
            .chain(components.iter().skip(1).cloned())
            .collect();
    }
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
            if let Some(path) = brokk_bifrost_analysis::analyzer::semantic_model::rust_qualified_path::RustQualifiedPath::parse(subject) {
                return path
                    .segments()
                    .iter()
                    .map(|segment| (*segment).to_owned())
                    .chain(components.iter().skip(1).cloned())
                    .collect();
            }
        }
    }
    if rust_path_is_leading_absolute(root) {
        Vec::new()
    } else {
        components
    }
}

fn external_call_proof_and_identity(
    analyzer: &dyn IAnalyzer,
    owner_components: &[String],
    member: &str,
    parameter_count: u32,
    cancellation: Option<&CancellationToken>,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    if owner_components.is_empty() {
        return None;
    }
    let written_owner = owner_components.join(".");
    let qualified_name = format!("{written_owner}.{member}");
    let canonical = if let Some(overlay) = analyzer.semantic_model_overlay_read().published() {
        let owner_lookup = overlay.rust_reexport_lookup_recording_with_cancellation(
            &written_owner,
            RustReexportNamespace::TypeOrModule,
            cancellation,
        );
        let local_type_owner = owner_components.len() > 1
            && matches!(owner_lookup, RustReexportLookup::Absent)
            && overlay
                .symbols_named(&written_owner)
                .records
                .iter()
                .any(|symbol| symbol.kind.is_type_declaration() && symbol.kind != brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind::Module);
        if local_type_owner {
            None
        } else {
            match overlay.rust_reexport_lookup_recording_with_cancellation(
                &qualified_name,
                RustReexportNamespace::Value,
                cancellation,
            ) {
                RustReexportLookup::Bound { symbol } => Some(symbol.qualified_name.clone()),
                RustReexportLookup::Absent => match owner_lookup {
                    RustReexportLookup::Bound { symbol } => {
                        Some(format!("{}.{}", symbol.qualified_name, member))
                    }
                    RustReexportLookup::Absent => None,
                    RustReexportLookup::MissingEvidence(_) => return None,
                },
                RustReexportLookup::MissingEvidence(_) => return None,
            }
        }
    } else {
        None
    };
    let canonical_parts = canonical
        .as_deref()
        .and_then(brokk_bifrost_analysis::analyzer::semantic_model::rust_qualified_path::RustQualifiedPath::parse)
        .and_then(|path| path.parent_and_member());
    let (owner, member) = canonical_parts
        .as_ref()
        .map(|(owner, member)| (owner.as_str(), *member))
        .unwrap_or((&written_owner, member));
    Some((
        ExactExternalCallProof::rust_external_call(
            format!("{}::{member}", owner.replace('.', "::")),
            parameter_count,
        ),
        ResolverOwnedExternalCalleeIdentity::new(Language::Rust, owner, member),
    ))
}

// Keep probe reads, but defer completion until we know which route supplied the answer.
struct ExternalCallProbe<T> {
    value: Option<T>,
    reasons: Vec<brokk_bifrost_analysis::analyzer::QueryReadIncomplete>,
}

impl<T> ExternalCallProbe<T> {
    fn capture(analyzer: &dyn IAnalyzer, probe: impl FnOnce() -> Option<T>) -> Self {
        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
        let _advisory = AnalyzerQueryScope::for_advisory_read(analyzer);
        let capture = AnalyzerQueryScope::capturing_read_incompleteness(analyzer);
        let value = probe();
        Self {
            value,
            reasons: capture.captured_read_incompleteness(),
        }
    }

    fn or_else(self, analyzer: &dyn IAnalyzer, fallback: impl FnOnce() -> Option<T>) -> Option<T> {
        if (self.value.is_none() || !self.reasons.is_empty())
            && let Some(answer) = fallback()
        {
            return Some(answer);
        }
        for reason in self.reasons {
            analyzer.record_query_incomplete(reason);
        }
        self.value
    }
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
    operation_factory: &'factory native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, 'selection>,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let function = call_path_for_site(tree, site)?;
    let callee = brokk_bifrost_rust::structural::call_function_target(function);
    if callee.kind() == "field_expression" {
        let proof = ExternalCallProbe::capture(analyzer, || {
            exact_rust_external_method_call_with_operation(
                analyzer,
                file,
                source,
                site,
                cancellation,
                operation_factory,
                &mut *operation,
            )
        });
        return proof.or_else(analyzer, || {
            let receiver_facts = receiver_facts()?;
            exact_rust_external_receiver_call(
                analyzer,
                file,
                source,
                tree,
                site,
                function,
                &receiver_facts,
                cancellation,
                operation_factory,
                operation,
            )
        });
    }
    let proof = ExternalCallProbe::capture(analyzer, || {
        exact_rust_external_type_call_with_operation(
            analyzer,
            file,
            source,
            tree,
            site,
            operation_factory,
            &mut *operation,
            cancellation,
        )
    });
    proof.or_else(analyzer, || {
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
                &mut *operation,
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
            None,
            operation_factory,
            &mut *operation,
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
        let declared = rust_external_callable_declaration(
            analyzer,
            &owner_components,
            member,
            parameter_count,
            cancellation,
        );
        // The unmodeled-std identity is for a path the author wrote as an extern
        // crate: a leading `::` or the root identifier alloc, core or std. A
        // prelude spelling such as `String::from` canonicalizes to a std owner
        // too, but it stays outside this path (#4317).
        let written_extern_root = rust_path_is_leading_absolute(*root)
            || matches!(rust_node_text(*root, source), "alloc" | "core" | "std");
        if !(written_extern_root
            && rust_external_identity_is_unmodeled_std_path(analyzer, &owner_components, member))
            && !declared
        {
            return None;
        }
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        external_call_proof_and_identity(
            analyzer,
            &owner_components,
            member,
            parameter_count,
            cancellation,
        )
    })
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
    factory: &native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, '_>,
    cancellation: Option<&CancellationToken>,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let function = call_path_for_site(tree, site)?;
    let callee = brokk_bifrost_rust::structural::call_function_target(function);
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
    let overlay = analyzer.semantic_model_overlay_read().published()?;
    let resolve_owner = |node: Node<'_>, operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, '_>| {
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
            &mut *operation,
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
                analyzer, token, file, source, tree, root, None, None, factory, operation,
            )
        {
            return None;
        }
        let owner = components.join(".");
        let symbol = RustOverlayCrates::new(Some(&overlay)).referenceable_owner(&owner)?;
        if symbol.kind != SemanticModelSymbolKind::Trait {
            if node.kind() == "generic_type" {
                return None;
            }
            let active = analyzer.active_semantic_models()?;
            let mut declarations = active.types_with_id(&symbol.id);
            declarations.records.retain(|record| {
                brokk_bifrost_core::analyzer::model::semantic_pack_realm(&record.shard.manifest.language) == "rust"
            });
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
    let nominal_owner = ExternalCallProbe::capture(analyzer, || {
        crate::analyzer::rust::std_types::rust_nominal_receiver_owner_with_operation(
            analyzer,
            file,
            source,
            qualifier,
            factory,
            &mut *operation,
            None,
        )
    });
    let mut owner =
        nominal_owner.or_else(analyzer, || resolve_owner(qualifier, &mut *operation))?;
    let mut symbol = RustOverlayCrates::new(Some(&overlay)).referenceable_owner(&owner)?;
    // A bare/imported trait path fixes the trait, while its explicit self
    // supplies the implementing type. A bracketed type fixes that type itself.
    if trait_node.is_none() && symbol.kind == SemanticModelSymbolKind::Trait {
        trait_node = Some(qualifier);
    }
    let constraint = if let Some(node) = trait_node {
        let trait_owner = resolve_owner(node, &mut *operation)?;
        let symbol = RustOverlayCrates::new(Some(&overlay)).referenceable_owner(&trait_owner)?;
        if symbol.kind != SemanticModelSymbolKind::Trait {
            return None;
        }
        let arguments = node
            .child_by_field_name("type_arguments")
            .map(super::trait_applicability::source_type_arguments);
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
            .members_of_in_family(&symbol.id, "rust")
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
        let call = function
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
                    &mut *operation,
                    None,
                )
            })?;
        symbol = RustOverlayCrates::new(Some(&overlay)).referenceable_owner(&owner)?;
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
            &mut *operation,
            constraint.as_ref(),
            None,
            cancellation,
        ) {
            if selected.is_some() {
                return None;
            }
            selected = Some((declaring, has_receiver, parameter_count));
        }
    }
    let (declaring_owner, has_receiver, parameter_count) = selected?;
    if has_receiver {
        let actual = function
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
                        &mut *operation,
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
    function: Node<'_>,
    receiver_facts: &crate::analyzer::rust::semantic::RustReceiverTypeFacts,
    cancellation: Option<&CancellationToken>,
    operation_factory: &native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, '_>,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let (receiver, member_node) = brokk_bifrost_rust::structural::rust_method_call_parts(function)?;
    // A reference site may include the wrapper's explicit type arguments.
    if site.focus_start_byte < function.start_byte()
        || site.focus_end_byte > function.end_byte()
        || site.focus_start_byte > member_node.start_byte()
        || member_node.end_byte() > site.focus_end_byte
        || cancellation.is_some_and(CancellationToken::is_cancelled)
    {
        return None;
    }
    let member = rust_node_text(member_node, source);
    let parameter_count = rust_call_written_arity(tree, member_node.start_byte())?;
    let overlay = analyzer.semantic_model_overlay_read().published()?;
    let owner =
        receiver_facts.owner_of_expression(source, tree, receiver, &overlay, &mut |ty| {
            crate::analyzer::rust::std_types::rust_nominal_receiver_owner_with_operation(
                analyzer,
                file,
                source,
                ty,
                operation_factory,
                &mut *operation,
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
        cancellation,
    )?;
    if !rust_external_bound_receiver_callable_declaration(
        &overlay,
        &owner.owner,
        member,
        parameter_count,
        cancellation,
    ) || cancellation.is_some_and(CancellationToken::is_cancelled)
    {
        return None;
    }
    Some((
        owner.proof(member, parameter_count),
        ResolverOwnedExternalCalleeIdentity::new(Language::Rust, owner.owner, member),
    ))
}

/// `file`, `source` and `tree` are the file that declares `import` and
/// `imports`; `parameter_count` is the written arity of the call being proved,
/// which may sit in another file (a crate-root import used from a descendant).
#[allow(clippy::too_many_arguments)]
pub(crate) fn rust_import_binder_external_callee(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    parameter_count: u32,
    import: &ImportInfo,
    imports: &[ImportInfo],
    member: &str,
    owner_components: &[String],
    operation_factory: &native_points::RustDefinitionOperationFactory<'_>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
    cancellation: Option<&CancellationToken>,
) -> Option<(ExactExternalCallProof, ResolverOwnedExternalCalleeIdentity)> {
    let path = import.path.as_ref()?;
    if path.segments.len() < 2 {
        return None;
    }
    let (written, _) = import_path_in_tree(import, tree, source)?;
    let canonical_owner;
    let owner_components = if rust_path_is_leading_absolute(written.root) {
        let head = written
            .root
            .child_by_field_name("name")
            .unwrap_or(written.root);
        canonical_owner = canonical_absolute_owner(
            analyzer,
            operation,
            file,
            rust_node_text(head, source),
            owner_components.iter().skip(1).cloned(),
            cancellation,
        )?;
        canonical_owner.as_slice()
    } else {
        owner_components
    };
    if written.segments != path.segments
        || !native_external_root(
            analyzer,
            token,
            file,
            source,
            tree,
            written.root,
            None,
            Some(imports),
            operation_factory,
            operation,
        )
        || (!rust_external_identity_is_unmodeled_std_path(analyzer, owner_components, member)
            && !rust_external_callable_declaration(
                analyzer,
                owner_components,
                member,
                parameter_count,
                cancellation,
            ))
    {
        return None;
    }
    external_call_proof_and_identity(
        analyzer,
        owner_components,
        member,
        parameter_count,
        cancellation,
    )
}

/// The external free function that a bare call names only through glob
/// imports, such as `stdout()` under `use std::io::*;` (#9949).
///
/// The caller passes only a site whose selected answer stopped at an unindexed
/// import boundary with no definition and no lexical binding, so the selected
/// resolver has already applied Rust's precedence and namespaces: no local
/// value, no workspace item and no workspace glob binds the name in the value
/// namespace. A glob is the weakest binder, so what is left to prove is which
/// glob binds the name. Each glob visible at the call in the call's own module
/// is decided by the activated models' enumeration of the module it names.
/// One glob whose module exports a free function of the name, with every other
/// visible glob proven to export no value of that name, selects the function.
/// Anything less leaves the call open: a named import of the same spelling,
/// which the named-binder route decides; a glob into the workspace, whose
/// exports are the resolver's to enumerate and which may forward an external
/// glob; a glob under a `cfg` attribute; a module that no model enumerates
/// completely; and two globs that both export the name.
///
/// Returns the proof, the identity and the glob's written module path, which
/// is the witness that the glob route, not the call's spelling, selected it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_rust_glob_external_call_with_operation(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    cancellation: Option<&CancellationToken>,
    operation_factory: &native_points::RustDefinitionOperationFactory<'_>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'_, '_>,
) -> Option<(
    ExactExternalCallProof,
    ResolverOwnedExternalCalleeIdentity,
    String,
)> {
    let callee = call_path_for_site(tree, site)?;
    if callee.kind() != "identifier"
        || callee.start_byte() > site.focus_start_byte
        || site.focus_end_byte > callee.end_byte()
    {
        return None;
    }
    let name = rust_node_text(callee, source);
    let parameter_count = rust_call_written_arity(tree, callee.start_byte())?;
    // Missing authority stays open: without an activated model no glob's
    // module can be enumerated.
    let overlay = analyzer.semantic_model_overlay_read().published()?;
    let selected_cancellation = cancellation.cloned().unwrap_or_default();
    let imports = crate::analyzer::rust::std_types::selected_import_infos(
        analyzer,
        operation,
        file,
        &selected_cancellation,
    )?;
    let mut selected: Option<RustPathRoute> = None;
    for import in &imports {
        let Some(path) = import.path.as_ref() else {
            // A route-less glob names no module this proof could enumerate.
            if import.is_wildcard {
                return None;
            }
            continue;
        };
        if !rust_import_binder_visible_at_byte(path, callee.start_byte(), tree) {
            continue;
        }
        if !import.is_wildcard {
            // An explicit import outranks every glob. Whether it binds a
            // value is the named-binder route's question, not this one's.
            // Only a same-name import can decide this call; an unrelated
            // named import has no route to extract here (`{self}` has no
            // binder span) and must not abort the glob proof.
            if import.local_name() == Some(name) {
                return None;
            }
            continue;
        }
        let (written, _) = import_path_in_tree(import, tree, source)?;
        let declaration = enclosing_use_declaration(written.root)?;
        if brokk_bifrost_rust::lexical_scope::rust_cfg_condition(declaration, source)
            != brokk_bifrost_rust::lexical_scope::RustCfgCondition::Always
        {
            return None;
        }
        if !native_external_root(
            analyzer,
            token,
            file,
            source,
            tree,
            written.root,
            cancellation,
            Some(&imports),
            operation_factory,
            &mut *operation,
        ) {
            return None;
        }
        match rust_glob_value_binding(
            analyzer,
            &overlay,
            &written.segments,
            name,
            parameter_count,
            cancellation,
        ) {
            RustGlobValueBinding::Function => match &selected {
                // Two globs of one module bind one item.
                Some(route) if route.segments == written.segments => {}
                Some(_) => return None,
                None => {
                    selected = Some(RustPathRoute {
                        segments: written.segments,
                        written: written.full_path,
                    });
                }
            },
            RustGlobValueBinding::Absent => {}
            RustGlobValueBinding::Open => return None,
        }
    }
    let route = selected?;
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return None;
    }
    let (proof, identity) = external_call_proof_and_identity(
        analyzer,
        &route.segments,
        name,
        parameter_count,
        cancellation,
    )?;
    Some((proof, identity, route.written))
}

/// One glob's module route: its segments and its written spelling.
struct RustPathRoute {
    segments: Vec<String>,
    written: String,
}

/// What the enumerated surface of one glob's module says about one
/// value-namespace name.
enum RustGlobValueBinding {
    /// The module exports a free function of that name at the written arity.
    Function,
    /// The module's complete surface holds no value of that name: no member,
    /// or only a module, type, trait or macro, which other namespaces hold.
    Absent,
    /// The surface cannot decide: no model declares the module, its surface is
    /// partial or conflicting, or the name is a value other than a free
    /// function of the written arity.
    Open,
}

fn rust_glob_value_binding(
    analyzer: &dyn IAnalyzer,
    overlay: &brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay,
    module: &[String],
    name: &str,
    parameter_count: u32,
    cancellation: Option<&CancellationToken>,
) -> RustGlobValueBinding {
    let Some(owner) = RustOverlayCrates::new(Some(overlay))
        .referenceable_symbol(&RustOverlayCrates::pack_name(module))
    else {
        return RustGlobValueBinding::Open;
    };
    if owner.kind != SemanticModelSymbolKind::Module {
        return RustGlobValueBinding::Open;
    }
    // A declared public callable is a positive fact even in a partial pack: a
    // module's value namespace holds at most one item of a name.
    if rust_external_callable_declaration(analyzer, module, name, parameter_count, cancellation) {
        return RustGlobValueBinding::Function;
    }
    let members = overlay.member_target_on_owner(&owner.id, name);
    match members.disposition {
        SemanticModelMemberTargetDisposition::Absent => RustGlobValueBinding::Absent,
        SemanticModelMemberTargetDisposition::Unique => {
            let [member] = members.records.as_slice() else {
                unreachable!("a unique member target has one record: {members:?}");
            };
            // A unique record of the owner's own surface needs only that
            // record to be complete, but a record in another namespace leaves
            // room for a same-named value that a partial surface omitted, so
            // the absence also needs the whole surface (the same test
            // `member_target_on_owner` applies before it reports Absent).
            // Unit and tuple structs also declare a value constructor, so a
            // struct does not prove the value namespace empty.
            if matches!(
                member.kind,
                SemanticModelSymbolKind::Module
                    | SemanticModelSymbolKind::Trait
                    | SemanticModelSymbolKind::TypeAlias
                    | SemanticModelSymbolKind::Enum
                    | SemanticModelSymbolKind::Union
                    | SemanticModelSymbolKind::Macro
            ) && overlay.owner_surface(&owner).proves_absence()
                && overlay
                    .gapped_member_surface(&owner.qualified_name, name)
                    .is_none()
            {
                RustGlobValueBinding::Absent
            } else {
                RustGlobValueBinding::Open
            }
        }
        SemanticModelMemberTargetDisposition::Incomplete
        | SemanticModelMemberTargetDisposition::Conflict => RustGlobValueBinding::Open,
    }
}

/// The `use` declaration that contains one node of its route.
fn enclosing_use_declaration(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "use_declaration" {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
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
    operation_factory: &'factory native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, 'selection>,
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
    operation_factory: &'factory native_points::RustDefinitionOperationFactory<'analyzer>,
    operation: &mut brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation<'analyzer, 'selection>,
) -> crate::analyzer::rust::std_types::RustProofAttempt<(
    ExactExternalCallProof,
    ResolverOwnedExternalCalleeIdentity,
)> {
    crate::analyzer::rust::std_types::completed_proof(analyzer, cancellation, || {
        let method = site.focus_start_byte..site.focus_end_byte;
        let (owner, arity) =
            crate::analyzer::rust::std_types::rust_method_receiver_owner_with_operation(
                analyzer,
                file,
                source,
                method,
                operation_factory,
                &mut *operation,
                cancellation,
            )?;
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
            cancellation,
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
    cancellation: Option<&CancellationToken>,
) -> bool {
    let Some(overlay) = analyzer.semantic_model_overlay_read().published() else {
        return false;
    };
    let owner = RustOverlayCrates::pack_name(owner_components);
    let Some(owner_symbol) = RustOverlayCrates::new(Some(&overlay)).referenceable_owner(&owner)
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
    let Some(callable) = rust_external_callable_match_with_overlay(
        &overlay,
        &owner,
        member,
        parameter_count,
        false,
        cancellation,
    ) else {
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
    owner_components: &[String],
    member: &str,
) -> bool {
    if !owner_components
        .first()
        .is_some_and(|root| matches!(root.as_str(), "alloc" | "core" | "std"))
    {
        return false;
    }
    let owner = RustOverlayCrates::pack_name(owner_components);
    let language = LanguageDialect::from(Language::Rust).semantic_pack_label();
    if analyzer.active_semantic_models().is_some_and(|active| {
        let modeled = match active
            .has_receiverless_procedure_summary_member(language, &owner, member)
        {
            brokk_bifrost_analysis::analyzer::store::active_models::FamilyPresence::Present => true,
            brokk_bifrost_analysis::analyzer::store::active_models::FamilyPresence::Absent => false,
            brokk_bifrost_analysis::analyzer::store::active_models::FamilyPresence::Open(open) => {
                unreachable!("a Rust realm question has no JVM-family part: {open:?}")
            }
        };
        modeled || active.gapped_member_surface(&owner, member).is_some()
    }) {
        return false;
    }
    let Some(overlay) = analyzer.semantic_model_overlay_read().published() else {
        return true;
    };
    let member_name = format!("{owner}.{member}");
    let owner_is_declared = overlay
        .symbols_named_for(&owner, "rust")
        .records
        .into_iter()
        .any(|symbol| symbol.language == language && symbol.qualified_name == owner);
    let member_is_declared = overlay
        .symbols_named_for(&member_name, "rust")
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
    cancellation: Option<&CancellationToken>,
) -> bool {
    let Some(callable) = rust_external_callable_match_with_overlay(
        overlay,
        owner,
        member,
        parameter_count,
        true,
        cancellation,
    ) else {
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
    cancellation: Option<&CancellationToken>,
) -> Option<SemanticModelCallableMatch> {
    // Preserve the written facade route before owner canonicalization. A
    // module reexport selects its provider only on the complete call path.
    let written_path = format!("{owner}.{member}");
    let reexported = match overlay.rust_reexport_lookup_recording_with_cancellation(
        &written_path,
        RustReexportNamespace::Value,
        cancellation,
    ) {
        RustReexportLookup::Bound { symbol } => Some(symbol),
        RustReexportLookup::Absent => None,
        RustReexportLookup::MissingEvidence(_) => return None,
    };
    let reexported_owner = if reexported.is_none() {
        match overlay.rust_reexport_lookup_recording_with_cancellation(
            owner,
            RustReexportNamespace::TypeOrModule,
            cancellation,
        ) {
            RustReexportLookup::Bound { symbol } => Some(symbol),
            RustReexportLookup::Absent => None,
            RustReexportLookup::MissingEvidence(_) => return None,
        }
    } else {
        None
    };
    let owner = RustOverlayCrates::new(Some(overlay)).referenceable_owner(owner);
    let (callable_owner, callable_member) = reexported
        .as_ref()
        .and_then(|symbol| {
            brokk_bifrost_analysis::analyzer::semantic_model::rust_qualified_path::RustQualifiedPath::parse(
                &symbol.qualified_name,
            )
            .and_then(|path| path.parent_and_member())
            .map(|(owner, member)| (owner, member.to_owned()))
        })
        .or_else(|| reexported_owner.as_ref().map(|owner| (owner.qualified_name.clone(), member.to_owned())))
        .or_else(|| owner.map(|owner| (owner.qualified_name.clone(), member.to_owned())))?;
    let key = SemanticModelCallableKey::new(
        Language::Rust.config_label(),
        &callable_owner,
        &callable_member,
        has_receiver,
        parameter_count,
    );
    let application = SemanticModelCallApplication::positional(parameter_count);
    let callable = if let Some(symbol) = reexported.as_ref() {
        overlay.callable_for_selected_rust_reexport_application(
            key,
            &application,
            (
                symbol.provenance.pack_digest.as_str(),
                symbol.provenance.record_id.as_str(),
            ),
            cancellation,
        )
    } else if let Some(owner) = reexported_owner {
        overlay.callable_for_rust_reexported_owner_application(key, &application, owner)
    } else {
        overlay.callable_for_selected_application(key, &application, None)
    };
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

#[cfg(test)]
mod probe_completion_tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
    use brokk_bifrost_analysis::analyzer::{MultiAnalyzer, QueryReadIncomplete};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#11145: optional external probes hid stops without a successful fallback")]
    fn stopped_external_probe_completion_follows_selected_route() {
        for (probe_value, fallback, incomplete) in [
            (Some(7), None, true),
            (Some(7), Some(8), false),
            (None, None, true),
            (None, Some(8), false),
        ] {
            let analyzer = MultiAnalyzer::default();
            let outer = AnalyzerQueryScope::new(&analyzer);
            let probe = ExternalCallProbe::capture(&analyzer, || {
                crate::analyzer::rust::std_types::completed_proof(&analyzer, None, || {
                    crate::analyzer::rust::std_types::operational_proof_stop("depth_limit", brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause::Budget);
                    probe_value
                })
                .into_value()
            });
            let result = probe.or_else(&analyzer, || fallback);
            assert_eq!(result, fallback.or(probe_value));
            assert_eq!(
                outer.read_completion(),
                if incomplete {
                    Err(QueryReadIncomplete::ProofStopped {
                        reason: "depth_limit",
                        cause: Some(brokk_bifrost_analysis::analyzer::read_ledger::DerivationExecutionCause::Budget),
                    })
                } else {
                    Ok(())
                }
            );
        }
    }
}
