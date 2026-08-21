use super::*;
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::QueryToken;
use crate::analyzer::TypeHierarchyProvider;
use crate::analyzer::rust::rust_focused_use_path;
use crate::analyzer::rust::{canonical_rust_hierarchy_type, usage_crate_export_targets};
use crate::analyzer::rust::{
    forward_export_fqn_from_files, has_rust_value_constructor,
    resolve_imported_export_from_binder_forward, resolve_module_files, resolve_module_package,
    resolve_visible_import_targets_forward, rust_associated_type_declaration_for_exact_node,
};
use crate::analyzer::rust::{
    resolve_rust_import_package_scoped, resolve_rust_module_segments_with_crate,
    rust_crate_root_package, rust_package_name,
};
use crate::analyzer::structural::resolution::{HierarchyRelation, MemberDispatchTier};
use crate::analyzer::usages::rust_graph::{
    RustDefinitionProvider, resolve_rust_path_fqn, rust_smallest_named_node_covering,
};
use crate::analyzer::{RustReferenceContext, SignatureMetadata, StructuredTypeIdentity};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;
use brokk_bifrost_rust::declarations::rust_macro_invocation_arguments;
use brokk_bifrost_rust::field_roles::{
    RustFieldNameRole, RustStructFieldContainer, classify_rust_field_name,
};
use brokk_bifrost_rust::graph::resolver::{RustBareTokenTreeRole, RustTokenTreeRoleCache};
use brokk_bifrost_rust::graph_support::{
    RustFactSource, RustSource, is_rust_export_visible_declaration,
    is_rust_macro_export_declaration, is_rust_trait_declaration,
    is_rust_trait_impl_member_declaration, rust_declaration_node,
};
use brokk_bifrost_rust::lexical_scope;
use brokk_bifrost_rust::macro_matcher::{
    self, MacroFragmentKind, MacroMatchError, MacroNamespaceEvidence,
    enclosing_macro_invocation_for_argument, is_macro_rules_definition, match_macro_rules,
    token_namespace_evidence,
};
use std::cell::RefCell;

use super::{
    DECLARATION_OR_IMPORT_SITE_DIAGNOSTIC_KIND, LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
    MACRO_FRAGMENT_NO_NAMESPACE_DIAGNOSTIC_KIND, MACRO_MATCHER_BINDING_DIAGNOSTIC_KIND,
    MACRO_MATCHER_DISAGREEMENT_DIAGNOSTIC_KIND, MACRO_MATCHER_FAILED_DIAGNOSTIC_KIND,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RustResolutionSemantics {
    Full,
    Bounded,
}

pub(crate) struct AnalyzerRustDefinitionProvider<'a> {
    rust: &'a RustAnalyzer,
    session: Option<&'a ResolutionSession>,
    semantics: RustResolutionSemantics,
    cache_lookups: bool,
    fqns: RefCell<HashMap<String, Vec<CodeUnit>>>,
    file_identifiers: RefCell<HashMap<(ProjectFile, String), Vec<CodeUnit>>>,
}

impl<'a> AnalyzerRustDefinitionProvider<'a> {
    pub(crate) fn new(rust: &'a RustAnalyzer, cache_lookups: bool) -> Self {
        Self {
            rust,
            session: None,
            semantics: RustResolutionSemantics::Full,
            cache_lookups,
            fqns: RefCell::new(HashMap::default()),
            file_identifiers: RefCell::new(HashMap::default()),
        }
    }

    pub(crate) fn bounded(rust: &'a RustAnalyzer, session: &'a ResolutionSession) -> Self {
        Self {
            rust,
            session: Some(session),
            semantics: RustResolutionSemantics::Bounded,
            cache_lookups: true,
            fqns: RefCell::new(HashMap::default()),
            file_identifiers: RefCell::new(HashMap::default()),
        }
    }

    pub(crate) fn cancellable_full(rust: &'a RustAnalyzer, session: &'a ResolutionSession) -> Self {
        Self {
            rust,
            session: Some(session),
            semantics: RustResolutionSemantics::Full,
            cache_lookups: true,
            fqns: RefCell::new(HashMap::default()),
            file_identifiers: RefCell::new(HashMap::default()),
        }
    }
}

impl RustDefinitionProvider for AnalyzerRustDefinitionProvider<'_> {
    fn is_bounded(&self) -> bool {
        self.semantics == RustResolutionSemantics::Bounded
    }

    fn scope_step(&self) -> bool {
        self.session.is_none_or(ResolutionSession::scope_step)
    }

    fn observe_cancellation(&self) -> bool {
        self.session
            .is_none_or(ResolutionSession::observe_cancellation)
    }

    fn forward_reference_context<'r>(
        &'r self,
        rust: &'r dyn RustFactSource,
        token: QueryToken<'r>,
        file: &ProjectFile,
    ) -> Option<RustReferenceContext<'r>> {
        match self.session {
            Some(session) => session.observe_cancellation().then(|| {
                RustReferenceContext::new(
                    rust,
                    token,
                    file,
                    true,
                    Box::new(move || session.observe_cancellation()),
                )
            }),
            None => Some(rust.forward_reference_context_of(token, file)),
        }
    }

    fn ranges(&self, index: &dyn CodeUnitIndex, unit: &CodeUnit) -> Vec<Range> {
        match self.session {
            Some(session) => {
                session.query_limited_rows(|limit| self.rust.ranges_limited(unit, limit))
            }
            None => index.ranges(unit),
        }
    }

    fn signature_metadata(
        &self,
        index: &dyn CodeUnitIndex,
        unit: &CodeUnit,
    ) -> Vec<SignatureMetadata> {
        match self.session {
            Some(session) => session
                .query_limited_rows(|limit| self.rust.signature_metadata_limited(unit, limit)),
            None => index.signature_metadata(unit),
        }
    }

    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        if self.cache_lookups
            && let Some(units) = self.fqns.borrow().get(fqn)
        {
            return units.clone();
        }
        let mut units: Vec<_> = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.rust
                    .declaration_candidates_by_fqn_limited(fqn, limit, || {
                        session.observe_cancellation()
                    })
            }),
            None => self.rust.declaration_candidates_by_fqn(fqn),
        };
        sort_units(&mut units);
        units.dedup();
        if self.cache_lookups {
            self.fqns
                .borrow_mut()
                .insert(fqn.to_string(), units.clone());
        }
        units
    }

    fn file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        if self.cache_lookups {
            let key = (file.clone(), identifier.to_string());
            if let Some(units) = self.file_identifiers.borrow().get(&key) {
                return units.clone();
            }
        }
        let mut units: Vec<_> = match self.session {
            Some(session) => session
                .query_limited_rows(|limit| {
                    self.rust.declaration_candidates_by_identifier_limited(
                        identifier,
                        limit,
                        || session.observe_cancellation(),
                    )
                })
                .into_iter()
                .filter(|unit| unit.source() == file)
                .collect(),
            None => self
                .rust
                .declaration_candidates_by_identifier(identifier)
                .into_iter()
                .filter(|unit| unit.source() == file)
                .filter(|unit| unit.identifier() == identifier)
                .collect(),
        };
        sort_units(&mut units);
        units.dedup();
        if self.cache_lookups {
            self.file_identifiers
                .borrow_mut()
                .insert((file.clone(), identifier.to_string()), units.clone());
        }
        units
    }

    fn members_for_owner_name(&self, owner_fqn: &str, name: &str) -> Vec<CodeUnit> {
        let mut units = match self.session {
            Some(session) => session.query_limited_rows(|limit| {
                self.rust
                    .member_candidates_for_owner_limited(owner_fqn, name, limit, || {
                        session.observe_cancellation()
                    })
            }),
            None => self
                .rust
                .declaration_candidates_by_fqn(&format!("{owner_fqn}.{name}")),
        };
        sort_units(&mut units);
        units.dedup();
        units
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_rust(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
    operation: Option<NavigationOperation>,
) -> DefinitionLookupOutcome {
    // Every tier below resolves the reference this site names, so the deep
    // scope covers the whole ladder; a nested lookup for a receiver type or an
    // owner sits outside it and attributes nothing to this reference.
    let _deep = trace::DeepScope::enter(&site.text);
    if !support.observe_cancellation() {
        return no_definition("cancelled", "Rust definition resolution was cancelled");
    }
    let outcome = resolve_rust_unscoped(
        analyzer, token, support, file, source, tree, site, cache, operation,
    );
    if !support.observe_cancellation() {
        return outcome;
    }
    let cargo_scope = resolve_analyzer::<RustAnalyzer>(analyzer).and_then(|rust| {
        rust_cargo_reference_scope(rust, token, file, source, tree, site).map(|scope| (rust, scope))
    });
    let outcome = match cargo_scope {
        Some((rust, scope)) => {
            let direct_crate_reference =
                tree.and_then(|tree| rust_direct_crate_root_reference(source, tree, site));
            rust_scope_forward_candidates_to_cargo_target(
                rust,
                token,
                support,
                file,
                scope,
                direct_crate_reference,
                outcome,
            )
        }
        None => outcome,
    };
    rust_filter_associated_call_outcome(analyzer, support, source, tree, site, outcome)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_rust_cancellable(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
    operation: Option<NavigationOperation>,
    budget: ReceiverAnalysisBudget,
    cancellation: &CancellationToken,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let session = ResolutionSession::bounded(budget, Some(cancellation));
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "rust_analyzer_unavailable",
            "Rust analyzer is unavailable",
        ));
    };
    let support = AnalyzerRustDefinitionProvider::cancellable_full(rust, &session);
    let outcome = resolve_rust(
        analyzer, token, &support, file, source, tree, site, cache, operation,
    );
    session.finish(outcome)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_rust_bounded(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "rust_analyzer_unavailable",
            "Rust analyzer is unavailable",
        ));
    };
    let support = AnalyzerRustDefinitionProvider::bounded(rust, &session);
    let mut cache = RustTypeLookupCache::bounded_for_query();
    let outcome = resolve_rust_bounded_in_session(
        analyzer, token, &support, file, source, tree, site, &mut cache,
    );
    session.finish(outcome)
}

#[allow(clippy::too_many_arguments)]
fn resolve_rust_bounded_in_session(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &AnalyzerRustDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
) -> DefinitionLookupOutcome {
    let Some(tree) = tree else {
        return no_definition("rust_parse_failed", "Rust source could not be parsed");
    };
    let Some(node) = rust_smallest_named_node_covering(
        support,
        tree.root_node(),
        site.focus_start_byte,
        site.focus_end_byte,
    ) else {
        return no_definition(
            "no_reference_node",
            "no Rust syntax node exists at the reference location",
        );
    };

    if let Some(outcome) = rust_rooted_use_prefix_outcome(
        analyzer,
        token,
        support.rust,
        support,
        file,
        source,
        tree,
        site,
    ) {
        return outcome;
    }

    if let Some(outcome) =
        resolve_rust_field(analyzer, token, support, file, source, tree, site, cache)
    {
        return outcome;
    }

    if node.kind() == "self" && focused_rust_field_receiver(node, site.focus_start_byte) {
        return no_definition(
            LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
            "the focused Rust receiver is a local expression, which is not indexed",
        );
    }

    if node.kind() == "self"
        && let Some(owner) =
            rust_enclosing_impl_type_fqn(analyzer, token, support, file, source, node)
    {
        let candidates = support
            .fqn(&owner)
            .into_iter()
            .filter(|unit| rust_is_type_definition(analyzer, unit))
            .collect::<Vec<_>>();
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }

    if rust_node_is_type_reference(support, node)
        && let Some(fqn) = rust_resolve_type_node_fqn(
            analyzer,
            token,
            support,
            file,
            source,
            node,
            Some(node.start_byte()),
        )
    {
        let candidates = support
            .fqn(&fqn)
            .into_iter()
            .filter(|unit| rust_is_type_definition(analyzer, unit))
            .collect::<Vec<_>>();
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }

    let function = rust_enclosing_call_function(support, node);
    if let Some(function) = function {
        let candidates = if matches!(
            function.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        ) {
            rust_bounded_scoped_callable_candidates(
                analyzer, token, support, file, source, function,
            )
        } else {
            rust_callable_name(support, function, source)
                .map(|name| {
                    rust_callable_candidates(
                        analyzer,
                        token,
                        support,
                        file,
                        tree.root_node(),
                        &name,
                        function.start_byte(),
                    )
                })
                .unwrap_or_default()
        };
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }

    no_definition(
        "no_indexed_definition",
        format!(
            "`{}` did not resolve through bounded structured Rust evidence",
            site.text
        ),
    )
}

fn rust_node_is_type_reference(support: &dyn RustDefinitionProvider, mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if !support.scope_step() {
            return false;
        }
        if parent.child_by_field_name("type") == Some(node)
            || parent.child_by_field_name("trait") == Some(node)
            || (parent.kind() == "struct_expression"
                && parent.child_by_field_name("name") == Some(node))
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "generic_type"
                | "scoped_type_identifier"
                | "qualified_type"
                | "reference_type"
                | "pointer_type"
                | "array_type"
                | "bracketed_type"
                | "tuple_type"
        ) {
            node = parent;
            continue;
        }
        break;
    }
    false
}

fn rust_enclosing_call_function<'tree>(
    support: &dyn RustDefinitionProvider,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    loop {
        let parent = node.parent()?;
        if !support.scope_step() {
            return None;
        }
        if matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        ) && (parent.child_by_field_name("name") == Some(node)
            || parent.child_by_field_name("path") == Some(node))
        {
            node = parent;
            continue;
        }
        if parent.kind() == "generic_function"
            && parent.child_by_field_name("function") == Some(node)
        {
            node = parent;
            continue;
        }
        return (parent.kind() == "call_expression"
            && parent.child_by_field_name("function") == Some(node))
        .then_some(node);
    }
}

enum RustCargoReferenceScope {
    LocalTarget { fail_closed: bool },
    LexicalSelf,
    ImportTargets(Vec<ProjectFile>),
    StructuredLocalPath,
    LibraryRoute(String),
}

fn rust_cargo_reference_scope(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> Option<RustCargoReferenceScope> {
    let tree = tree?;
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    if let Some(focused_use) = rust_focused_use_path(focused, source)
        && let Some(targets) =
            rust_import_path_target_files(rust, token, file, &focused_use.segments)
    {
        return Some(RustCargoReferenceScope::ImportTargets(targets));
    }
    let mut path = focused;
    while let Some(parent) = path.parent() {
        if !matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        ) {
            break;
        }
        path = parent;
    }
    let root = rust_scoped_path_root(path);
    let root = rust_node_text(root, source).trim();
    if !root.is_empty() {
        for binder in lexical_scope::visible_import_binders_at(source, site.focus_start_byte) {
            let mut targets =
                resolve_visible_import_targets_forward(rust, token, file, &binder, root)
                    .into_iter()
                    .map(|(target, _)| target)
                    .collect::<Vec<_>>();
            targets.sort();
            targets.dedup();
            if !targets.is_empty() {
                return Some(RustCargoReferenceScope::ImportTargets(targets));
            }
        }
    }
    if root == "Self" {
        Some(RustCargoReferenceScope::LexicalSelf)
    } else if path != focused
        && rust
            .declarations(file)
            .into_iter()
            .any(|unit| unit.is_module() && unit.identifier() == root)
    {
        Some(RustCargoReferenceScope::StructuredLocalPath)
    } else if path == focused || matches!(root, "crate" | "self" | "super") {
        Some(RustCargoReferenceScope::LocalTarget { fail_closed: true })
    } else if root.is_empty() {
        None
    } else {
        Some(RustCargoReferenceScope::LibraryRoute(root.to_string()))
    }
}

fn rust_import_path_target_files(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    segments: &[String],
) -> Option<Vec<ProjectFile>> {
    for prefix_len in (1..=segments.len()).rev() {
        let module_specifier = segments[..prefix_len].join("::");
        let targets = resolve_module_files(rust, token, file, &module_specifier);
        if !targets.is_empty() {
            return Some(targets);
        }
    }
    None
}

fn rust_direct_crate_root_reference(
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<(String, RustBareReferenceRole)> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    if rust_enclosing_macro_name(focused).is_some() {
        return None;
    }
    let parent = focused.parent()?;
    if !matches!(
        parent.kind(),
        "scoped_identifier" | "scoped_type_identifier"
    ) || parent.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        )
    }) || !parent
        .child_by_field_name("name")
        .is_some_and(|name| node_within(name, focused))
        || parent
            .child_by_field_name("path")
            .is_none_or(|path| path.kind() != "crate")
    {
        return None;
    }
    let name = rust_node_text(focused, source).trim();
    let role = rust_bare_reference_role(tree, site, source)?;
    (!name.is_empty() && role != RustBareReferenceRole::Macro).then(|| (name.to_string(), role))
}

fn rust_scope_forward_candidates_to_cargo_target(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    scope: RustCargoReferenceScope,
    direct_crate_reference: Option<(String, RustBareReferenceRole)>,
    mut outcome: DefinitionLookupOutcome,
) -> DefinitionLookupOutcome {
    if let Some((name, role)) = direct_crate_reference.as_ref() {
        let roots = rust.cargo_target_roots_for_file(file);
        let mut candidates = usage_crate_export_targets(rust, token, file, name)
            .into_iter()
            .flat_map(|(target_file, target_name)| {
                support.file_identifier(&target_file, &target_name)
            })
            .filter(|candidate| rust_role_accepts_current_module(rust, *role, candidate))
            .collect::<Vec<_>>();
        for root in &roots {
            candidates.extend(
                support
                    .file_identifier(root, name)
                    .into_iter()
                    .filter(|candidate| rust.structural_parent_of(candidate).is_none())
                    .filter(|candidate| rust_role_accepts_current_module(rust, *role, candidate)),
            );
        }
        sort_units(&mut candidates);
        candidates.dedup();
        if !candidates.is_empty() {
            let reference = outcome.reference.take();
            let lexical_definition = outcome.lexical_definition.take();
            let prior_diagnostics = std::mem::take(&mut outcome.diagnostics);
            outcome = candidates_outcome(candidates);
            outcome.reference = reference;
            outcome.lexical_definition = lexical_definition;
            outcome
                .diagnostics
                .extend(prior_diagnostics.into_iter().filter(|diagnostic| {
                    !matches!(
                        diagnostic.kind.as_str(),
                        "no_indexed_definition" | "ambiguous_definition"
                    )
                }));
        } else if !roots.is_empty() && !outcome.definitions.is_empty() {
            let reference = outcome.reference.take();
            let lexical_definition = outcome.lexical_definition.take();
            outcome = no_definition(
                "no_indexed_definition",
                format!("no crate-root Rust declaration found for `{name}`"),
            );
            outcome.reference = reference;
            outcome.lexical_definition = lexical_definition;
        }
    }
    if outcome.definitions.is_empty() {
        return outcome;
    }
    // `Self` resolution already carries the exact enclosing impl identity in
    // the CodeUnit signature. Expanding that result by FQN can introduce
    // unrelated associated items from other impls whose analyzer identity is
    // necessarily the same (for example several `Alias<S>::Output` items).
    // Keep the lexical result exact and only use Cargo membership to validate
    // that result below.
    let preserve_exact_lexical_self = matches!(&scope, RustCargoReferenceScope::LexicalSelf);
    let mut expanded = outcome.definitions.clone();
    if !preserve_exact_lexical_self {
        for definition in &outcome.definitions {
            expanded.extend(
                support
                    .fqn(&definition.fq_name())
                    .into_iter()
                    .filter(|candidate| {
                        rust_same_declaration_namespace(rust, definition, candidate)
                    }),
            );
            expanded.extend(
                support
                    .file_identifier(file, definition.identifier())
                    .into_iter()
                    .filter(|candidate| {
                        candidate.fq_name() == definition.fq_name()
                            && rust_same_declaration_namespace(rust, definition, candidate)
                    }),
            );
        }
    }
    sort_units(&mut expanded);
    expanded.dedup();
    if matches!(
        scope,
        RustCargoReferenceScope::LexicalSelf
            | RustCargoReferenceScope::ImportTargets(_)
            | RustCargoReferenceScope::StructuredLocalPath
    ) && outcome.definitions.len() == 1
        && expanded == outcome.definitions
    {
        return outcome;
    }
    let (scoped, fail_closed) = match scope {
        RustCargoReferenceScope::LocalTarget { fail_closed } => (
            rust.candidates_in_same_cargo_target_root(file, expanded),
            fail_closed,
        ),
        RustCargoReferenceScope::LexicalSelf => (
            rust.candidates_in_same_cargo_target_root(file, expanded),
            true,
        ),
        RustCargoReferenceScope::ImportTargets(targets) => (
            Some(
                expanded
                    .into_iter()
                    .filter(|candidate| {
                        targets.iter().any(|target| {
                            candidate.source() == target
                                || rust.files_share_cargo_target(candidate.source(), target)
                                    == Some(true)
                        })
                    })
                    .collect(),
            ),
            true,
        ),
        RustCargoReferenceScope::StructuredLocalPath => (
            rust.candidates_in_same_cargo_target_root(file, expanded),
            true,
        ),
        RustCargoReferenceScope::LibraryRoute(route) => (
            rust.candidates_in_cargo_library_route(file, &route, expanded),
            true,
        ),
    };
    let Some(scoped) = scoped else {
        return outcome;
    };
    if scoped.is_empty() && fail_closed {
        let reference = outcome.reference.take();
        let lexical_definition = outcome.lexical_definition.take();
        let mut scoped_outcome = no_definition(
            "no_indexed_definition",
            "no Rust definition remains in the resolved Cargo target",
        );
        scoped_outcome.reference = reference;
        scoped_outcome.lexical_definition = lexical_definition;
        return scoped_outcome;
    }
    if scoped.is_empty() {
        return outcome;
    }
    if scoped == outcome.definitions {
        return outcome;
    }
    let reference = outcome.reference.take();
    let lexical_definition = outcome.lexical_definition.take();
    let prior_diagnostics = std::mem::take(&mut outcome.diagnostics);
    let mut scoped_outcome = candidates_outcome(scoped);
    scoped_outcome.reference = reference;
    scoped_outcome.lexical_definition = lexical_definition;
    scoped_outcome.diagnostics.extend(
        prior_diagnostics
            .into_iter()
            .filter(|diagnostic| diagnostic.kind != "ambiguous_definition"),
    );
    scoped_outcome
}

fn rust_same_declaration_namespace(
    rust: &RustAnalyzer,
    expected: &CodeUnit,
    candidate: &CodeUnit,
) -> bool {
    expected.is_module() == candidate.is_module()
        && expected.is_class() == candidate.is_class()
        && expected.is_macro() == candidate.is_macro()
        && expected.is_function() == candidate.is_function()
        && expected.is_field() == candidate.is_field()
        && (!expected.is_field() || rust.is_type_alias(expected) == rust.is_type_alias(candidate))
}

#[allow(clippy::too_many_arguments)]
fn resolve_rust_unscoped(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
    operation: Option<NavigationOperation>,
) -> DefinitionLookupOutcome {
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return no_definition("rust_analyzer_unavailable", "Rust analyzer is unavailable");
    };
    let reference = site.text.as_str();
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_rooted_use_prefix_outcome(analyzer, token, rust, support, file, source, tree, site)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_struct_field_name_outcome(analyzer, token, support, file, source, tree, site)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_enum_variant_declaration_outcome(analyzer, support, file, source, tree, site)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_imported_pattern_variant_outcome(rust, token, support, file, source, tree, site)
    {
        return outcome;
    }
    // An impl associated type is both a declaration site and a navigation
    // source: declaration jumps to the trait contract, while definition stays
    // on the concrete impl item. Handle that exact structured shape before the
    // generic declaration-name guard rejects it as a non-reference.
    if let Some(operation) = operation
        && let Some(tree) = tree
        && let Some(outcome) = rust_impl_associated_type_declaration_outcome(
            rust,
            token,
            support,
            file,
            source,
            tree,
            site,
            Some(operation),
        )
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_exact_reference_role_outcome(analyzer, token, support, file, source, tree, site)
    {
        return outcome;
    }
    // Preserve the exact focused segment of structured Rust paths before
    // whole-expression member handling can collapse an owner focus such as
    // `EventInfo` in `vec![EventInfo::default()]` to the terminal method.
    if let Some(tree) = tree
        && let Some(outcome) = rust_focused_token_tree_prefix_outcome(
            analyzer, token, rust, support, file, source, tree, site,
        )
    {
        return outcome;
    }
    if let Some(tree) = tree
        && !reference.contains(['.', ':'])
        && let Some(node) = smallest_named_node_covering(
            tree.root_node(),
            site.focus_start_byte,
            site.focus_end_byte,
        )
        && matches!(node.kind(), "identifier" | "shorthand_field_identifier")
    {
        let shadowed = lexical_scope::name_shadowed_in_tree(
            tree.root_node(),
            source,
            reference,
            site.focus_start_byte,
        );
        if lexical_scope::is_pattern_binding_identifier(node) && !shadowed {
            return no_definition(
                "local_binding",
                format!("`{reference}` is a local Rust binding, which is not indexed"),
            );
        }
        if shadowed {
            return no_definition(
                LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
                format!("`{reference}` is a local Rust binding, which is not indexed"),
            );
        }
    }
    if let Some(tree) = tree
        && let Some(operation) = operation
        && let Some(outcome) = rust_qualified_associated_type_navigation_outcome(
            rust, token, analyzer, support, file, source, tree, site, operation,
        )
    {
        return outcome;
    }
    if reference.contains('.')
        && let Some(tree) = tree
        && let Some(outcome) =
            resolve_rust_field(analyzer, token, support, file, source, tree, site, cache)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(candidates) =
            rust_self_scoped_associated_type_candidates(rust, analyzer, file, source, tree, site)
        && !candidates.is_empty()
    {
        return candidates_outcome(candidates);
    }
    // `Self` (as a type) denotes the lexically enclosing impl's type — the Rust
    // form of the `LexicalEnclosingType` receiver origin. Name-based resolution
    // (`resolve_bare` / `resolve_scoped`) has no notion of `Self`, so resolve it
    // here where the cursor node is available: bare `Self` / `Self { .. }` goes
    // to the type declaration, and `Self::assoc` to the associated item.
    if let Some(tree) = tree
        && (reference == "Self" || reference.starts_with("Self::"))
        && let Some(node) = smallest_named_node_covering(
            tree.root_node(),
            site.focus_start_byte,
            site.focus_end_byte,
        )
        && let Some(self_type) =
            rust_enclosing_impl_type_fqn(analyzer, token, support, file, source, node)
    {
        let focused_segment = reference_segments(site, "::", 2)
            .and_then(|segments| focus_segment_index(site, &segments));
        let member_kind = smallest_named_node_covering(
            tree.root_node(),
            site.range.start_byte,
            site.range.end_byte,
        )
        .map_or(RustMemberKind::Field, |expression| {
            if rust_identifier_is_callee(expression) {
                RustMemberKind::Function
            } else {
                RustMemberKind::Field
            }
        });
        // fqname-M4: `reference` here is always `Self` or `Self::<rest>`, and
        // `<rest>` may itself contain further `::` (e.g. `Self::Outer::Item`);
        // `split_once` deliberately peels only the first component and keeps the
        // remainder verbatim (still `::`-joined) for the downstream
        // `format!("{self_type}.{name}")`/trait-associated-item lookups below.
        // Re-decomposing `name` with the generic segment splitter would flatten
        // that remainder onto `.`-joins and could change which candidates match
        // for nested associated-item paths — a real (if rare) behavior question
        // that needs its own equivalence check against the trait-item resolver,
        // not a mechanical rewrite. Revisit alongside that resolver.
        let candidates = match reference.split_once("::") {
            Some(_) if focused_segment == Some(0) => support.fqn(&self_type),
            Some((_, name)) => {
                let mut candidates = rust_member_candidates(
                    support.fqn(&format!("{self_type}.{name}")),
                    member_kind,
                );
                if candidates.is_empty() {
                    // The enclosing impl's type may get the associated item from an
                    // implemented trait; the owner fqn is already resolved, so this
                    // enters the shared resolver past its scoped-path step.
                    let Some(refs) = support.forward_reference_context(rust, token, file) else {
                        return no_definition(
                            "cancelled",
                            "Rust definition resolution was cancelled",
                        );
                    };
                    let matches_kind: fn(&CodeUnit) -> bool = match member_kind {
                        RustMemberKind::Field => CodeUnit::is_field,
                        RustMemberKind::Function => CodeUnit::is_function,
                    };
                    candidates = match crate::analyzer::usages::rust_graph::resolve_trait_associated_item_matching(
                            rust, support, &refs, file, &self_type, name,
                            matches_kind,
                            site.focus_start_byte,
                        ) {
                            ReceiverAnalysisOutcome::Precise(resolved) => {
                                rust_member_candidates(resolved, member_kind)
                            }
                            ReceiverAnalysisOutcome::Ambiguous(_)
                            | ReceiverAnalysisOutcome::Unknown
                            | ReceiverAnalysisOutcome::Unsupported { .. }
                            | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
                        };
                }
                if candidates.is_empty() && member_kind == RustMemberKind::Function {
                    // `Self::Variant(..)` reads syntactically as a call yet names a
                    // tuple enum variant — a field-namespace member, not a method.
                    // Without this, the variant is missed and the reference falls
                    // through to a false import-boundary claim even though the
                    // variant is indexed in this file (issue #1126 nushell
                    // `SqliteError` vs `use rusqlite::Error as SqliteError`).
                    candidates = support
                        .fqn(&format!("{self_type}.{name}"))
                        .into_iter()
                        .filter(|candidate| candidate.is_field())
                        .collect();
                }
                candidates
            }
            None => support.fqn(&self_type),
        };
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }
    if let Some(tree) = tree
        && let Some(outcome) = rust_focused_terminal_scoped_declaration_outcome(
            analyzer, token, rust, support, file, source, tree, site, cache,
        )
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_focused_use_path_outcome(analyzer, token, rust, support, file, source, tree, site)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) = rust_focused_scoped_prefix_outcome(
            analyzer, token, rust, support, file, source, tree, site,
        )
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(candidates) = rust_focused_terminal_scoped_type_candidates(
            analyzer, token, rust, support, file, source, tree, site,
        )
    {
        return candidates_outcome(candidates);
    }
    // fqname-M4: `reference` is an arbitrary bare Rust path (`a::b::c::d`);
    // `rsplit_once` peels only the terminal segment as `name` and keeps
    // everything before the last `::` joined verbatim as `path`, which is fed
    // as an opaque string into `resolve_scoped_associated_item_matching` and
    // the focused-use-path/scoped-prefix resolvers above. Those resolvers
    // themselves re-derive structure from `path` (module lookups, `use`
    // resolution) in ways not yet threaded onto `FqName`; migrating this split
    // alone without also migrating those callees risks a shape mismatch this
    // batch cannot fully prove via the touched suites. Revisit once the scoped
    // associated-item resolver chain carries segments end-to-end.
    let (candidates, scoped_lookup_failed) = if let Some((path, name)) = reference.rsplit_once("::")
    {
        let Some(refs) = support.forward_reference_context(rust, token, file) else {
            return no_definition("cancelled", "Rust definition resolution was cancelled");
        };
        let role = tree
            .and_then(|tree| rust_bare_reference_role(tree, site, source))
            .unwrap_or(RustBareReferenceRole::Callable);
        let mut resolved =
            match crate::analyzer::usages::rust_graph::resolve_scoped_associated_item_matching(
                rust,
                support,
                &refs,
                file,
                path,
                name,
                rust_scoped_role_candidate(role),
                site.focus_start_byte,
            ) {
                ReceiverAnalysisOutcome::Precise(candidates) => {
                    // The role filter is a namespace decision the resolver
                    // already makes: a scoped path used as a type does not
                    // accept a value-namespace item of the same name. Recording
                    // what it discards is what lets Rust claim the rejection
                    // axis; nothing here is recomputed.
                    let (accepted, refused): (Vec<_>, Vec<_>) = candidates
                        .into_iter()
                        .partition(|candidate| rust_role_accepts_scoped(rust, role, candidate));
                    trace_rejected_units(
                        &refused,
                        PrecedenceTier::PackageOrModule,
                        RejectionReason::WrongNamespace,
                    );
                    accepted
                }
                ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Unknown
                | ReceiverAnalysisOutcome::Unsupported { .. }
                | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
            };
        if resolved.is_empty()
            && let Some(tree) = tree
            && let Some(local) = rust_local_scoped_owner_member_candidates(
                analyzer, token, rust, support, file, source, tree, site, name, role, cache,
            )
        {
            resolved = local;
        }
        (resolved, true)
    } else {
        let resolved = if let Some(tree) = tree
            && let Some(role) = rust_bare_reference_role(tree, site, source)
        {
            if role == RustBareReferenceRole::Type
                && lexical_scope::local_item_name_shadowed_in_tree(
                    tree.root_node(),
                    source,
                    reference,
                    site.focus_start_byte,
                )
            {
                return no_definition(
                    LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
                    format!("`{reference}` is a local Rust item, which is not indexed"),
                );
            }
            match rust_visible_import_resolution(
                rust,
                token,
                support,
                file,
                source,
                site.focus_start_byte,
                reference,
                role,
            ) {
                RustVisibleImportResolution::Resolved(candidates) => {
                    trace_selected_units(&candidates, PrecedenceTier::ExplicitImport);
                    candidates
                }
                RustVisibleImportResolution::GlobResolved(candidates) => {
                    let local = rust_current_module_candidates(
                        analyzer,
                        rust,
                        support,
                        file,
                        tree.root_node(),
                        site.focus_start_byte,
                        site.focus_end_byte,
                        reference,
                        role,
                    );
                    if local.is_empty() {
                        trace_selected_units(&candidates, PrecedenceTier::WildcardImport);
                        candidates
                    } else {
                        // Both sets are computed here and the module wins, so
                        // the glob candidates are a rejection the resolver
                        // performed rather than one this trace invented.
                        trace_selected_units(&local, PrecedenceTier::PackageOrModule);
                        trace_rejected_units(
                            &candidates,
                            PrecedenceTier::WildcardImport,
                            RejectionReason::ShadowedByNearer,
                        );
                        local
                    }
                }
                RustVisibleImportResolution::BoundButUnindexed => {
                    // An unresolvable import must not blind the reference to a
                    // same-named local item in another namespace: Rust keeps
                    // types and macros in separate namespaces, so a derive
                    // re-export (`pub use diesel_derives::AsExpression;`)
                    // never shadows the trait defined in the same file —
                    // claiming an unindexed boundary there is dishonest
                    // (tier-3 diesel/ripgrep/meilisearch/nushell evidence).
                    let lexical = (role == RustBareReferenceRole::Type)
                        .then(|| {
                            resolve_in_enclosing_scopes(
                                analyzer,
                                file,
                                reference,
                                site.focus_start_byte,
                                CodeUnit::is_class,
                            )
                        })
                        .flatten()
                        .filter(|unit| rust_declaration_is_trait(rust, unit));
                    // The import route is bound but unindexed, and the workspace
                    // nonetheless supplies the name: the route loses to a
                    // workspace declaration, which is a decision this arm makes
                    // and the trace reports.
                    if let Some(unit) = lexical {
                        trace_rejected_import_route(
                            file,
                            reference,
                            BoundaryStatus::ExternalDeclaredUnindexed,
                        );
                        trace_selected_units(
                            std::slice::from_ref(&unit),
                            PrecedenceTier::OwnMember,
                        );
                        return candidates_outcome(vec![unit]);
                    }
                    let local = rust_current_module_candidates(
                        analyzer,
                        rust,
                        support,
                        file,
                        tree.root_node(),
                        site.focus_start_byte,
                        site.focus_end_byte,
                        reference,
                        role,
                    )
                    .into_iter()
                    .filter(|unit| {
                        role != RustBareReferenceRole::Type || rust_declaration_is_trait(rust, unit)
                    })
                    .collect::<Vec<_>>();
                    if !local.is_empty() {
                        trace_rejected_import_route(
                            file,
                            reference,
                            BoundaryStatus::ExternalDeclaredUnindexed,
                        );
                        trace_selected_units(&local, PrecedenceTier::PackageOrModule);
                        return candidates_outcome(local);
                    }
                    if let Some(unit) = rust_enclosing_scope_type_fallback(
                        analyzer,
                        file,
                        reference,
                        site.focus_start_byte,
                    )
                    .filter(|unit| {
                        role != RustBareReferenceRole::Type || rust_declaration_is_trait(rust, unit)
                    }) {
                        return candidates_outcome(vec![unit]);
                    }
                    // gated upstream: the enclosing-scope member fallback and the
                    // current-module candidates just above are the workspace
                    // check; only a genuinely-unindexed import reaches here.
                    return boundary_unchecked(format!(
                        "`{reference}` is explicitly imported across a Rust crate/module boundary that is not indexed"
                    ));
                }
                RustVisibleImportResolution::GlobBoundButUnindexed => {
                    return boundary_unchecked(format!(
                        "`{reference}` is inherited from an unindexed Rust import"
                    ));
                }
                RustVisibleImportResolution::Unbound => {
                    // A bare name is first resolved in its physical module. The
                    // enclosing CodeUnit can have a different logical owner -- for
                    // example, a child-file `impl From<Local> for parent::Local`
                    // is stored beneath the parent type -- and must not make that
                    // owner shadow the child module's own declaration (#2129).
                    let module = rust_current_module_candidates(
                        analyzer,
                        rust,
                        support,
                        file,
                        tree.root_node(),
                        site.focus_start_byte,
                        site.focus_end_byte,
                        reference,
                        role,
                    );
                    if !module.is_empty() {
                        trace_selected_units(&module, PrecedenceTier::PackageOrModule);
                        module
                    } else {
                        // Only an unbound name may fall back to a lexically
                        // enclosing declaration. An explicit import is
                        // authoritative even when a same-named type exists in
                        // the surrounding file/module.
                        let lexical = (role == RustBareReferenceRole::Type)
                            .then(|| {
                                resolve_in_enclosing_scopes(
                                    analyzer,
                                    file,
                                    reference,
                                    site.focus_start_byte,
                                    CodeUnit::is_class,
                                )
                            })
                            .flatten();
                        lexical.map_or_else(Vec::new, |unit| {
                            trace_selected_units(
                                std::slice::from_ref(&unit),
                                PrecedenceTier::OwnMember,
                            );
                            vec![unit]
                        })
                    }
                }
            }
        } else {
            let Some(refs) = support.forward_reference_context(rust, token, file) else {
                return no_definition("cancelled", "Rust definition resolution was cancelled");
            };
            refs.resolve_bare(reference)
                .map(|fqn| support.fqn(&fqn))
                .unwrap_or_default()
        };
        (resolved, false)
    };
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if rust_reference_looks_external(reference) {
        // A `::`-qualified reference reaches here only after the scoped-
        // associated-item and visible-import paths above are exhausted. Before a
        // confident boundary claim, consult the enclosing lexical scope: now that
        // the shared resolver is separator-aware (#1162), the member fallback can
        // match a `::`-qualified path (`inner::Config` -> a workspace-declared
        // enclosing-scope `inner.Config`) instead of being inert as the ff08191a
        // NOTE recorded. Rust's own scoped-associated resolution already catches
        // every enclosing-qualified workspace shape upstream (see
        // issue_1162's rust pin), so this fires only as the #1126 safety net for
        // a future upstream regression — a genuinely-external `::` path yields
        // `None` here and still draws the boundary.
        if rust_qualified_head_is_proven_route(
            analyzer,
            token,
            rust,
            file,
            source,
            reference,
            site.focus_start_byte,
        ) && let Some(unit) =
            rust_enclosing_scope_type_fallback(analyzer, file, reference, site.focus_start_byte)
        {
            return candidates_outcome(vec![unit]);
        }
        return boundary_unchecked(format!(
            "`{reference}` appears to cross a Rust crate/module boundary not indexed in this workspace"
        ));
    }
    if scoped_lookup_failed {
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve through its Rust module path"),
        );
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed Rust definition"),
    )
}

fn rust_struct_field_name_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    match classify_rust_field_name(focused) {
        RustFieldNameRole::Declaration { name }
            if name.start_byte() == site.focus_start_byte
                && name.end_byte() == site.focus_end_byte =>
        {
            Some(no_definition(
                DECLARATION_OR_IMPORT_SITE_DIAGNOSTIC_KIND,
                "Rust field declaration names do not reference another definition",
            ))
        }
        RustFieldNameRole::Reference {
            owner_type,
            name,
            container: RustStructFieldContainer::Literal | RustStructFieldContainer::Pattern,
        } if name.start_byte() == site.focus_start_byte
            && name.end_byte() == site.focus_end_byte =>
        {
            if name.parent().is_some_and(|field| {
                field.kind() == "field_pattern" && field.child_by_field_name("pattern").is_none()
            }) {
                return Some(no_definition(
                    LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
                    "Rust shorthand struct-pattern fields introduce local bindings",
                ));
            }
            let field_name = &source[name.byte_range()];
            let Some(owner) = rust_resolve_type_node_fqn(
                analyzer,
                token,
                support,
                file,
                source,
                owner_type,
                Some(owner_type.start_byte()),
            )
            .or_else(|| {
                rust_resolve_struct_pattern_variant_owner(
                    analyzer, token, support, file, source, owner_type, field_name,
                )
            }) else {
                return Some(no_definition(
                    "unresolved_struct_owner",
                    "Rust struct field owner could not be resolved",
                ));
            };
            let candidates = support
                .fqn(&format!("{owner}.{field_name}"))
                .into_iter()
                .filter(CodeUnit::is_field)
                .collect();
            Some(candidates_outcome(candidates))
        }
        RustFieldNameRole::Other
        | RustFieldNameRole::Declaration { .. }
        | RustFieldNameRole::Reference { .. } => None,
    }
}

fn rust_resolve_struct_pattern_variant_owner(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    owner_type: Node<'_>,
    field_name: &str,
) -> Option<String> {
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
    let type_ref = rust_type_ref(support, owner_type, source)?;
    let refs = support.forward_reference_context(rust, token, file)?;
    let owner = match type_ref.path.as_deref() {
        Some(path) => refs.resolve_scoped(path, &type_ref.name)?,
        None => refs.resolve_bare(&type_ref.name)?.to_string(),
    };
    support
        .members_for_owner_name(&owner, field_name)
        .into_iter()
        .any(|candidate| candidate.is_field())
        .then_some(owner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustBareReferenceRole {
    Type,
    // Rust struct and enum constructors occupy the value namespace too.
    Value,
    Callable,
    Owner,
    Macro,
}

enum RustVisibleImportResolution {
    Resolved(Vec<CodeUnit>),
    GlobResolved(Vec<CodeUnit>),
    BoundButUnindexed,
    GlobBoundButUnindexed,
    Unbound,
}

fn rust_exact_reference_role_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    if brokk_bifrost_rust::graph::ast::is_rust_declaration_name(focused) {
        return Some(no_definition(
            DECLARATION_OR_IMPORT_SITE_DIAGNOSTIC_KIND,
            "Rust declaration names do not reference another definition",
        ));
    }
    if let Some(outcome) =
        rust_macro_argument_outcome(analyzer, token, support, file, source, tree, site, focused)
    {
        return Some(outcome);
    }
    if crate::analyzer::usages::rust_graph::rust_bare_token_tree_non_reference_role(focused, source)
    {
        let focused_name = rust_node_text(focused, source).trim();
        return Some(no_definition(
            "local_binding",
            format!(
                "`{focused_name}` occupies a declaration or local binding role in a Rust macro token tree"
            ),
        ));
    }
    if rust_enclosing_lifetime(focused).is_some() {
        return Some(no_definition(
            LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
            "Rust lifetime parameters are lexical bindings and are not indexed definitions",
        ));
    }
    if focused.kind() == "self" && focused_rust_field_receiver(focused, site.focus_start_byte) {
        return Some(no_definition(
            LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
            "the focused Rust receiver is a local expression, which is not indexed",
        ));
    }

    let focused_name = rust_node_text(focused, source).trim();
    if focused.kind() == "type_identifier"
        && rust_type_parameter_visible_from(focused, source, focused_name)
    {
        return Some(no_definition(
            LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
            format!("`{focused_name}` is a lexical Rust type parameter, which is not indexed"),
        ));
    }

    if let Some(type_binding) = rust_enclosing_type_binding_name(focused) {
        return Some(rust_type_binding_name_outcome(
            analyzer,
            token,
            support,
            file,
            source,
            type_binding,
        ));
    }

    if let Some(macro_invocation) = rust_enclosing_macro_name(focused) {
        return rust_macro_name_outcome(
            analyzer,
            token,
            support,
            file,
            source,
            tree,
            site,
            macro_invocation,
            focused,
        );
    }

    if matches!(focused.kind(), "identifier" | "shorthand_field_identifier") {
        let shadowed = lexical_scope::name_shadowed_in_tree(
            tree.root_node(),
            source,
            focused_name,
            site.focus_start_byte,
        );
        if lexical_scope::is_pattern_binding_identifier(focused) && !shadowed {
            return Some(no_definition(
                "local_binding",
                format!("`{focused_name}` is a local Rust binding, which is not indexed"),
            ));
        }
        if shadowed
            && (rust_identifier_is_explicit_receiver(focused) || !site.text.contains(['.', ':']))
        {
            return Some(no_definition(
                LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
                format!("`{focused_name}` is a local Rust binding, which is not indexed"),
            ));
        }
    }
    None
}

fn rust_imported_pattern_variant_outcome(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let possible_unit_variant = lexical_scope::is_pattern_binding_identifier(focused);
    let possible_constructor_variant =
        std::iter::successors(focused.parent(), |node| node.parent())
            .take_while(|node| !matches!(node.kind(), "match_arm" | "block" | "function_item"))
            .any(|node| {
                matches!(node.kind(), "tuple_struct_pattern" | "struct_pattern")
                    && node
                        .child_by_field_name("type")
                        .is_some_and(|r#type| node_within(r#type, focused))
            });
    if !possible_unit_variant && !possible_constructor_variant {
        return None;
    }

    let name = rust_node_text(focused, source).trim();
    if name.is_empty() {
        return None;
    }
    let candidates = match rust_visible_import_resolution(
        rust,
        token,
        support,
        file,
        source,
        site.focus_start_byte,
        name,
        RustBareReferenceRole::Value,
    ) {
        RustVisibleImportResolution::Resolved(candidates)
        | RustVisibleImportResolution::GlobResolved(candidates) => candidates,
        RustVisibleImportResolution::BoundButUnindexed
        | RustVisibleImportResolution::GlobBoundButUnindexed
        | RustVisibleImportResolution::Unbound => return None,
    };
    let variants: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| rust_declaration_is_enum_variant(rust, candidate))
        .collect();
    (!variants.is_empty()).then(|| candidates_outcome(variants))
}

fn rust_enclosing_lifetime(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "lifetime" {
            return Some(node);
        }
        if matches!(
            node.kind(),
            "type_identifier" | "scoped_type_identifier" | "identifier"
        ) && node
            .parent()
            .is_some_and(|parent| parent.kind() != "lifetime")
        {
            return None;
        }
        node = node.parent()?;
    }
}

fn rust_type_parameter_visible_from(mut node: Node<'_>, source: &str, name: &str) -> bool {
    loop {
        if let Some(parameters) = node.child_by_field_name("type_parameters") {
            let mut cursor = parameters.walk();
            if parameters.named_children(&mut cursor).any(|parameter| {
                parameter.kind() == "type_parameter"
                    && parameter
                        .child_by_field_name("name")
                        .is_some_and(|parameter_name| {
                            rust_node_text(parameter_name, source).trim() == name
                        })
            }) {
                return true;
            }
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        node = parent;
    }
}

fn rust_enclosing_type_binding_name(focused: Node<'_>) -> Option<Node<'_>> {
    let mut node = focused;
    loop {
        if node.kind() == "type_binding" {
            return node
                .child_by_field_name("name")
                .is_some_and(|name| node_within(name, focused))
                .then_some(node);
        }
        if matches!(node.kind(), "generic_type" | "trait_bounds") {
            return None;
        }
        node = node.parent()?;
    }
}

fn rust_type_binding_name_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    binding: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(name) = binding.child_by_field_name("name") else {
        return no_definition(
            "invalid_associated_type_binding",
            "Rust associated type binding has no name",
        );
    };
    let name = rust_node_text(name, source).trim();
    let mut owner = binding.parent();
    while let Some(candidate) = owner {
        if candidate.kind() == "generic_type" {
            let Some(type_node) = candidate.child_by_field_name("type") else {
                break;
            };
            let Some(owner_fqn) = rust_resolve_type_node_fqn(
                analyzer,
                token,
                support,
                file,
                source,
                type_node,
                Some(type_node.start_byte()),
            ) else {
                break;
            };
            let candidates: Vec<_> = support
                .fqn(&format!("{owner_fqn}.{name}"))
                .into_iter()
                .filter(CodeUnit::is_field)
                .collect();
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            break;
        }
        if matches!(candidate.kind(), "where_predicate" | "function_item") {
            break;
        }
        owner = candidate.parent();
    }
    no_definition(
        "unresolved_associated_type_binding",
        format!("Rust associated type binding `{name}` did not resolve to an indexed trait item"),
    )
}

fn rust_enclosing_macro_name(focused: Node<'_>) -> Option<Node<'_>> {
    let mut node = focused;
    loop {
        if node.kind() == "macro_invocation" {
            return node
                .child_by_field_name("macro")
                .is_some_and(|macro_name| node_within(macro_name, focused))
                .then_some(node);
        }
        if node.kind() == "token_tree" {
            return None;
        }
        node = node.parent()?;
    }
}

#[allow(clippy::too_many_arguments)]
fn rust_macro_name_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    invocation: Node<'_>,
    focused: Node<'_>,
) -> Option<DefinitionLookupOutcome> {
    let macro_name = invocation.child_by_field_name("macro")?;
    if macro_name.kind() == "scoped_identifier"
        && macro_name
            .child_by_field_name("path")
            .is_some_and(|path| node_within(path, focused))
    {
        return None;
    }
    match rust_collect_macro_units(
        analyzer,
        token,
        support,
        file,
        source,
        tree,
        site.focus_start_byte,
        site.focus_end_byte,
        invocation,
        focused,
    ) {
        MacroUnitResolution::Found(candidates) if candidates.is_empty() => {
            let name = rust_macro_invocation_name(invocation, source).unwrap_or("?");
            Some(no_definition(
                "unindexed_macro",
                format!("Rust macro `{name}` did not resolve to an indexed macro definition"),
            ))
        }
        MacroUnitResolution::Found(candidates) => Some(candidates_outcome(candidates)),
        MacroUnitResolution::Boundary(outcome) => Some(*outcome),
        MacroUnitResolution::NotAMacroName => None,
    }
}

enum MacroUnitResolution {
    Found(Vec<CodeUnit>),
    Boundary(Box<DefinitionLookupOutcome>),
    NotAMacroName,
}

fn rust_macro_invocation_name<'a>(invocation: Node<'_>, source: &'a str) -> Option<&'a str> {
    let macro_name = invocation.child_by_field_name("macro")?;
    let name_node = macro_name.child_by_field_name("name").unwrap_or(macro_name);
    let name = rust_node_text(name_node, source).trim();
    (!name.is_empty()).then_some(name)
}

#[allow(clippy::too_many_arguments)]
fn rust_collect_macro_units(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    lookup_start: usize,
    lookup_end: usize,
    invocation: Node<'_>,
    focused: Node<'_>,
) -> MacroUnitResolution {
    let Some(macro_name) = invocation.child_by_field_name("macro") else {
        return MacroUnitResolution::Found(Vec::new());
    };
    if macro_name.kind() == "scoped_identifier"
        && macro_name
            .child_by_field_name("path")
            .is_some_and(|path| node_within(path, focused))
    {
        return MacroUnitResolution::NotAMacroName;
    }
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return MacroUnitResolution::Found(Vec::new());
    };
    let Some(refs) = support.forward_reference_context(rust, token, file) else {
        return MacroUnitResolution::Found(Vec::new());
    };
    let name_node = macro_name.child_by_field_name("name").unwrap_or(macro_name);
    let name = rust_node_text(name_node, source).trim();
    let mut candidates = if let Some(path) = macro_name.child_by_field_name("path") {
        let path = rust_node_text(path, source).trim();
        refs.resolve_scoped(path, name)
            .into_iter()
            .flat_map(|fqn| support.fqn(&fqn))
            .filter(CodeUnit::is_macro)
            .collect()
    } else {
        match rust_visible_import_resolution(
            rust,
            token,
            support,
            file,
            source,
            lookup_start,
            name,
            RustBareReferenceRole::Macro,
        ) {
            RustVisibleImportResolution::Resolved(candidates)
            | RustVisibleImportResolution::GlobResolved(candidates) => candidates,
            RustVisibleImportResolution::BoundButUnindexed => {
                if let Some(unit) = resolve_in_enclosing_scopes(
                    analyzer,
                    file,
                    name,
                    lookup_start,
                    CodeUnit::is_macro,
                ) {
                    vec![unit]
                } else {
                    let same_package = rust_same_package_macros(analyzer, rust, file, name);
                    if same_package.is_empty() {
                        return MacroUnitResolution::Boundary(Box::new(boundary_unchecked(
                            format!(
                                "Rust macro `{name}` is imported across a crate/module boundary that is not indexed"
                            ),
                        )));
                    }
                    same_package
                }
            }
            RustVisibleImportResolution::GlobBoundButUnindexed => {
                return MacroUnitResolution::Boundary(Box::new(boundary_unchecked(format!(
                    "Rust macro `{name}` is inherited from an unindexed import"
                ))));
            }
            RustVisibleImportResolution::Unbound => rust_current_module_candidates(
                analyzer,
                rust,
                support,
                file,
                tree.root_node(),
                lookup_start,
                lookup_end,
                name,
                RustBareReferenceRole::Macro,
            ),
        }
    };
    if candidates.is_empty()
        && let Some(unit) =
            resolve_in_enclosing_scopes(analyzer, file, name, lookup_start, CodeUnit::is_macro)
    {
        candidates = vec![unit];
    }
    if candidates.is_empty() {
        candidates = rust_same_package_macros(analyzer, rust, file, name);
    }
    MacroUnitResolution::Found(candidates)
}

fn rust_same_crate_types(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let crate_root = rust_crate_root_package(file);
    rust.get_analyzed_files()
        .into_iter()
        .filter(|candidate| rust_crate_root_package(candidate) == crate_root)
        .flat_map(|candidate| analyzer.declarations(&candidate))
        .filter(|unit| {
            unit.identifier() == name
                && (unit.is_class() || rust_declaration_is_module_type_alias(rust, unit))
        })
        .collect()
}

fn rust_same_package_macros(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let crate_root = rust_crate_root_package(file);
    rust.get_analyzed_files()
        .into_iter()
        .filter(|candidate| rust_crate_root_package(candidate) == crate_root)
        .flat_map(|candidate| analyzer.declarations(&candidate))
        .filter(|unit| unit.is_macro() && unit.identifier() == name)
        .collect()
}

pub(crate) fn ingest_file_macro_matcher_roles(
    cache: &mut RustTokenTreeRoleCache,
    token: QueryToken<'_>,
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
) {
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "macro_invocation" {
            ingest_invocation_matcher_roles(
                cache, token, analyzer, support, file, source, tree, node,
            );
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
}

#[allow(clippy::too_many_arguments)]
fn ingest_invocation_matcher_roles(
    cache: &mut RustTokenTreeRoleCache,
    token: QueryToken<'_>,
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    invocation: Node<'_>,
) {
    let Some(arguments) = rust_macro_invocation_arguments(invocation) else {
        return;
    };
    let MacroUnitResolution::Found(units) = rust_collect_macro_units(
        analyzer,
        token,
        support,
        file,
        source,
        tree,
        invocation.start_byte(),
        invocation.end_byte(),
        invocation,
        arguments,
    ) else {
        return;
    };
    for unit in &units {
        let Some((def_source, def_tree)) = rust_macro_definition_source(unit, file, source, tree)
        else {
            continue;
        };
        let Some(definition) = rust_macro_definition_node(analyzer, unit, &def_tree) else {
            continue;
        };
        if !is_macro_rules_definition(definition, &def_source) {
            continue;
        }
        let Ok(arm_match) = match_macro_rules(definition, &def_source, arguments, source) else {
            continue;
        };
        for binding in &arm_match.bindings {
            let namespace = token_namespace_evidence(
                &arm_match,
                definition,
                &def_source,
                binding.start_byte,
                binding.end_byte,
            )
            .unwrap_or(MacroNamespaceEvidence::NoNamespace);
            match namespace {
                MacroNamespaceEvidence::Interior(fragment) => {
                    ingest_interior_fragment_roles(
                        cache,
                        fragment,
                        source,
                        arguments,
                        binding.start_byte,
                        binding.end_byte,
                    );
                }
                other => {
                    if let Some(role) = matcher_namespace_to_role(other) {
                        cache.ingest_matcher_role(binding.start_byte, binding.end_byte, role);
                    }
                }
            }
        }
    }
}

fn ingest_interior_fragment_roles(
    cache: &mut RustTokenTreeRoleCache,
    fragment: MacroFragmentKind,
    source: &str,
    arguments: Node<'_>,
    start: usize,
    end: usize,
) {
    let Some(fragment_source) = source.get(start..end) else {
        return;
    };
    let mut stack = vec![arguments];
    while let Some(node) = stack.pop() {
        if node.end_byte() <= start || node.start_byte() >= end {
            continue;
        }
        if matches!(node.kind(), "identifier" | "type_identifier")
            && node.start_byte() >= start
            && node.end_byte() <= end
        {
            let rel_start = node.start_byte() - start;
            let rel_end = node.end_byte() - start;
            if let Some(namespace) = macro_matcher::classify_fragment_interior(
                fragment,
                fragment_source,
                rel_start,
                rel_end,
            ) && let Some(role) = matcher_namespace_to_role(namespace)
            {
                cache.ingest_matcher_role(node.start_byte(), node.end_byte(), role);
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
}

fn matcher_namespace_to_role(namespace: MacroNamespaceEvidence) -> Option<RustBareTokenTreeRole> {
    Some(match namespace {
        MacroNamespaceEvidence::Type => RustBareTokenTreeRole::TypeReference,
        MacroNamespaceEvidence::Value => RustBareTokenTreeRole::Reference,
        MacroNamespaceEvidence::Pattern => RustBareTokenTreeRole::Pattern,
        MacroNamespaceEvidence::Declaration => RustBareTokenTreeRole::Declaration,
        MacroNamespaceEvidence::NoNamespace => RustBareTokenTreeRole::NoNamespace,
        MacroNamespaceEvidence::Interior(_) => return None,
    })
}

pub(super) fn focused_site_is_macro_argument(root: Node<'_>, site: &ResolvedReferenceSite) -> bool {
    smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
        .is_some_and(|node| enclosing_macro_invocation_for_argument(node).is_some())
}

#[allow(clippy::too_many_arguments)]
fn rust_macro_argument_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    focused: Node<'_>,
) -> Option<DefinitionLookupOutcome> {
    let invocation = enclosing_macro_invocation_for_argument(focused)?;
    let Some(arguments) = rust_macro_invocation_arguments(invocation) else {
        return Some(no_definition(
            MACRO_MATCHER_FAILED_DIAGNOSTIC_KIND,
            "Rust macro invocation has no argument token tree",
        ));
    };
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return Some(no_definition(
            "rust_analyzer_unavailable",
            "Rust analyzer is unavailable",
        ));
    };
    let name_node = invocation
        .child_by_field_name("macro")
        .map(|macro_name| macro_name.child_by_field_name("name").unwrap_or(macro_name));
    let macro_name = name_node
        .map(|node| rust_node_text(node, source).trim().to_string())
        .unwrap_or_default();
    let units = match rust_collect_macro_units(
        analyzer,
        token,
        support,
        file,
        source,
        tree,
        invocation.start_byte(),
        invocation.end_byte(),
        invocation,
        focused,
    ) {
        MacroUnitResolution::Found(units) => units,
        MacroUnitResolution::Boundary(outcome) => {
            return Some(argument_boundary_outcome(&macro_name, *outcome));
        }
        MacroUnitResolution::NotAMacroName => return None,
    };
    if units.is_empty() {
        // An opaque macro matcher cannot classify a bare token's namespace,
        // but qualified paths, receiver-member expressions, constructor calls,
        // and exact imports inside a nested macro already carry structured
        // evidence. Let the existing Rust resolver consume that evidence
        // instead of allowing the missing matcher to hide an indexed local
        // definition.
        if rust_macro_argument_has_structured_reference(focused, source, site)
            || rust_macro_argument_has_resolved_nested_import(
                rust, token, support, file, source, site, focused,
            )
        {
            return None;
        }
        return Some(boundary_unchecked(format!(
            "Rust macro `{macro_name}` is defined outside the indexed workspace and matcher evidence is unavailable"
        )));
    }
    let mut evidences = Vec::new();
    let mut saw_macro_rules = false;
    for unit in &units {
        let Some((def_source, def_tree)) = rust_macro_definition_source(unit, file, source, tree)
        else {
            continue;
        };
        let Some(definition) = rust_macro_definition_node(analyzer, unit, &def_tree) else {
            continue;
        };
        if !is_macro_rules_definition(definition, &def_source) {
            continue;
        }
        saw_macro_rules = true;
        match match_macro_rules(definition, &def_source, arguments, source) {
            Ok(arm_match) => {
                let Some(binding) =
                    arm_match.binding_containing(site.focus_start_byte, site.focus_end_byte)
                else {
                    continue;
                };
                let Some(namespace) = token_namespace_evidence(
                    &arm_match,
                    definition,
                    &def_source,
                    site.focus_start_byte,
                    site.focus_end_byte,
                ) else {
                    continue;
                };
                let namespace = match namespace {
                    MacroNamespaceEvidence::Interior(fragment) => {
                        let rel_start = site.focus_start_byte.saturating_sub(binding.start_byte);
                        let rel_end = site.focus_end_byte.saturating_sub(binding.start_byte);
                        let Some(fragment_source) =
                            source.get(binding.start_byte..binding.end_byte)
                        else {
                            continue;
                        };
                        macro_matcher::classify_fragment_interior(
                            fragment,
                            fragment_source,
                            rel_start,
                            rel_end,
                        )
                        .unwrap_or(MacroNamespaceEvidence::NoNamespace)
                    }
                    other => other,
                };
                evidences.push(MatcherTokenEvidence {
                    fqn: unit.fq_name(),
                    arm: arm_match.arm_index,
                    metavar: binding.name.clone(),
                    fragment: binding.fragment,
                    namespace,
                });
            }
            Err(MacroMatchError::NoArmMatched) => {}
            Err(MacroMatchError::NotMacroRules | MacroMatchError::EmptyRules) => {}
        }
    }
    if !saw_macro_rules {
        return Some(boundary_unchecked(format!(
            "Rust macro `{macro_name}` is defined outside the indexed workspace and matcher evidence is unavailable"
        )));
    }
    if evidences.is_empty() {
        return Some(no_definition(
            MACRO_MATCHER_FAILED_DIAGNOSTIC_KIND,
            format!("Rust macro `{macro_name}` has no matcher arm that accepts this invocation"),
        ));
    }
    let first = &evidences[0];
    if evidences.iter().any(|evidence| {
        evidence.fragment != first.fragment || evidence.namespace != first.namespace
    }) {
        return Some(no_definition(
            MACRO_MATCHER_DISAGREEMENT_DIAGNOSTIC_KIND,
            format!(
                "Rust macro `{macro_name}` matcher arms bind this token with disagreeing fragment kinds or roles"
            ),
        ));
    }
    if first.namespace == MacroNamespaceEvidence::NoNamespace
        && (rust_macro_argument_has_structured_reference(focused, source, site)
            || rust_macro_argument_has_resolved_nested_import(
                rust, token, support, file, source, site, focused,
            ))
    {
        return None;
    }
    Some(rust_matcher_namespace_outcome(
        analyzer, token, rust, support, file, source, tree, site, focused, first,
    ))
}

fn rust_macro_argument_has_structured_reference(
    focused: Node<'_>,
    source: &str,
    site: &ResolvedReferenceSite,
) -> bool {
    let focused = rust_macro_argument_focused_node(focused, site);
    if brokk_bifrost_rust::graph::resolver::token_tree_ancestor(focused).is_none() {
        return false;
    }
    if matches!(
        focused.kind(),
        "scoped_identifier" | "scoped_type_identifier"
    ) {
        return true;
    }
    if brokk_bifrost_rust::graph::resolver::rust_token_path_segment_is_qualified(focused) {
        return true;
    }
    if matches!(
        crate::analyzer::usages::rust_graph::rust_bare_token_tree_role(focused, source),
        RustBareTokenTreeRole::Pattern | RustBareTokenTreeRole::TypeReference
    ) {
        return true;
    }
    focused.parent().is_some_and(|parent| {
        parent.kind() == "token_tree"
            && ((focused
                .prev_sibling()
                .is_some_and(|token| token.kind() == ".")
                && focused
                    .prev_sibling()
                    .and_then(|separator| separator.prev_sibling())
                    .is_some_and(|receiver| matches!(receiver.kind(), "identifier" | "self")))
                || (focused
                    .next_sibling()
                    .is_some_and(|token| token.kind() == ".")
                    && focused
                        .next_sibling()
                        .and_then(|separator| separator.next_sibling())
                        .is_some_and(|member| member.kind() == "identifier"))
                || focused.next_sibling().is_some_and(|arguments| {
                    arguments.kind() == "token_tree"
                        && arguments.child(0).is_some_and(|open| open.kind() == "(")
                }))
    })
}

fn rust_macro_argument_has_resolved_nested_import(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    focused: Node<'_>,
) -> bool {
    let focused = rust_macro_argument_focused_node(focused, site);
    let Some(arguments) = brokk_bifrost_rust::graph::resolver::token_tree_ancestor(focused) else {
        return false;
    };
    let nested_macro = arguments.parent().is_some_and(|parent| {
        parent.kind() == "token_tree"
            && arguments
                .prev_sibling()
                .is_some_and(|separator| separator.kind() == "!")
            && arguments
                .prev_sibling()
                .and_then(|separator| separator.prev_sibling())
                .is_some_and(|name| name.kind() == "identifier")
    });
    if !nested_macro {
        return false;
    }
    let name = rust_node_text(focused, source).trim();
    !name.is_empty()
        && matches!(
            rust_visible_import_resolution(
                rust,
                token,
                support,
                file,
                source,
                site.focus_start_byte,
                name,
                RustBareReferenceRole::Value,
            ),
            RustVisibleImportResolution::Resolved(_) | RustVisibleImportResolution::GlobResolved(_)
        )
}

fn rust_macro_argument_focused_node<'tree>(
    focused: Node<'tree>,
    site: &ResolvedReferenceSite,
) -> Node<'tree> {
    focused
        .descendant_for_byte_range(site.focus_start_byte, site.focus_end_byte)
        .unwrap_or(focused)
}

fn argument_boundary_outcome(
    macro_name: &str,
    mut outcome: DefinitionLookupOutcome,
) -> DefinitionLookupOutcome {
    if outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary {
        outcome.diagnostics.insert(
            0,
            DefinitionLookupDiagnostic {
                kind: "unresolvable_import_boundary".to_string(),
                message: format!(
                    "Rust macro `{macro_name}` is defined outside the indexed workspace and matcher evidence is unavailable"
                ),
            },
        );
    }
    outcome
}

struct MatcherTokenEvidence {
    fqn: String,
    arm: usize,
    metavar: String,
    fragment: MacroFragmentKind,
    namespace: MacroNamespaceEvidence,
}

#[allow(clippy::too_many_arguments)]
fn rust_matcher_namespace_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    focused: Node<'_>,
    evidence: &MatcherTokenEvidence,
) -> DefinitionLookupOutcome {
    let mut outcome = match evidence.namespace {
        MacroNamespaceEvidence::Declaration => no_definition(
            DECLARATION_OR_IMPORT_SITE_DIAGNOSTIC_KIND,
            format!(
                "`{}` is a macro-generated declaration name and is not an indexed reference",
                rust_node_text(focused, source).trim()
            ),
        ),
        MacroNamespaceEvidence::NoNamespace => no_definition(
            MACRO_FRAGMENT_NO_NAMESPACE_DIAGNOSTIC_KIND,
            format!(
                "`${}` is a `{}` fragment and carries no namespace evidence",
                evidence.metavar,
                evidence.fragment.as_str()
            ),
        ),
        MacroNamespaceEvidence::Type => rust_resolve_matcher_bare_name(
            analyzer,
            token,
            rust,
            support,
            file,
            source,
            tree,
            site,
            RustBareReferenceRole::Type,
        ),
        MacroNamespaceEvidence::Value | MacroNamespaceEvidence::Pattern => {
            if let Some(lexical) = rust_matcher_lexical_value(tree, source, site) {
                lexical
            } else {
                rust_resolve_matcher_bare_name(
                    analyzer,
                    token,
                    rust,
                    support,
                    file,
                    source,
                    tree,
                    site,
                    RustBareReferenceRole::Value,
                )
            }
        }
        MacroNamespaceEvidence::Interior(_) => no_definition(
            MACRO_FRAGMENT_NO_NAMESPACE_DIAGNOSTIC_KIND,
            format!(
                "`{}` is inside a `{}` fragment whose interior role could not be proven",
                rust_node_text(focused, source).trim(),
                evidence.fragment.as_str()
            ),
        ),
    };
    outcome.diagnostics.push(DefinitionLookupDiagnostic {
        kind: MACRO_MATCHER_BINDING_DIAGNOSTIC_KIND.to_string(),
        message: format!(
            "macro_fqn={} arm={} metavar=${} fragment={}",
            evidence.fqn,
            evidence.arm,
            evidence.metavar,
            evidence.fragment.as_str()
        ),
    });
    outcome
}

fn rust_matcher_lexical_value(
    tree: &Tree,
    source: &str,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let identifier = source.get(site.focus_start_byte..site.focus_end_byte)?;
    match crate::analyzer::lexical_definitions::resolve_lexical_binding(
        Language::Rust,
        tree.root_node(),
        source,
        site.focus_start_byte,
        site.focus_end_byte,
        identifier,
    ) {
        Some(
            crate::analyzer::lexical_definitions::LexicalBindingResolution::Parameter(definition)
            | crate::analyzer::lexical_definitions::LexicalBindingResolution::OtherLocal(definition),
        ) => Some(lexical_definition_outcome(definition)),
        None => {
            if lexical_scope::name_shadowed_in_tree(
                tree.root_node(),
                source,
                identifier,
                site.focus_start_byte,
            ) {
                Some(no_definition(
                    LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
                    format!("`{identifier}` is a local Rust binding, which is not indexed"),
                ))
            } else {
                None
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn rust_resolve_matcher_bare_name(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    role: RustBareReferenceRole,
) -> DefinitionLookupOutcome {
    let reference = rust_node_text(
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
            .unwrap_or_else(|| tree.root_node()),
        source,
    )
    .trim();
    match rust_visible_import_resolution(
        rust,
        token,
        support,
        file,
        source,
        site.focus_start_byte,
        reference,
        role,
    ) {
        RustVisibleImportResolution::Resolved(candidates)
        | RustVisibleImportResolution::GlobResolved(candidates) => {
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
        }
        RustVisibleImportResolution::BoundButUnindexed => {
            let local = rust_current_module_candidates(
                analyzer,
                rust,
                support,
                file,
                tree.root_node(),
                site.focus_start_byte,
                site.focus_end_byte,
                reference,
                role,
            );
            if !local.is_empty() {
                return candidates_outcome(local);
            }
            if role == RustBareReferenceRole::Type {
                if let RustVisibleImportResolution::Resolved(candidates)
                | RustVisibleImportResolution::GlobResolved(candidates) =
                    rust_visible_import_resolution(
                        rust,
                        token,
                        support,
                        file,
                        source,
                        site.focus_start_byte,
                        reference,
                        RustBareReferenceRole::Value,
                    )
                {
                    let types: Vec<_> = candidates
                        .into_iter()
                        .filter(|candidate| {
                            candidate.is_class()
                                || rust_declaration_is_module_type_alias(rust, candidate)
                        })
                        .collect();
                    if !types.is_empty() {
                        return candidates_outcome(types);
                    }
                }
                let crate_types = rust_same_crate_types(analyzer, rust, file, reference);
                if !crate_types.is_empty() {
                    return candidates_outcome(crate_types);
                }
            }
            // gated upstream: matcher-proven namespace already consulted the
            // current module and the value-namespace class view of the import.
            return boundary_unchecked(format!(
                "`{reference}` is explicitly imported across a Rust crate/module boundary that is not indexed"
            ));
        }
        RustVisibleImportResolution::GlobBoundButUnindexed => {
            return boundary_unchecked(format!(
                "`{reference}` is inherited from an unindexed Rust import"
            ));
        }
        RustVisibleImportResolution::Unbound => {}
    }
    let local = rust_current_module_candidates(
        analyzer,
        rust,
        support,
        file,
        tree.root_node(),
        site.focus_start_byte,
        site.focus_end_byte,
        reference,
        role,
    );
    if local.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!(
                "the matcher-proven `{reference}` reference resolved to no workspace definition"
            ),
        )
    } else {
        candidates_outcome(local)
    }
}

fn rust_macro_definition_source(
    unit: &CodeUnit,
    current_file: &ProjectFile,
    current_source: &str,
    current_tree: &Tree,
) -> Option<(String, Tree)> {
    if unit.source() == current_file {
        return Some((current_source.to_string(), current_tree.clone()));
    }
    let source = unit.source().read_to_string().ok()?;
    let tree = lexical_scope::parse_rust_tree(&source)?;
    Some((source, tree))
}

fn rust_macro_definition_node<'tree>(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    tree: &'tree Tree,
) -> Option<Node<'tree>> {
    let node = rust_declaration_node(analyzer, unit, tree.root_node())?;
    let mut current = node;
    loop {
        if current.kind() == "macro_definition" {
            return Some(current);
        }
        current = current.parent()?;
    }
}

fn rust_identifier_is_explicit_receiver(node: Node<'_>) -> bool {
    rust_enclosing_field_expression(node)
        .and_then(|field| field.child_by_field_name("value"))
        .is_some_and(|receiver| node_within(receiver, node))
}

fn rust_bare_reference_role(
    tree: &Tree,
    site: &ResolvedReferenceSite,
    source: &str,
) -> Option<RustBareReferenceRole> {
    let node =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    if crate::analyzer::usages::rust_graph::rust_bare_token_tree_role(node, source)
        == crate::analyzer::usages::rust_graph::RustBareTokenTreeRole::TypeReference
    {
        return Some(RustBareReferenceRole::Type);
    }
    match node.kind() {
        "type_identifier" => Some(RustBareReferenceRole::Type),
        "identifier" if rust_identifier_is_callee(node) => Some(RustBareReferenceRole::Callable),
        "identifier" => Some(RustBareReferenceRole::Value),
        _ => None,
    }
}

fn rust_identifier_is_callee(node: Node<'_>) -> bool {
    let mut function = node;
    while let Some(parent) = function.parent()
        && matches!(parent.kind(), "generic_function" | "scoped_identifier")
        && parent
            .child_by_field_name("function")
            .or_else(|| parent.child_by_field_name("name"))
            .is_some_and(|child| node_within(child, function))
    {
        function = parent;
    }
    function.parent().is_some_and(|parent| {
        parent.kind() == "call_expression"
            && parent
                .child_by_field_name("function")
                .is_some_and(|callee| node_within(callee, function))
    })
}

#[allow(clippy::too_many_arguments)]
fn rust_visible_import_resolution(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    reference_byte: usize,
    reference: &str,
    role: RustBareReferenceRole,
) -> RustVisibleImportResolution {
    // Rust resolves names one lexical scope at a time. A function-local glob
    // that supplies a name therefore wins over a module-level glob; only when
    // the inner glob does not export that name do we continue outward.
    for (scope_start, binder) in
        lexical_scope::visible_import_binders_with_scopes_at(source, reference_byte)
    {
        let explicitly_bound = rust_binder_has_external_binding(&binder, reference);
        let mut expected_fqns = HashSet::default();
        let mut expected_routes: HashMap<String, Vec<ProjectFile>> = HashMap::default();
        let mut preserve_unqualified_namespace_candidates = false;
        if explicitly_bound {
            for (local_name, binding) in &binder.bindings {
                if local_name != reference {
                    continue;
                }
                // Scope-aware fqn for `self`/`super` specifiers: Named
                // bindings (`use super::{X}`) resolve the package and append
                // the item; Namespace bindings (`use super::X`) resolve the
                // full path directly. File-level resolution pops from the
                // file's parent package and misses both (#1074).
                match binding.kind {
                    ImportKind::Named => {
                        let imported = binding.imported_name.as_deref().unwrap_or(reference);
                        if let Some(package) = resolve_rust_import_package_scoped(
                            rust,
                            token,
                            file,
                            source,
                            scope_start,
                            &binding.module_specifier,
                        ) {
                            let mut module_files =
                                resolve_module_files(rust, token, file, &binding.module_specifier);
                            if module_files.is_empty() {
                                module_files = rust
                                    .get_analyzed_files()
                                    .into_iter()
                                    .filter(|candidate| rust_package_name(candidate) == package)
                                    .collect();
                            }
                            let expected_fqn = if let Some(export_fqn) =
                                forward_export_fqn_from_files(rust, token, &module_files, imported)
                            {
                                export_fqn
                            } else {
                                format!("{package}.{imported}")
                            };
                            expected_routes
                                .entry(expected_fqn.clone())
                                .or_default()
                                .extend(module_files.iter().cloned());
                            expected_fqns.insert(expected_fqn);
                            if role == RustBareReferenceRole::Value {
                                let module_value_fqn = format!("{package}._module_.{imported}");
                                expected_routes
                                    .entry(module_value_fqn.clone())
                                    .or_default()
                                    .extend(module_files.iter().cloned());
                                expected_fqns.insert(module_value_fqn);
                            }
                        }
                    }
                    ImportKind::Namespace => {
                        preserve_unqualified_namespace_candidates = true;
                        if let Some(fqn) = resolve_rust_import_package_scoped(
                            rust,
                            token,
                            file,
                            source,
                            scope_start,
                            &binding.module_specifier,
                        ) {
                            expected_routes.entry(fqn.clone()).or_default().extend(
                                resolve_module_files(rust, token, file, &binding.module_specifier),
                            );
                            expected_fqns.insert(fqn);
                        }
                    }
                    _ => {}
                }
            }
        }
        let mut targets = rust_forward_import_targets(rust, token, file, &binder, reference);
        let mut scoped_glob_resolution = None;
        let mut routed_glob_candidates = Vec::new();
        if !explicitly_bound {
            scoped_glob_resolution = rust_scoped_glob_forward_import_candidates(
                rust,
                token,
                support,
                file,
                source,
                scope_start,
                &binder,
                reference,
                role,
            );
            routed_glob_candidates = rust_glob_forward_export_candidates(
                rust, token, support, file, &binder, reference, role,
            );
            if scoped_glob_resolution.is_some() {
                targets.clear();
            }
        }
        // `self`/`super` imports that resolve within the current file: the
        // standard target resolution looks in the file's parent package and
        // misses them, so steer them to the current file directly.
        for (local_name, binding) in &binder.bindings {
            if local_name != reference {
                continue;
            }
            match binding.kind {
                ImportKind::Named => {
                    let imported = binding.imported_name.as_deref().unwrap_or(reference);
                    targets.extend(
                        resolve_module_files(rust, token, file, &binding.module_specifier)
                            .into_iter()
                            .map(|target_file| (target_file, imported.to_string())),
                    );
                    if import_package_resolves_to_file(
                        file,
                        source,
                        scope_start,
                        &binding.module_specifier,
                    ) {
                        targets.push((file.clone(), imported.to_string()));
                    }
                }
                ImportKind::Namespace => {
                    targets.extend(rust_namespace_import_parent_targets(
                        rust,
                        token,
                        file,
                        &binding.module_specifier,
                    ));
                    if let Some(name) = import_path_resolves_within_file(
                        file,
                        source,
                        scope_start,
                        &binding.module_specifier,
                    ) {
                        targets.push((file.clone(), name));
                    }
                }
                _ => {}
            }
        }
        let (mut candidates, mut crossed_unindexed_explicit_binding) = scoped_glob_resolution
            .map_or_else(
                || (Vec::new(), false),
                |resolution| {
                    (
                        resolution.candidates,
                        resolution.crossed_unindexed_explicit_binding,
                    )
                },
            );
        candidates.extend(routed_glob_candidates);
        let mut resolved_through_import_chain = false;
        for (target_file, target_name) in targets {
            let resolved =
                rust_import_target_candidates(rust, token, support, target_file, target_name, role);
            resolved_through_import_chain |= resolved.resolved_through_import_chain;
            candidates.extend(resolved.candidates);
            crossed_unindexed_explicit_binding |= resolved.crossed_unindexed_explicit_binding;
        }
        if !explicitly_bound {
            candidates.retain(|candidate| {
                rust_glob_import_exposes_candidate(
                    rust,
                    token,
                    support,
                    file,
                    source,
                    scope_start,
                    &binder,
                    reference,
                    candidate,
                )
            });
        }
        if explicitly_bound && !expected_fqns.is_empty() {
            let exact: Vec<_> = candidates
                .iter()
                .filter(|candidate| expected_fqns.contains(&candidate.fq_name()))
                .cloned()
                .collect();
            if !exact.is_empty() {
                candidates = exact;
            } else {
                let expected: Vec<_> = expected_fqns
                    .iter()
                    .flat_map(|fqn| support.fqn(fqn))
                    .filter(|candidate| rust_role_accepts_imported(rust, role, candidate))
                    .collect();
                if !expected.is_empty() {
                    candidates = expected;
                } else if !preserve_unqualified_namespace_candidates
                    && (!resolved_through_import_chain || role == RustBareReferenceRole::Value)
                {
                    // A structured import chain can prove a renamed type,
                    // owner, callable, or macro. It cannot make a mismatched
                    // value candidate exact: Rust's value namespace also
                    // contains enum variants and constructors with the same
                    // terminal name.
                    candidates.clear();
                }
            }
        }
        candidates.retain(|candidate| language_for_file(candidate.source()) == Language::Rust);
        candidates.retain(|candidate| {
            let candidate_fqn = candidate.fq_name();
            let Some(module_files) = expected_routes.get(&candidate_fqn) else {
                return true;
            };
            let mut saw_disjoint = false;
            for module_file in module_files {
                match rust.files_share_cargo_target(module_file, candidate.source()) {
                    Some(true) => return true,
                    Some(false) => saw_disjoint = true,
                    None => {}
                }
            }
            !saw_disjoint
        });
        sort_units(&mut candidates);
        candidates.dedup();
        if !candidates.is_empty() {
            return if explicitly_bound {
                RustVisibleImportResolution::Resolved(candidates)
            } else {
                RustVisibleImportResolution::GlobResolved(candidates)
            };
        }
        if explicitly_bound {
            return RustVisibleImportResolution::BoundButUnindexed;
        }
        if crossed_unindexed_explicit_binding {
            return RustVisibleImportResolution::GlobBoundButUnindexed;
        }
    }
    RustVisibleImportResolution::Unbound
}

fn rust_glob_forward_export_candidates(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
    role: RustBareReferenceRole,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    let refs = support.forward_reference_context(rust, token, file);
    for binding in binder
        .bindings
        .values()
        .filter(|binding| binding.kind == ImportKind::Glob)
    {
        let segments = crate::analyzer::symbol_lookup::parse_symbol_path(
            Language::Rust,
            &binding.module_specifier,
        );
        if matches!(segments.first().map(String::as_str), Some("self" | "super")) {
            continue;
        }
        let module_files = resolve_module_files(rust, token, file, &binding.module_specifier);
        if let Some(fqn) = forward_export_fqn_from_files(rust, token, &module_files, reference) {
            candidates.extend(
                rust.get_definitions(&fqn)
                    .into_iter()
                    .filter(|candidate| rust_role_accepts_imported(rust, role, candidate)),
            );
        }
        if let Some(owner) = refs
            .as_ref()
            .and_then(|refs| resolve_rust_path_fqn(rust, refs, file, &binding.module_specifier))
        {
            candidates.extend(
                support
                    .fqn(&format!("{owner}.{reference}"))
                    .into_iter()
                    .filter(|candidate| rust_role_accepts_imported(rust, role, candidate))
                    .filter(|candidate| rust_declaration_is_enum_variant(rust, candidate)),
            );
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

#[allow(clippy::too_many_arguments)]
fn rust_glob_import_exposes_candidate(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    scope_start: usize,
    binder: &ImportBinder,
    reference: &str,
    candidate: &CodeUnit,
) -> bool {
    let Some(owner) = rust.parent_of(candidate) else {
        return true;
    };
    if owner.is_module() || owner.is_file_scope() {
        return true;
    }
    let Some(refs) = support.forward_reference_context(rust, token, file) else {
        return false;
    };
    binder
        .bindings
        .values()
        .filter(|binding| binding.kind == ImportKind::Glob)
        .any(|binding| {
            let scoped_package = resolve_rust_import_package_scoped(
                rust,
                token,
                file,
                source,
                scope_start,
                &binding.module_specifier,
            );
            let resolved_owner = scoped_package
                .clone()
                .or_else(|| resolve_rust_path_fqn(rust, &refs, file, &binding.module_specifier));
            if resolved_owner.as_deref() == Some(owner.fq_name().as_str()) {
                return true;
            }

            let mut module_files = scoped_package
                .map(|package| {
                    rust.get_analyzed_files()
                        .into_iter()
                        .filter(|candidate| rust_package_name(candidate) == package)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if module_files.is_empty() {
                module_files = resolve_module_files(rust, token, file, &binding.module_specifier);
            }
            forward_export_fqn_from_files(rust, token, &module_files, reference)
                .is_some_and(|export_fqn| export_fqn == candidate.fq_name())
        })
}

#[allow(clippy::too_many_arguments)]
fn rust_scoped_glob_forward_import_candidates(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    scope_start: usize,
    binder: &ImportBinder,
    reference: &str,
    role: RustBareReferenceRole,
) -> Option<RustImportTargetCandidates> {
    let mut candidates = Vec::new();
    let mut saw_scoped_glob = false;
    let mut crossed_unindexed_explicit_binding = false;
    let refs = support.forward_reference_context(rust, token, file);
    for binding in binder.bindings.values() {
        let segments = crate::analyzer::symbol_lookup::parse_symbol_path(
            Language::Rust,
            &binding.module_specifier,
        );
        if binding.kind != ImportKind::Glob
            || !matches!(segments.first().map(String::as_str), Some("self" | "super"))
        {
            continue;
        }
        saw_scoped_glob = true;
        if let Some(owner) = refs
            .as_ref()
            .and_then(|refs| resolve_rust_path_fqn(rust, refs, file, &binding.module_specifier))
        {
            candidates.extend(
                support
                    .fqn(&format!("{owner}.{reference}"))
                    .into_iter()
                    .filter(|candidate| rust_role_accepts_imported(rust, role, candidate))
                    .filter(|candidate| rust_declaration_is_enum_variant(rust, candidate)),
            );
        }
        let Some(package) = resolve_rust_import_package_scoped(
            rust,
            token,
            file,
            source,
            scope_start,
            &binding.module_specifier,
        ) else {
            continue;
        };
        let files = rust
            .get_analyzed_files()
            .into_iter()
            .filter(|candidate| rust_package_name(candidate) == package)
            .collect::<Vec<_>>();
        for target_file in files {
            let Ok(target_source) = target_file.read_to_string() else {
                continue;
            };
            let target_binder = lexical_scope::visible_import_binder_at(&target_source, 0);
            if rust_binder_has_external_binding(&target_binder, reference) {
                let imported = rust
                    .reference_context_of(token, &target_file)
                    .resolve_bare(reference)
                    .into_iter()
                    .flat_map(|fqn| support.fqn(&fqn))
                    .filter(|candidate| rust_role_accepts_imported(rust, role, candidate))
                    .collect::<Vec<_>>();
                if imported.is_empty() {
                    crossed_unindexed_explicit_binding = true;
                } else {
                    candidates.extend(imported);
                }
            }
            candidates.extend(
                rust.declarations(&target_file)
                    .into_iter()
                    .filter(|candidate| candidate.identifier() == reference)
                    .filter(|candidate| {
                        rust.parent_of(candidate)
                            .is_none_or(|owner| owner.is_module() || owner.is_file_scope())
                    })
                    .filter(|candidate| rust_role_accepts_imported(rust, role, candidate)),
            );
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    saw_scoped_glob.then_some(RustImportTargetCandidates {
        candidates,
        crossed_unindexed_explicit_binding,
        resolved_through_import_chain: false,
    })
}

/// True when a `self`/`super` import's module specifier resolves to the
/// current file's own package — i.e. the import targets a declaration in
/// this file, which the file-level target resolution (looking in the file's
/// parent package) cannot see. Used for Named bindings (`use super::{X}`).
fn import_package_resolves_to_file(
    file: &ProjectFile,
    source: &str,
    scope_start: usize,
    module_specifier: &str,
) -> bool {
    let segments =
        crate::analyzer::symbol_lookup::parse_symbol_path(Language::Rust, module_specifier);
    let Some(first) = segments.first().map(String::as_str) else {
        return false;
    };
    if !matches!(first, "self" | "super") {
        return false;
    }
    let file_package = crate::analyzer::rust::rust_package_name(file);
    let lexical_package = lexical_scope::lexical_package_at(&file_package, source, scope_start);
    let crate_package = crate::analyzer::rust::rust_crate_root_package(file);
    crate::analyzer::rust::resolve_rust_module_segments_with_crate(
        &lexical_package,
        &crate_package,
        &segments,
    )
    .is_some_and(|resolved| resolved == file_package)
}

/// For Namespace bindings (`use super::X` — the full path is the specifier):
/// when the scope-aware resolution lands inside the current file, return the
/// imported declaration's terminal name so the file can be targeted directly.
fn import_path_resolves_within_file(
    file: &ProjectFile,
    source: &str,
    scope_start: usize,
    module_specifier: &str,
) -> Option<String> {
    let segments =
        crate::analyzer::symbol_lookup::parse_symbol_path(Language::Rust, module_specifier);
    let first = segments.first().map(String::as_str)?;
    if !matches!(first, "self" | "super") {
        return None;
    }
    let file_package = crate::analyzer::rust::rust_package_name(file);
    let lexical_package = lexical_scope::lexical_package_at(&file_package, source, scope_start);
    let crate_package = crate::analyzer::rust::rust_crate_root_package(file);
    let resolved = crate::analyzer::rust::resolve_rust_module_segments_with_crate(
        &lexical_package,
        &crate_package,
        &segments,
    )?;
    // `resolved` is this same code's own `.`-joined package/name string (built two
    // lines above by `resolve_rust_module_segments_with_crate`), and Rust
    // identifiers cannot contain a literal `.`, so re-tokenizing it with the same
    // structured splitter reproduces `rsplit_once('.')`'s (parent, name) split
    // exactly — it is not source-text inference, it is re-reading this function's
    // own already-structured output.
    let resolved_parts =
        crate::analyzer::symbol_lookup::parse_symbol_path(Language::Rust, &resolved);
    if resolved_parts.len() < 2 {
        return None;
    }
    let (name, parent_parts) = resolved_parts.split_last()?;
    let parent = parent_parts.join(".");
    (parent == file_package).then(|| name.clone())
}

/// Preserve the physical parent-module route for a namespace-shaped import.
///
/// `use super::Error` can name a private import in the parent module. Public
/// export traversal correctly omits that binding, but Rust makes it visible to
/// child modules. Return the parent module files and terminal name so
/// `rust_import_target_candidates` can follow the parent's lexical binder.
fn rust_namespace_import_parent_targets(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    module_specifier: &str,
) -> Vec<(ProjectFile, String)> {
    let segments =
        crate::analyzer::symbol_lookup::parse_symbol_path(Language::Rust, module_specifier);
    let Some((terminal, parent_segments)) = segments.split_last() else {
        return Vec::new();
    };
    if parent_segments.is_empty() {
        return Vec::new();
    }
    let parent_specifier = parent_segments.join("::");
    resolve_module_files(rust, token, file, &parent_specifier)
        .into_iter()
        .map(|parent_file| (parent_file, terminal.clone()))
        .collect()
}

struct RustImportTargetCandidates {
    candidates: Vec<CodeUnit>,
    crossed_unindexed_explicit_binding: bool,
    resolved_through_import_chain: bool,
}

fn rust_import_target_candidates(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    target_file: ProjectFile,
    target_name: String,
    role: RustBareReferenceRole,
) -> RustImportTargetCandidates {
    let mut candidates = Vec::new();
    let mut crossed_explicit_binding = false;
    let mut followed_import_chain = false;
    let mut pending = vec![(target_file, target_name)];
    let mut visited = HashSet::default();
    while let Some((file, name)) = pending.pop() {
        if !visited.insert((file.clone(), name.clone())) {
            continue;
        }
        let direct: Vec<_> = support
            .file_identifier(&file, &name)
            .into_iter()
            .filter(|candidate| rust_role_accepts_imported(rust, role, candidate))
            .collect();
        if !direct.is_empty() {
            candidates.extend(direct);
            continue;
        }

        // A child module can import a private name from its parent. Follow the
        // parent's module-level binder until we reach the physical declaration,
        // while excluding imports nested in functions or other lexical scopes.
        let Ok(source) = file.read_to_string() else {
            continue;
        };
        let binder = lexical_scope::visible_import_binder_at(&source, source.len());
        if rust_binder_has_external_binding(&binder, &name) {
            crossed_explicit_binding = true;
            followed_import_chain = true;
            pending.extend(rust_forward_import_targets(
                rust, token, &file, &binder, &name,
            ));
            continue;
        }
        pending.extend(rust_forward_import_targets(
            rust, token, &file, &binder, &name,
        ));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    RustImportTargetCandidates {
        crossed_unindexed_explicit_binding: crossed_explicit_binding && candidates.is_empty(),
        resolved_through_import_chain: followed_import_chain && !candidates.is_empty(),
        candidates,
    }
}

fn rust_forward_import_targets(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> Vec<(ProjectFile, String)> {
    resolve_visible_import_targets_forward(rust, token, file, binder, reference)
}

#[allow(clippy::too_many_arguments)]
fn rust_current_module_candidates(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    root: Node<'_>,
    reference_start: usize,
    reference_end: usize,
    reference: &str,
    role: RustBareReferenceRole,
) -> Vec<CodeUnit> {
    let range = Range {
        start_byte: reference_start,
        end_byte: reference_end,
        start_line: 0,
        end_line: 0,
    };
    let mut enclosing = Vec::new();
    let mut current = analyzer.enclosing_code_unit(file, &range);
    while let Some(unit) = current {
        enclosing.push(unit.clone());
        current = analyzer.parent_of(&unit);
    }
    let reference_syntax_module = lexical_scope::enclosing_mod_item_range_at(root, reference_start);
    let mut physical = analyzer
        .declarations(file)
        .into_iter()
        .filter(|candidate| candidate.identifier() == reference)
        .collect::<Vec<_>>();
    physical.extend(
        support
            .file_identifier(file, reference)
            .into_iter()
            .filter(|candidate| candidate.source() == file),
    );
    let mut candidates: Vec<_> = physical
        .into_iter()
        .filter(|candidate| rust_role_accepts_current_module(rust, role, candidate))
        .filter(|candidate| {
            analyzer.ranges(candidate).iter().any(|range| {
                rust_declaration_syntax_module_range(root, range, candidate.is_module())
                    == reference_syntax_module
            })
        })
        .filter(|candidate| {
            analyzer.parent_of(candidate).is_none_or(|parent| {
                parent.is_module() || enclosing.iter().any(|scope| scope == &parent)
            })
        })
        .collect();
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn rust_declaration_syntax_module_range(
    root: Node<'_>,
    range: &Range,
    declaration_is_module: bool,
) -> Option<(usize, usize)> {
    if !declaration_is_module {
        return lexical_scope::enclosing_mod_item_range_at(root, range.start_byte);
    }
    let mut declaration = smallest_named_node_covering(root, range.start_byte, range.end_byte)?;
    while declaration.kind() != "mod_item" {
        declaration = declaration.parent()?;
    }
    let mut parent = declaration.parent();
    while let Some(node) = parent {
        if node.kind() == "mod_item" {
            return Some((node.start_byte(), node.end_byte()));
        }
        parent = node.parent();
    }
    None
}

fn rust_role_accepts_imported(
    rust: &RustAnalyzer,
    role: RustBareReferenceRole,
    candidate: &CodeUnit,
) -> bool {
    match role {
        RustBareReferenceRole::Type => {
            candidate.is_class() || rust_declaration_is_module_type_alias(rust, candidate)
        }
        RustBareReferenceRole::Value => {
            rust_value_namespace_candidate(rust, candidate) || candidate.is_field()
        }
        RustBareReferenceRole::Callable => rust_callable_namespace_candidate(rust, candidate),
        RustBareReferenceRole::Owner => {
            candidate.is_module()
                || candidate.is_class()
                || rust_declaration_is_module_type_alias(rust, candidate)
        }
        RustBareReferenceRole::Macro => candidate.is_macro(),
    }
}

fn rust_role_accepts_current_module(
    rust: &RustAnalyzer,
    role: RustBareReferenceRole,
    candidate: &CodeUnit,
) -> bool {
    match role {
        RustBareReferenceRole::Type => {
            candidate.is_class() || rust_declaration_is_module_type_alias(rust, candidate)
        }
        RustBareReferenceRole::Value => {
            (candidate.is_class() && has_rust_value_constructor(rust, candidate))
                || (candidate.is_function() && rust_declaration_is_free_function(rust, candidate))
                || (candidate.is_field() && rust_declaration_is_module_value_item(rust, candidate))
        }
        RustBareReferenceRole::Callable => {
            candidate.is_class()
                || (candidate.is_function() && rust_declaration_is_free_function(rust, candidate))
        }
        RustBareReferenceRole::Owner => {
            candidate.is_module()
                || candidate.is_class()
                || rust_declaration_is_module_type_alias(rust, candidate)
        }
        RustBareReferenceRole::Macro => candidate.is_macro(),
    }
}

/// Stage `tier` for the outcome constructor these units flow into.
///
/// Nothing is recorded here: the row is minted by the shared seam that builds
/// the outcome, so a selection the resolver later discards on another path
/// cannot leave a selected row behind.
fn trace_selected_units(units: &[CodeUnit], tier: PrecedenceTier) {
    if trace::recording() && !units.is_empty() {
        trace::stage_tier(tier, units.iter().map(CodeUnit::fq_name).collect());
    }
}

/// Record candidates a tier computed and then discarded.
fn trace_rejected_units(units: &[CodeUnit], tier: PrecedenceTier, reason: RejectionReason) {
    if !trace::recording() || units.is_empty() {
        return;
    }
    trace::record_all(units.iter().map(|unit| {
        trace::TraceCandidate::rejected(
            trace::TraceCandidateRef::Unit(unit.clone()),
            Some(tier),
            reason,
        )
    }));
}

/// Record an import route that bound the name but could not answer for it.
/// The resolution outcome this arm reads back does not carry the route's
/// `ImportInfo`, so the route's target stays unstated (an empty list), not
/// re-derived.
fn trace_rejected_import_route(file: &ProjectFile, name: &str, boundary: BoundaryStatus) {
    if !trace::recording() {
        return;
    }
    trace::record(
        trace::TraceCandidate::rejected(
            trace::TraceCandidateRef::ImportBinder {
                file: file.clone(),
                node: None,
                name: name.to_owned(),
                target_segments: Vec::new(),
            },
            Some(PrecedenceTier::ExplicitImport),
            RejectionReason::BoundaryBlocked,
        )
        .with_boundary(boundary),
    );
}

fn rust_role_accepts_scoped(
    rust: &RustAnalyzer,
    role: RustBareReferenceRole,
    candidate: &CodeUnit,
) -> bool {
    match role {
        RustBareReferenceRole::Type => {
            candidate.is_class() || rust_declaration_is_module_type_alias(rust, candidate)
        }
        RustBareReferenceRole::Value => {
            candidate.is_class()
                || candidate.is_function()
                || (candidate.is_field()
                    && (rust_declaration_is_value_item(rust, candidate)
                        || rust_declaration_is_enum_variant(rust, candidate)))
        }
        RustBareReferenceRole::Callable => {
            candidate.is_class()
                || candidate.is_function()
                || (candidate.is_field() && rust_declaration_is_enum_variant(rust, candidate))
        }
        RustBareReferenceRole::Owner => {
            candidate.is_module()
                || candidate.is_class()
                || rust_declaration_is_module_type_alias(rust, candidate)
        }
        RustBareReferenceRole::Macro => candidate.is_macro(),
    }
}

fn rust_value_namespace_candidate(rust: &RustAnalyzer, candidate: &CodeUnit) -> bool {
    (candidate.is_class() && has_rust_value_constructor(rust, candidate))
        || (candidate.is_function() && rust_declaration_is_free_function(rust, candidate))
        || (candidate.is_field()
            && (rust_declaration_is_value_item(rust, candidate)
                || rust_declaration_is_enum_variant(rust, candidate)))
}

fn rust_callable_namespace_candidate(rust: &RustAnalyzer, candidate: &CodeUnit) -> bool {
    (candidate.is_class() && has_rust_value_constructor(rust, candidate))
        || (candidate.is_function() && rust_declaration_is_free_function(rust, candidate))
        || (candidate.is_field() && rust_declaration_is_enum_variant(rust, candidate))
}

fn rust_scoped_role_candidate(role: RustBareReferenceRole) -> fn(&CodeUnit) -> bool {
    match role {
        RustBareReferenceRole::Type => rust_scoped_type_candidate,
        RustBareReferenceRole::Value | RustBareReferenceRole::Callable => {
            rust_scoped_value_candidate
        }
        RustBareReferenceRole::Owner => rust_scoped_owner_candidate,
        RustBareReferenceRole::Macro => CodeUnit::is_macro,
    }
}

fn rust_scoped_type_candidate(candidate: &CodeUnit) -> bool {
    candidate.is_class() || candidate.is_field()
}

fn rust_scoped_value_candidate(candidate: &CodeUnit) -> bool {
    candidate.is_class() || candidate.is_function() || candidate.is_field()
}

fn rust_scoped_owner_candidate(candidate: &CodeUnit) -> bool {
    candidate.is_module() || candidate.is_class() || candidate.is_field()
}

fn rust_declaration_is_free_function(rust: &RustAnalyzer, candidate: &CodeUnit) -> bool {
    rust_declaration_matches(rust, candidate, |node| {
        if node.kind() != "function_item" {
            return false;
        }
        let mut current = node.parent();
        while let Some(parent) = current {
            if matches!(parent.kind(), "impl_item" | "trait_item") {
                return false;
            }
            current = parent.parent();
        }
        true
    })
}

fn rust_declaration_is_module_type_alias(rust: &RustAnalyzer, candidate: &CodeUnit) -> bool {
    if !rust.is_type_alias(candidate) {
        return false;
    }
    rust_declaration_matches(rust, candidate, |node| {
        if node.kind() != "type_item" {
            return false;
        }
        let mut current = node.parent();
        while let Some(parent) = current {
            if matches!(parent.kind(), "impl_item" | "trait_item") {
                return false;
            }
            current = parent.parent();
        }
        true
    })
}

fn rust_declaration_is_trait(rust: &RustAnalyzer, candidate: &CodeUnit) -> bool {
    rust_declaration_matches(rust, candidate, |node| node.kind() == "trait_item")
}

fn rust_declaration_is_value_item(rust: &RustAnalyzer, candidate: &CodeUnit) -> bool {
    rust_declaration_matches(rust, candidate, |node| {
        matches!(node.kind(), "enum_variant" | "const_item" | "static_item")
    })
}

fn rust_declaration_is_module_value_item(rust: &RustAnalyzer, candidate: &CodeUnit) -> bool {
    rust_declaration_matches(rust, candidate, |node| {
        if !matches!(node.kind(), "const_item" | "static_item") {
            return false;
        }
        let mut current = node.parent();
        while let Some(parent) = current {
            match parent.kind() {
                // The nearest item boundary determines whether this is an
                // associated item. A const inside a method's block is a local
                // value even though an impl or trait appears farther up the
                // ancestor chain.
                "block" | "function_item" | "mod_item" | "source_file" => return true,
                "impl_item" | "trait_item" => return false,
                _ => {}
            }
            current = parent.parent();
        }
        true
    })
}

fn rust_declaration_is_enum_variant(rust: &RustAnalyzer, candidate: &CodeUnit) -> bool {
    let support = AnalyzerRustDefinitionProvider::new(rust, false);
    let Some(source) = rust.indexed_source(candidate.source()) else {
        return false;
    };
    let Some(tree) = lexical_scope::parse_rust_tree(&source) else {
        return false;
    };
    rust_code_unit_range_is_enum_variant(rust, &support, candidate, tree.root_node())
}

fn rust_declaration_matches(
    rust: &RustAnalyzer,
    candidate: &CodeUnit,
    predicate: impl FnOnce(Node<'_>) -> bool,
) -> bool {
    let Ok(source) = candidate.source().read_to_string() else {
        return false;
    };
    let Some(tree) = lexical_scope::parse_rust_tree(&source) else {
        return false;
    };
    let support = AnalyzerRustDefinitionProvider::new(rust, false);
    rust_code_unit_declaration_node(rust, &support, candidate, tree.root_node())
        .is_some_and(predicate)
}

#[allow(clippy::too_many_arguments)]
fn rust_impl_associated_type_declaration_outcome(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    operation: Option<NavigationOperation>,
) -> Option<DefinitionLookupOutcome> {
    let node =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let type_item =
        rust_enclosing_named_associated_type(node, site.focus_start_byte, site.focus_end_byte)?;
    let name = type_item.child_by_field_name("name")?;
    let associated_type = rust_node_text(name, source).trim();
    if associated_type.is_empty() {
        return None;
    }
    let impl_item = rust_enclosing_ancestor(type_item, "impl_item")?;
    if operation == Some(NavigationOperation::Definition) {
        let candidate = rust_associated_type_declaration_for_exact_node(
            rust,
            file,
            type_item,
            associated_type,
        )?;
        return Some(candidates_outcome(vec![candidate]));
    }
    let trait_type = impl_item.child_by_field_name("trait")?;
    let trait_fqn = rust_resolve_type_node_fqn(
        rust,
        token,
        support,
        file,
        source,
        trait_type,
        Some(trait_type.start_byte()),
    )?;
    let mut candidates: Vec<_> = support
        .fqn(&format!("{trait_fqn}.{associated_type}"))
        .into_iter()
        .filter(CodeUnit::is_field)
        .collect();
    if candidates.is_empty() {
        return None;
    }
    sort_units(&mut candidates);
    candidates.dedup();
    Some(candidates_outcome(candidates))
}

#[allow(clippy::too_many_arguments)]
fn rust_qualified_associated_type_navigation_outcome(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    operation: NavigationOperation,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let scoped = rust_enclosing_ancestor(focused, "scoped_type_identifier")?;
    let name = scoped.child_by_field_name("name")?;
    if name.start_byte() > site.focus_start_byte || name.end_byte() < site.focus_end_byte {
        return None;
    }
    let mut qualified = scoped.child_by_field_name("path")?;
    while qualified.kind() == "bracketed_type" {
        qualified = qualified.named_child(0)?;
    }
    if qualified.kind() != "qualified_type" {
        return None;
    }
    let owner_type = qualified.child_by_field_name("type")?;
    let trait_type = qualified.child_by_field_name("alias")?;
    let owner_fqn = rust_resolve_type_node_fqn(
        analyzer,
        token,
        support,
        file,
        source,
        owner_type,
        Some(owner_type.start_byte()),
    )?;
    let trait_fqn = rust_resolve_type_node_fqn(
        analyzer,
        token,
        support,
        file,
        source,
        trait_type,
        Some(trait_type.start_byte()),
    )?;
    let member_name = rust_node_text(name, source).trim();
    let trait_members: Vec<_> = support
        .fqn(&format!("{trait_fqn}.{member_name}"))
        .into_iter()
        .filter(CodeUnit::is_field)
        .collect();
    if trait_members.is_empty() {
        return None;
    }
    if operation == NavigationOperation::Declaration {
        return Some(candidates_outcome(trait_members));
    }
    let mut implementations = Vec::new();
    for trait_member in trait_members {
        implementations.extend(
            rust.rust_trait_member_implementations(&trait_member)
                .unwrap_or_default()
                .into_iter()
                .filter(|candidate| {
                    analyzer
                        .parent_of(candidate)
                        .is_some_and(|parent| parent.fq_name() == owner_fqn)
                }),
        );
    }
    sort_units(&mut implementations);
    implementations.dedup();
    Some(if implementations.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!(
                "qualified Rust associated type `{member_name}` has no indexed implementation for `{owner_fqn}`"
            ),
        )
    } else {
        candidates_outcome(implementations)
    })
}

fn rust_enclosing_named_associated_type(
    node: Node<'_>,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if matches!(candidate.kind(), "associated_type" | "type_item")
            && let Some(name) = candidate.child_by_field_name("name")
            && name.start_byte() <= focus_start_byte
            && focus_end_byte <= name.end_byte()
        {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn rust_self_scoped_associated_type_candidates(
    rust: &RustAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<Vec<CodeUnit>> {
    let node =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    // `Self::Assoc` is a `scoped_type_identifier` in a type position but a
    // `scoped_identifier` when it is immediately used as a value/callee. Both
    // forms name the enclosing trait or impl's associated item; resolving only
    // the type-shaped node lets an unrelated import of `Assoc` win for the
    // value-shaped form.
    let scoped =
        rust_enclosing_scoped_terminal_name(node, site.focus_start_byte, site.focus_end_byte)?;
    let path = scoped.child_by_field_name("path")?;
    if rust_node_text(path, source).trim() != "Self" {
        return None;
    }
    let name = scoped.child_by_field_name("name")?;
    let name = rust_node_text(name, source).trim();
    let Some(impl_item) = rust_enclosing_ancestor(scoped, "impl_item") else {
        return resolve_in_enclosing_scopes(
            analyzer,
            file,
            name,
            site.focus_start_byte,
            CodeUnit::is_field,
        )
        .map(|candidate| vec![candidate]);
    };
    if let Some(body) = impl_item.child_by_field_name("body") {
        let mut cursor = body.walk();
        for item in body.named_children(&mut cursor) {
            if !matches!(item.kind(), "associated_type" | "type_item") {
                continue;
            }
            let Some(item_name) = item.child_by_field_name("name") else {
                continue;
            };
            if rust_node_text(item_name, source).trim() != name {
                continue;
            }
            if let Some(candidate) =
                rust_associated_type_declaration_for_exact_node(rust, file, item, name)
            {
                return Some(vec![candidate]);
            }
        }
    }
    let candidate = resolve_in_enclosing_scopes(
        analyzer,
        file,
        name,
        site.focus_start_byte,
        CodeUnit::is_field,
    );
    let candidate_is_in_impl = candidate.as_ref().is_some_and(|candidate| {
        candidate.source() == file
            && analyzer.ranges(candidate).iter().any(|range| {
                impl_item.start_byte() <= range.start_byte && range.end_byte <= impl_item.end_byte()
            })
    });
    Some(
        candidate
            .filter(|_| candidate_is_in_impl)
            .into_iter()
            .collect(),
    )
}

fn rust_enum_variant_declaration_outcome(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let variant = std::iter::successors(Some(focused), |node| node.parent())
        .find(|node| node.kind() == "enum_variant")?;
    let name = variant.child_by_field_name("name")?;
    if !(name.start_byte() <= site.focus_start_byte && site.focus_end_byte <= name.end_byte()) {
        return None;
    }
    let variant_name = rust_node_text(name, source).trim();
    let candidates: Vec<_> = support
        .file_identifier(file, variant_name)
        .into_iter()
        .filter(CodeUnit::is_field)
        .filter(|candidate| {
            analyzer.ranges(candidate).iter().any(|range| {
                range.start_byte == variant.start_byte() && range.end_byte == variant.end_byte()
            })
        })
        .collect();
    (!candidates.is_empty()).then(|| candidates_outcome(candidates))
}

fn rust_enclosing_scoped_type_identifier_name(
    node: Node<'_>,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "scoped_type_identifier"
            && let Some(name) = candidate.child_by_field_name("name")
            && name.start_byte() <= focus_start_byte
            && focus_end_byte <= name.end_byte()
        {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn rust_enclosing_scoped_terminal_name(
    node: Node<'_>,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> Option<Node<'_>> {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if matches!(
            candidate.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        ) && let Some(name) = candidate.child_by_field_name("name")
            && name.start_byte() <= focus_start_byte
            && focus_end_byte <= name.end_byte()
        {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn rust_local_scoped_owner_member_candidates(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    member: &str,
    role: RustBareReferenceRole,
    cache: &mut RustTypeLookupCache,
) -> Option<Vec<CodeUnit>> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let scoped =
        rust_enclosing_scoped_terminal_name(focused, site.focus_start_byte, site.focus_end_byte)?;
    let path = scoped.child_by_field_name("path")?;
    if !matches!(path.kind(), "identifier" | "type_identifier") {
        return None;
    }
    let owner_text = rust_node_text(path, source).trim();
    if owner_text.is_empty() {
        return None;
    }
    let mut owners = rust_current_module_candidates(
        analyzer,
        rust,
        support,
        file,
        tree.root_node(),
        path.start_byte(),
        path.end_byte(),
        owner_text,
        RustBareReferenceRole::Owner,
    );
    if !owners.iter().any(|owner| rust.is_type_alias(owner)) {
        match rust_visible_import_resolution(
            rust,
            token,
            support,
            file,
            source,
            site.focus_start_byte,
            owner_text,
            RustBareReferenceRole::Owner,
        ) {
            RustVisibleImportResolution::Resolved(imported)
            | RustVisibleImportResolution::GlobResolved(imported) => owners.extend(imported),
            RustVisibleImportResolution::BoundButUnindexed
            | RustVisibleImportResolution::GlobBoundButUnindexed
            | RustVisibleImportResolution::Unbound => {}
        }
    }
    sort_units(&mut owners);
    owners.dedup();
    let alias_owner_present = owners.iter().any(|owner| rust.is_type_alias(owner));
    let mut candidates = owners
        .into_iter()
        .filter(|owner| !alias_owner_present || rust.is_type_alias(owner))
        .flat_map(|owner| {
            let is_type_alias = rust.is_type_alias(&owner);
            let canonical_owner = if is_type_alias {
                rust_code_unit_type_fqn(
                    analyzer,
                    token,
                    support,
                    owner.source(),
                    None,
                    &owner,
                    "type",
                    RustTypeMode::Direct,
                    cache,
                )
            } else {
                None
            };
            canonical_owner
                .into_iter()
                .flat_map(|owner_fqn| {
                    let owner_sources = support
                        .fqn(&owner_fqn)
                        .into_iter()
                        .filter(|candidate| rust_is_type_definition(analyzer, candidate))
                        .map(|candidate| candidate.source().clone())
                        .collect::<Vec<_>>();
                    let mut members = support.members_for_owner_name(&owner_fqn, member);
                    if !owner_sources.is_empty() {
                        members.retain(|member| {
                            owner_sources.iter().any(|owner_source| {
                                rust.files_share_cargo_target(owner_source, member.source())
                                    != Some(false)
                            })
                        });
                    }
                    members
                })
                .chain(
                    (!is_type_alias)
                        .then(|| owner.fq_name())
                        .into_iter()
                        .flat_map(|owner_fqn| support.members_for_owner_name(&owner_fqn, member)),
                )
        })
        .filter(|candidate| rust_role_accepts_scoped(rust, role, candidate))
        .collect::<Vec<_>>();
    if !alias_owner_present {
        candidates.extend(rust_cargo_root_member_candidates(
            rust, support, file, source, path, member,
        ));
    }
    candidates.retain(|candidate| rust_role_accepts_scoped(rust, role, candidate));
    sort_units(&mut candidates);
    candidates.dedup();
    (!candidates.is_empty()).then_some(candidates)
}

#[allow(clippy::too_many_arguments)]
fn rust_focused_terminal_scoped_type_candidates(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<Vec<CodeUnit>> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let scoped = rust_enclosing_scoped_type_identifier_name(
        focused,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    let path = scoped.child_by_field_name("path")?;
    let name = scoped.child_by_field_name("name")?;
    let member = rust_node_text(name, source).trim();
    if member.is_empty() {
        return None;
    }
    let refs = support.forward_reference_context(rust, token, file)?;
    let owners = rust_scoped_owner_candidates_from_path(
        analyzer, token, rust, support, file, source, path, &refs,
    )?;
    let mut candidates = owners
        .into_iter()
        .flat_map(|owner| {
            support
                .members_for_owner_name(&owner.fq_name(), member)
                .into_iter()
                .filter(|candidate| rust_is_type_definition(analyzer, candidate))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    candidates.extend(
        rust_cargo_root_member_candidates(rust, support, file, source, path, member)
            .into_iter()
            .filter(|candidate| rust_is_type_definition(analyzer, candidate)),
    );
    sort_units(&mut candidates);
    candidates.dedup();
    (!candidates.is_empty()).then_some(candidates)
}

fn rust_cargo_root_member_candidates(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    path: Node<'_>,
    member: &str,
) -> Vec<CodeUnit> {
    if !matches!(path.kind(), "identifier" | "type_identifier") {
        return Vec::new();
    }
    let route = rust_node_text(path, source).trim();
    if route.is_empty() {
        return Vec::new();
    }
    let Some(root_file) = rust.resolve_cargo_crate_root_file(file, route) else {
        return Vec::new();
    };
    support
        .file_identifier(&root_file, member)
        .into_iter()
        .filter(|candidate| candidate.source() == &root_file)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn rust_scoped_owner_candidates_from_path(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    path: Node<'_>,
    refs: &RustReferenceContext<'_>,
) -> Option<Vec<CodeUnit>> {
    let owner_text = rust_node_text(path, source).trim();
    if owner_text.is_empty() {
        return None;
    }

    let mut candidates = Vec::new();
    if owner_text == "Self" {
        if let Some(owner) =
            rust_enclosing_impl_type_fqn(analyzer, token, support, file, source, path)
        {
            candidates.extend(support.fqn(&owner));
        }
    } else if let Some(fqn) = rust_scoped_prefix_fqn(rust, token, file, refs, path, source) {
        candidates.extend(support.fqn(&fqn).into_iter().filter(|candidate| {
            rust_role_accepts_imported(rust, RustBareReferenceRole::Owner, candidate)
        }));
    }

    if matches!(path.kind(), "identifier" | "type_identifier") {
        if candidates.is_empty()
            && let Some(root) = rust_root_node(support, path)
        {
            candidates.extend(rust_current_module_candidates(
                analyzer,
                rust,
                support,
                file,
                root,
                path.start_byte(),
                path.end_byte(),
                owner_text,
                RustBareReferenceRole::Owner,
            ));
        }
        let rust_2015 = rust.file_uses_rust_2015_edition(file);
        let explicit_extern_route = rust_2015
            .then(|| rust_visible_extern_crate_binding(path, source, owner_text))
            .flatten();
        let cargo_root_in_scope = !rust_2015 || explicit_extern_route.is_some();
        let cargo_route = explicit_extern_route.as_deref().unwrap_or(owner_text);
        let external = cargo_root_in_scope
            .then(|| resolve_module_package(rust, token, file, cargo_route))
            .flatten()
            .into_iter()
            .flat_map(|package| support.fqn(&package))
            .filter(|candidate| {
                rust_role_accepts_imported(rust, RustBareReferenceRole::Owner, candidate)
            })
            .collect::<Vec<_>>();
        if let Some(routed) = rust.candidates_in_cargo_library_route(file, cargo_route, external) {
            candidates.extend(routed);
        }
        if let Some(fqn) = resolve_module_package(rust, token, file, owner_text) {
            candidates.extend(support.fqn(&fqn));
        }
    }

    candidates.retain(|candidate| {
        rust_role_accepts_imported(rust, RustBareReferenceRole::Owner, candidate)
    });
    sort_units(&mut candidates);
    candidates.dedup();
    (!candidates.is_empty()).then_some(candidates)
}

fn rust_enclosing_ancestor<'tree>(mut node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == kind {
            return Some(parent);
        }
        node = parent;
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn rust_rooted_use_prefix_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let focused_text = rust_node_text(focused, source).trim();
    if !matches!(focused_text, "self" | "super")
        || rust_enclosing_ancestor(focused, "use_declaration").is_none()
    {
        return None;
    }
    let focused_path = rust_focused_use_path(focused, source)?;
    if focused_path.root.start_byte() != focused.start_byte()
        || focused_path.root.end_byte() != focused.end_byte()
    {
        return None;
    }
    let mut current = analyzer.enclosing_code_unit(file, &site.range);
    while current.as_ref().is_some_and(|unit| !unit.is_module()) {
        current = current.and_then(|unit| analyzer.parent_of(&unit));
    }
    let lexical_module = match focused_text {
        "self" => current,
        "super" => current.and_then(|unit| analyzer.parent_of(&unit)),
        _ => unreachable!(),
    };
    if let Some(module) = lexical_module.filter(CodeUnit::is_module) {
        return Some(candidates_outcome(vec![module]));
    }
    let fqn = resolve_rust_import_package_scoped(
        rust,
        token,
        file,
        source,
        focused.start_byte(),
        focused_text,
    )?;
    let mut candidates = support
        .fqn(&fqn)
        .into_iter()
        .filter(CodeUnit::is_module)
        .collect::<Vec<_>>();
    sort_units(&mut candidates);
    candidates.dedup();
    (!candidates.is_empty()).then(|| candidates_outcome(candidates))
}

/// Return the structured target path for a focused renamed import binder.
///
/// The alias token itself is not part of the use path tree. Without this
/// lookup, a site on `linear` in `use ...::linear_no_bias as linear` is
/// resolved as a bare local path and can select an unrelated `linear` item.
fn rust_focused_import_alias_path(focused: Node<'_>, source: &str) -> Option<String> {
    let use_declaration = rust_enclosing_ancestor(focused, "use_declaration")?;
    brokk_bifrost_rust::imports::rust_imports_from_use_declaration(use_declaration, source)
        .into_iter()
        .filter(|import| import.alias.is_some())
        .find_map(|import| {
            let span = import.binder_span?;
            if span.start_byte <= focused.start_byte() && focused.end_byte() <= span.end_byte {
                import.path.map(|path| path.segments.join("::"))
            } else {
                None
            }
        })
        .filter(|path| !path.is_empty())
}

#[allow(clippy::too_many_arguments)]
fn rust_focused_use_path_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let focused_path = rust_focused_use_path(focused, source)?;
    let focused_text = rust_node_text(focused, source).trim();
    let alias_path = rust_focused_import_alias_path(focused, source);
    let resolution_path = alias_path.as_deref().unwrap_or(&focused_path.full_path);
    let role = if rust_focused_nonterminal_prefix(focused).is_some() {
        RustFocusedPathRole::Owner
    } else {
        RustFocusedPathRole::Declaration
    };
    if role == RustFocusedPathRole::Declaration && focused_path.full_path == focused_text {
        let local = rust_current_module_candidates(
            analyzer,
            rust,
            support,
            file,
            tree.root_node(),
            site.focus_start_byte,
            site.focus_end_byte,
            focused_text,
            RustBareReferenceRole::Owner,
        )
        .into_iter()
        .filter(CodeUnit::is_module)
        .collect::<Vec<_>>();
        if !local.is_empty() {
            return Some(candidates_outcome(local));
        }
    }
    if role == RustFocusedPathRole::Declaration
        && let Some(candidates) =
            rust_focused_import_macro_candidates(rust, token, support, file, source, focused, site)
    {
        return Some(candidates_outcome(candidates));
    }
    let refs = support.forward_reference_context(rust, token, file)?;
    let rooted_segments =
        crate::analyzer::symbol_lookup::parse_symbol_path(Language::Rust, resolution_path);
    let resolved_fqn = if matches!(
        rooted_segments.first().map(String::as_str),
        Some("self" | "super")
    ) {
        resolve_rust_import_package_scoped(
            rust,
            token,
            file,
            source,
            focused.start_byte(),
            resolution_path,
        )
    } else {
        crate::analyzer::usages::rust_graph::resolve_rust_path_fqn(
            rust,
            &refs,
            file,
            resolution_path,
        )
    };
    Some(rust_focused_prefix_resolution_outcome(
        analyzer,
        token,
        rust,
        support,
        file,
        source,
        site,
        &refs,
        focused_path.root,
        focused_text,
        resolution_path,
        role,
        resolved_fqn.as_deref(),
        false,
    ))
}

/// Select an exported macro for an unqualified `use` terminal when a private
/// module has the same spelling. Rust keeps macro and module names in separate
/// namespaces. A private module does not make the import ambiguous because it
/// cannot cross the crate boundary (`spacetimedb_primitives::col_list`).
///
/// The generic path resolver intentionally accepts every declaration with the
/// resolved FQN. This narrow import-terminal pass supplies the missing
/// visibility fact before that fallback can select the private module.
#[allow(clippy::too_many_arguments)]
fn rust_focused_import_macro_candidates(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    focused: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<Vec<CodeUnit>> {
    let use_declaration = rust_enclosing_ancestor(focused, "use_declaration")?;
    let focused_text = rust_node_text(focused, source).trim();
    if focused_text.is_empty() {
        return None;
    }
    let import = brokk_bifrost_rust::imports::rust_imports_with_visibility_from_use_declaration(
        use_declaration,
        source,
    )
    .into_iter()
    .find(|import| {
        import.info.alias.is_none()
            && import.info.binder_span.is_some_and(|span| {
                span.start_byte <= site.focus_start_byte && site.focus_end_byte <= span.end_byte
            })
            && import.path.last().is_some_and(|name| name == focused_text)
    })?;
    if import.path.len() < 2 {
        return None;
    }
    let module_specifier = import.path[..import.path.len() - 1].join("::");
    let binder = lexical_scope::visible_import_binder_at(source, site.focus_start_byte);
    let mut candidates =
        resolve_visible_import_targets_forward(rust, token, file, &binder, focused_text)
            .into_iter()
            .flat_map(|(target_file, target_name)| {
                support.file_identifier(&target_file, &target_name)
            })
            .collect::<Vec<_>>();
    if candidates.is_empty() {
        candidates = resolve_module_files(rust, token, file, &module_specifier)
            .into_iter()
            .flat_map(|target_file| support.file_identifier(&target_file, focused_text))
            .collect();
    }
    if let Some(package) = resolve_module_package(rust, token, file, &module_specifier) {
        candidates.extend(support.fqn(&format!("{package}.{focused_text}")));
        let route_files = resolve_module_files(rust, token, file, &module_specifier);
        candidates.extend(
            rust.get_analyzed_files()
                .into_iter()
                .filter(|candidate_file| {
                    rust_crate_root_package(candidate_file) == package
                        && route_files.iter().any(|route_file| {
                            rust.files_share_cargo_target(candidate_file, route_file) != Some(false)
                        })
                })
                .flat_map(|candidate_file| rust.declarations(&candidate_file))
                .filter(|candidate| candidate.identifier() == focused_text)
                .filter(|candidate| {
                    candidate.is_macro()
                        && is_rust_macro_export_declaration(rust.code_units(), candidate)
                }),
        );
    }
    sort_units(&mut candidates);
    candidates.dedup();
    let macros = candidates
        .iter()
        .filter(|candidate| {
            candidate.is_macro() && is_rust_macro_export_declaration(rust.code_units(), candidate)
        })
        .cloned()
        .collect::<Vec<_>>();
    if macros.is_empty() {
        return None;
    }
    let has_exported_non_macro = candidates.iter().any(|candidate| {
        !candidate.is_macro() && is_rust_export_visible_declaration(rust.code_units(), candidate)
    });
    (!has_exported_non_macro).then_some(macros)
}

#[allow(clippy::too_many_arguments)]
fn rust_focused_terminal_scoped_declaration_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let scoped =
        rust_enclosing_scoped_terminal_name(focused, site.focus_start_byte, site.focus_end_byte)?;
    let (owner, member) = rust_scoped_owner_and_member(support, scoped, source)?;
    if member.is_empty() || owner.is_empty() {
        return None;
    }

    let owner_path = scoped.child_by_field_name("path")?;
    if owner_path.kind() == "identifier"
        && lexical_scope::local_item_name_shadowed_in_tree(
            tree.root_node(),
            source,
            &owner,
            site.focus_start_byte,
        )
    {
        return Some(no_definition(
            LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
            format!("`{owner}` is a local Rust item, which is not indexed"),
        ));
    }
    let owner_root = rust_scoped_path_root(owner_path);
    let owner_root_name = rust_node_text(owner_root, source).trim();
    let owner_availability = rust_owner_root_availability(
        analyzer,
        token,
        rust,
        support,
        file,
        source,
        site,
        owner_root,
        owner_root_name,
    );

    let role = rust_bare_reference_role(tree, site, source).unwrap_or(RustBareReferenceRole::Value);
    if let Some(local) = rust_local_scoped_owner_member_candidates(
        analyzer, token, rust, support, file, source, tree, site, &member, role, cache,
    ) {
        return Some(candidates_outcome(local));
    }
    let refs = support.forward_reference_context(rust, token, file)?;
    let mut candidates = refs
        .resolve_scoped(&owner, &member)
        .into_iter()
        .flat_map(|fqn| support.fqn(&fqn))
        .filter(|candidate| language_for_file(candidate.source()) == Language::Rust)
        .filter(|candidate| candidate.identifier() == member)
        .filter(|candidate| rust_role_accepts_scoped(rust, role, candidate))
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        candidates =
            match crate::analyzer::usages::rust_graph::resolve_scoped_associated_item_matching(
                rust,
                support,
                &refs,
                file,
                &owner,
                &member,
                rust_scoped_role_candidate(role),
                site.focus_start_byte,
            ) {
                ReceiverAnalysisOutcome::Precise(candidates) => candidates
                    .into_iter()
                    .filter(|candidate| rust_role_accepts_scoped(rust, role, candidate))
                    .collect(),
                ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Unknown
                | ReceiverAnalysisOutcome::Unsupported { .. }
                | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
            };
    }
    if candidates.is_empty()
        && let Some(local) = rust_local_scoped_owner_member_candidates(
            analyzer, token, rust, support, file, source, tree, site, &member, role, cache,
        )
    {
        candidates = local;
    }
    if candidates.is_empty()
        && scoped
            .child_by_field_name("path")
            .is_some_and(|path| matches!(path.kind(), "identifier" | "type_identifier"))
    {
        // Some parser-indexed local type owners do not participate in the
        // forward-reference module graph. A unique same-file type declaration
        // is still exact structured evidence for a bare scoped owner; fail
        // closed when more than one physical owner has the same spelling.
        let mut local_owners = support
            .file_identifier(file, &owner)
            .into_iter()
            .filter(|candidate| rust_is_type_definition(analyzer, candidate))
            .collect::<Vec<_>>();
        sort_units(&mut local_owners);
        local_owners.dedup();
        if let [local_owner] = local_owners.as_slice() {
            candidates = support
                .fqn(&format!("{}.{member}", local_owner.fq_name()))
                .into_iter()
                .filter(|candidate| {
                    rust_role_accepts_scoped(rust, role, candidate)
                        || (role == RustBareReferenceRole::Value
                            && candidate.is_field()
                            && rust_code_unit_range_is_enum_variant(
                                analyzer,
                                support,
                                candidate,
                                tree.root_node(),
                            ))
                })
                .collect();
        }
    }
    if matches!(
        owner_availability,
        RustOwnerRootAvailability::Boundary | RustOwnerRootAvailability::CargoBoundary
    ) {
        candidates = rust
            .candidates_in_cargo_library_route(file, owner_root_name, candidates)
            .unwrap_or_default();
        if candidates.is_empty() {
            let message = if owner_availability == RustOwnerRootAvailability::CargoBoundary {
                format!(
                    "Rust owner `{owner}` resolves through a declared Cargo dependency whose crate root is not indexed"
                )
            } else {
                format!(
                    "Rust owner `{owner}` is explicitly imported across a crate/module boundary that is not indexed"
                )
            };
            return Some(boundary_unchecked(message));
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    (!candidates.is_empty()).then(|| candidates_outcome(candidates))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RustCallTypeMatch {
    Coercion,
    Exact,
}

fn rust_filter_associated_call_outcome(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    outcome: DefinitionLookupOutcome,
) -> DefinitionLookupOutcome {
    if outcome.definitions.len() < 2 {
        return outcome;
    }
    let Some(tree) = tree else {
        return outcome;
    };
    let Some(focused) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return outcome;
    };
    let Some(scoped) =
        rust_enclosing_scoped_terminal_name(focused, site.focus_start_byte, site.focus_end_byte)
    else {
        return outcome;
    };
    let original_len = outcome.definitions.len();
    let filtered = rust_associated_call_applicable_candidates(
        analyzer,
        support,
        source,
        tree.root_node(),
        scoped,
        outcome.definitions.clone(),
    )
    .filter(|filtered| !filtered.is_empty());
    if let Some(filtered) = filtered.filter(|filtered| filtered.len() < original_len) {
        candidates_outcome(filtered)
    } else {
        outcome
    }
}

/// The positively applicable declarations for a one-argument scoped call.
/// `None` means the node is not such a call; an empty vector means it is a call
/// whose argument type provides no positive narrowing evidence.
pub(crate) fn rust_associated_call_applicable_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    source: &str,
    root: Node<'_>,
    scoped: Node<'_>,
    candidates: Vec<CodeUnit>,
) -> Option<Vec<CodeUnit>> {
    let argument = rust_single_scoped_call_argument(support, scoped)?;
    let Some(actual) = rust_call_argument_type_spellings(support, root, source, argument) else {
        return Some(Vec::new());
    };
    let scored = candidates
        .iter()
        .filter_map(|candidate| {
            let candidate_signature = candidate.signature()?;
            let expected = support
                .signature_metadata(analyzer, candidate)
                .into_iter()
                .find_map(|metadata| {
                    if !candidate_signature.ends_with(metadata.label()) {
                        return None;
                    }
                    match metadata.callable_parameter_types()? {
                        [expected] => Some(expected.to_owned()),
                        _ => None,
                    }
                })?;
            actual
                .iter()
                .find_map(|(spelling, rank)| (spelling == &expected).then_some(*rank))
                .map(|rank| (candidate.clone(), rank))
        })
        .collect::<Vec<_>>();
    let Some(best) = scored.iter().map(|(_, rank)| *rank).max() else {
        return Some(Vec::new());
    };
    Some(
        scored
            .into_iter()
            .filter_map(|(candidate, rank)| (rank == best).then_some(candidate))
            .collect(),
    )
}

fn rust_single_scoped_call_argument<'tree>(
    support: &dyn RustDefinitionProvider,
    scoped: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut function = scoped;
    while let Some(parent) = function.parent()
        && parent.kind() == "generic_function"
        && parent.child_by_field_name("function") == Some(function)
    {
        if !support.scope_step() {
            return None;
        }
        function = parent;
    }
    let call = function.parent()?;
    if call.kind() != "call_expression"
        || call.child_by_field_name("function") != Some(function)
        || !support.scope_step()
    {
        return None;
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let mut values = arguments
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "attribute_item");
    let argument = values.next()?;
    values.next().is_none().then_some(argument)
}

fn rust_call_argument_type_spellings(
    support: &dyn RustDefinitionProvider,
    root: Node<'_>,
    source: &str,
    argument: Node<'_>,
) -> Option<Vec<(String, RustCallTypeMatch)>> {
    let type_node = match argument.kind() {
        "identifier" => {
            let name = rust_node_text(argument, source).trim();
            if name.is_empty() {
                return None;
            }
            rust_binding_type_node_at(support, root, source, name, argument.start_byte())?
        }
        "cast_expression" => argument.child_by_field_name("type")?,
        _ => return None,
    };
    let exact = rust_node_text(type_node, source).trim();
    if exact.is_empty()
        || (matches!(type_node.kind(), "identifier" | "type_identifier")
            && rust_type_parameter_visible_from(type_node, source, exact))
    {
        return None;
    }
    let mut spellings = vec![(exact.to_string(), RustCallTypeMatch::Exact)];
    if type_node.kind() == "reference_type" {
        let inner = type_node.child_by_field_name("type")?;
        let mutable = (0..type_node.named_child_count()).any(|index| {
            type_node
                .named_child(index)
                .is_some_and(|child| child.kind() == "mutable_specifier")
        });
        let inner_text = rust_node_text(inner, source).trim();
        if mutable && !inner_text.is_empty() {
            spellings.push((format!("&{inner_text}"), RustCallTypeMatch::Coercion));
        }
        if inner.kind() == "array_type"
            && inner.child_by_field_name("length").is_some()
            && let Some(element) = inner.child_by_field_name("element")
        {
            let element = rust_node_text(element, source).trim();
            if !element.is_empty() {
                spellings.push((format!("&[{element}]"), RustCallTypeMatch::Coercion));
            }
        }
    }
    Some(spellings)
}

fn rust_binding_type_node_at<'tree>(
    support: &dyn RustDefinitionProvider,
    root: Node<'tree>,
    source: &str,
    name: &str,
    before_byte: usize,
) -> Option<Node<'tree>> {
    let mut found = None;
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if !support.scope_step() {
            return None;
        }
        if node.start_byte() >= before_byte {
            continue;
        }
        match node.kind() {
            "parameter" => {
                if let Some((binding, type_node)) = rust_typed_binding(support, node, source)
                    && binding == name
                {
                    found = Some(type_node);
                }
            }
            "let_declaration" if node.end_byte() <= before_byte => {
                if node
                    .child_by_field_name("pattern")
                    .and_then(|pattern| rust_simple_identifier_text(pattern, source))
                    .is_some_and(|binding| binding == name)
                    && let Some(type_node) = node.child_by_field_name("type")
                {
                    found = Some(type_node);
                }
            }
            _ => {}
        }
        for index in (0..node.named_child_count()).rev() {
            let Some(child) = node.named_child(index) else {
                continue;
            };
            if child.start_byte() < before_byte
                && !rust_scope_boundary_excludes_reference(child, before_byte)
            {
                pending.push(child);
            }
        }
    }
    found
}

fn rust_scoped_owner_and_member(
    support: &dyn RustDefinitionProvider,
    scoped: Node<'_>,
    source: &str,
) -> Option<(String, String)> {
    if let (Some(path), Some(name)) = (
        scoped.child_by_field_name("path"),
        scoped.child_by_field_name("name"),
    ) {
        let owner = rust_node_text(path, source).trim();
        let member = rust_node_text(name, source).trim();
        if !owner.is_empty() && !member.is_empty() {
            return Some((owner.to_string(), member.to_string()));
        }
    }

    let components = rust_structured_path_components(support, scoped, source)?;
    let (member, owner) = components.split_last()?;
    (!owner.is_empty()).then(|| (owner.join("::"), member.clone()))
}

fn node_within(container: Node<'_>, node: Node<'_>) -> bool {
    container.start_byte() <= node.start_byte() && node.end_byte() <= container.end_byte()
}

#[allow(clippy::too_many_arguments)]
fn rust_focused_scoped_prefix_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let prefix = rust_focused_nonterminal_prefix(focused)?;
    let focused_text = rust_node_text(focused, source).trim();
    let prefix_text = rust_node_text(prefix, source).trim();
    if focused_text.is_empty() || prefix_text.is_empty() {
        return Some(no_definition(
            "invalid_scoped_segment",
            "the focused Rust path segment is empty",
        ));
    }

    let refs = support.forward_reference_context(rust, token, file)?;
    let uses_module_package_fallback =
        rust_scoped_prefix_uses_module_package_fallback(rust, token, file, &refs, prefix, source);
    let resolved_fqn = rust_scoped_prefix_fqn(rust, token, file, &refs, prefix, source);
    let root = rust_scoped_path_root(prefix);
    Some(rust_focused_prefix_resolution_outcome(
        analyzer,
        token,
        rust,
        support,
        file,
        source,
        site,
        &refs,
        root,
        focused_text,
        prefix_text,
        RustFocusedPathRole::Owner,
        resolved_fqn.as_deref(),
        uses_module_package_fallback,
    ))
}

#[allow(clippy::too_many_arguments)]
fn rust_focused_token_tree_prefix_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    if focused.kind() == "crate"
        && std::iter::successors(focused.parent(), Node::parent)
            .any(|ancestor| ancestor.kind() == "token_tree")
    {
        return Some(no_definition(
            "crate_root_segment",
            "the focused Rust crate root is a path segment, not the terminal declaration",
        ));
    }
    let token_tree = focused.parent()?;
    if !rust_path_segment_node(focused) || token_tree.kind() != "token_tree" {
        return None;
    }
    let separator = focused.next_sibling()?;
    if separator.kind() != "::" || !separator.next_sibling().is_some_and(rust_path_segment_node) {
        return None;
    }
    let mut root = focused;
    while let Some(separator) = root.prev_sibling() {
        if separator.kind() != "::" {
            break;
        }
        let Some(segment) = separator.prev_sibling() else {
            break;
        };
        if !rust_path_segment_node(segment) {
            break;
        }
        root = segment;
    }
    let refs = support.forward_reference_context(rust, token, file)?;
    let resolved_fqn = crate::analyzer::usages::rust_graph::resolve_rust_token_tree_paths(
        rust, support, &refs, file, source, token_tree,
    )
    .into_iter()
    .find(|segment| {
        segment.node.start_byte() == focused.start_byte()
            && segment.node.end_byte() == focused.end_byte()
            && segment.role == crate::analyzer::usages::rust_graph::RustTokenPathRole::Prefix
    })
    .map(|segment| segment.fqn);
    let prefix = source.get(root.start_byte()..focused.end_byte())?.trim();
    let focused_text = rust_node_text(focused, source).trim();
    if prefix.is_empty() || focused_text.is_empty() {
        return Some(no_definition(
            "invalid_scoped_segment",
            "the focused Rust path segment is empty",
        ));
    }
    Some(rust_focused_prefix_resolution_outcome(
        analyzer,
        token,
        rust,
        support,
        file,
        source,
        site,
        &refs,
        root,
        focused_text,
        prefix,
        RustFocusedPathRole::Owner,
        resolved_fqn.as_deref(),
        false,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustFocusedPathRole {
    Owner,
    Declaration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustOwnerRootAvailability {
    Indexed,
    Boundary,
    CargoBoundary,
    Unbound,
}

#[allow(clippy::too_many_arguments)]
fn rust_owner_root_availability(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    root: Node<'_>,
    root_name: &str,
) -> RustOwnerRootAvailability {
    if matches!(root.kind(), "crate" | "self" | "super") {
        return RustOwnerRootAvailability::Indexed;
    }

    let visible_import = rust_visible_import_resolution(
        rust,
        token,
        support,
        file,
        source,
        site.focus_start_byte,
        root_name,
        RustBareReferenceRole::Owner,
    );
    let import_boundary = match visible_import {
        RustVisibleImportResolution::Resolved(candidates)
        | RustVisibleImportResolution::GlobResolved(candidates)
            if !candidates.is_empty() =>
        {
            return RustOwnerRootAvailability::Indexed;
        }
        RustVisibleImportResolution::BoundButUnindexed
        | RustVisibleImportResolution::GlobBoundButUnindexed => true,
        RustVisibleImportResolution::Resolved(_)
        | RustVisibleImportResolution::GlobResolved(_)
        | RustVisibleImportResolution::Unbound => false,
    };

    let mut syntax_root = root;
    while let Some(parent) = syntax_root.parent() {
        syntax_root = parent;
    }
    if !rust_current_module_candidates(
        analyzer,
        rust,
        support,
        file,
        syntax_root,
        site.focus_start_byte,
        site.focus_end_byte,
        root_name,
        RustBareReferenceRole::Owner,
    )
    .is_empty()
    {
        return RustOwnerRootAvailability::Indexed;
    }
    if lexical_scope::visible_import_binders_at(source, site.focus_start_byte)
        .into_iter()
        .any(|binder| {
            binder.bindings.get(root_name).is_some_and(|binding| {
                binding.kind == ImportKind::Namespace
                    && !resolve_module_files(rust, token, file, &binding.module_specifier)
                        .is_empty()
            })
        })
    {
        return RustOwnerRootAvailability::Indexed;
    }

    let rust_2015 = rust.file_uses_rust_2015_edition(file);
    let explicit_extern_route = rust_2015
        .then(|| rust_visible_extern_crate_binding(root, source, root_name))
        .flatten();
    let cargo_root_in_scope = !rust_2015 || explicit_extern_route.is_some();
    let cargo_route = explicit_extern_route.as_deref().unwrap_or(root_name);
    if let Some(root_file) = rust.resolve_cargo_crate_root_file(file, cargo_route) {
        if !cargo_root_in_scope {
            return RustOwnerRootAvailability::Boundary;
        }
        return if rust.get_analyzed_files().contains(&root_file) {
            RustOwnerRootAvailability::Indexed
        } else {
            RustOwnerRootAvailability::Boundary
        };
    }
    if cargo_root_in_scope && rust.has_available_declared_cargo_dependency(file, cargo_route) {
        return RustOwnerRootAvailability::CargoBoundary;
    }
    if import_boundary {
        return RustOwnerRootAvailability::Boundary;
    }

    RustOwnerRootAvailability::Unbound
}

fn rust_scoped_prefix_uses_module_package_fallback(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    refs: &RustReferenceContext<'_>,
    prefix: Node<'_>,
    source: &str,
) -> bool {
    let ("scoped_identifier" | "scoped_type_identifier") = prefix.kind() else {
        return false;
    };
    let Some(path) = prefix.child_by_field_name("path") else {
        return false;
    };
    let Some(name) = prefix.child_by_field_name("name") else {
        return false;
    };
    let path = rust_node_text(path, source).trim();
    let name = rust_node_text(name, source).trim();
    refs.resolve_scoped(path, name).is_none()
        && resolve_module_package(rust, token, file, rust_node_text(prefix, source).trim())
            .is_some()
}

#[allow(clippy::too_many_arguments)]
fn rust_focused_prefix_resolution_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    refs: &RustReferenceContext<'_>,
    root: Node<'_>,
    focused_text: &str,
    focused_path: &str,
    role: RustFocusedPathRole,
    resolved_fqn: Option<&str>,
    uses_module_package_fallback: bool,
) -> DefinitionLookupOutcome {
    let root_name = rust_node_text(root, source).trim();
    let root_availability = (role == RustFocusedPathRole::Owner).then(|| {
        rust_owner_root_availability(
            analyzer, token, rust, support, file, source, site, root, root_name,
        )
    });
    if role == RustFocusedPathRole::Owner && focused_path == focused_text && root_name == "self" {
        let lexical_module =
            rust_enclosing_inline_module_candidates(analyzer, support, file, source, root);
        if !lexical_module.is_empty() {
            return candidates_outcome(lexical_module);
        }
    }
    let binder = lexical_scope::visible_import_binder_at(source, site.focus_start_byte);
    // An inline module does not bring its own name into scope inside its body:
    // `mod serde_json { serde_json::Value }` names the extern-prelude crate (or
    // is unresolved), not the enclosing module. An explicit import can still
    // establish that spelling normally.
    let enclosing_module_self_root = !binder.bindings.contains_key(root_name)
        && rust_path_root_matches_enclosing_module(root, source, root_name);

    // A scoped path's bare root still obeys lexical import precedence. In
    // particular, `use dependency::*; task::spawn()` names the dependency's
    // exported `task` module even when some unrelated crate-root module also
    // has that name. Only a declaration in the actual current lexical module
    // can shadow a glob import.
    if role == RustFocusedPathRole::Owner
        && focused_path == focused_text
        && !enclosing_module_self_root
    {
        let mut syntax_root = root;
        while let Some(parent) = syntax_root.parent() {
            syntax_root = parent;
        }
        if lexical_scope::local_item_name_shadowed_in_tree(
            syntax_root,
            source,
            focused_text,
            site.focus_start_byte,
        ) {
            let local = rust_current_module_candidates(
                analyzer,
                rust,
                support,
                file,
                syntax_root,
                site.focus_start_byte,
                site.focus_end_byte,
                focused_text,
                RustBareReferenceRole::Owner,
            );
            return if local.is_empty() {
                no_definition(
                    "local_item",
                    format!(
                        "focused Rust owner `{focused_text}` is a local item that is not indexed"
                    ),
                )
            } else {
                candidates_outcome(local)
            };
        }
        match rust_visible_import_resolution(
            rust,
            token,
            support,
            file,
            source,
            site.focus_start_byte,
            focused_text,
            RustBareReferenceRole::Owner,
        ) {
            RustVisibleImportResolution::Resolved(imported) => {
                return candidates_outcome(imported);
            }
            RustVisibleImportResolution::GlobResolved(imported) => {
                let local = rust_current_module_candidates(
                    analyzer,
                    rust,
                    support,
                    file,
                    syntax_root,
                    site.focus_start_byte,
                    site.focus_end_byte,
                    focused_text,
                    RustBareReferenceRole::Owner,
                );
                return candidates_outcome(if local.is_empty() { imported } else { local });
            }
            RustVisibleImportResolution::BoundButUnindexed => {
                // The owner segment (`Error::Variant`, `Foo::Bar`) shares its
                // spelling with an unresolvable explicit import, but the path
                // owner is resolved against the local type/module namespace — an
                // import never shadows a same-file enum/type. Try the local owner
                // before claiming an unindexed boundary; only claim it when no
                // workspace-internal owner exists (issue #1126 meilisearch
                // `Error` vs `use thiserror::Error`).
                let local = rust_current_module_candidates(
                    analyzer,
                    rust,
                    support,
                    file,
                    syntax_root,
                    site.focus_start_byte,
                    site.focus_end_byte,
                    focused_text,
                    RustBareReferenceRole::Owner,
                );
                if !local.is_empty() {
                    return candidates_outcome(local);
                }
                if rust_qualified_head_is_proven_route(
                    analyzer,
                    token,
                    rust,
                    file,
                    source,
                    focused_path,
                    site.focus_start_byte,
                ) && let Some(unit) = rust_enclosing_scope_type_fallback(
                    analyzer,
                    file,
                    focused_text,
                    site.focus_start_byte,
                ) {
                    return candidates_outcome(vec![unit]);
                }
                // The enclosing-scope fallback above already returned early; the
                // remaining gate is the #1089 workspace-module-namespace check.
                return gated_boundary(
                    || rust_focused_is_workspace_module_namespace(rust, token, file, focused_text),
                    format!(
                        "focused Rust owner `{focused_text}` is explicitly imported across a crate/module boundary that is not indexed"
                    ),
                    "workspace_module_namespace",
                    format!(
                        "`{focused_text}` names a Rust crate or module in this workspace, not a single indexed declaration"
                    ),
                );
            }
            RustVisibleImportResolution::GlobBoundButUnindexed => {
                return gated_boundary(
                    || rust_focused_is_workspace_module_namespace(rust, token, file, focused_text),
                    format!(
                        "focused Rust owner `{focused_text}` is inherited from an unindexed import"
                    ),
                    "workspace_module_namespace",
                    format!(
                        "`{focused_text}` names a Rust crate or module in this workspace, not a single indexed declaration"
                    ),
                );
            }
            RustVisibleImportResolution::Unbound => {}
        }

        let local = rust_current_module_candidates(
            analyzer,
            rust,
            support,
            file,
            syntax_root,
            site.focus_start_byte,
            site.focus_end_byte,
            focused_text,
            RustBareReferenceRole::Owner,
        );
        if !local.is_empty() {
            return candidates_outcome(local);
        }

        // Rust 2018+ places Cargo dependencies in the extern prelude. A module
        // declared in an ancestor is not thereby visible by its bare name in a
        // child module, so once explicit imports and declarations in the actual
        // lexical module are exhausted, an available Cargo route wins over a
        // same-named parent/sibling declaration cached in the file-wide forward
        // reference context.
        let rust_2015 = rust.file_uses_rust_2015_edition(file);
        let explicit_extern_route = rust_2015
            .then(|| rust_visible_extern_crate_binding(root, source, focused_text))
            .flatten();
        let cargo_root_in_scope = !rust_2015 || explicit_extern_route.is_some();
        let cargo_route = explicit_extern_route.as_deref().unwrap_or(focused_text);
        let external = cargo_root_in_scope
            .then(|| resolve_module_package(rust, token, file, cargo_route))
            .flatten()
            .into_iter()
            .flat_map(|package| support.fqn(&package))
            .filter(|candidate| {
                rust_role_accepts_imported(rust, RustBareReferenceRole::Owner, candidate)
            })
            .collect();
        if let Some(routed) = rust.candidates_in_cargo_library_route(file, cargo_route, external) {
            if !cargo_root_in_scope {
                return no_definition(
                    "no_indexed_definition",
                    format!(
                        "Cargo dependency `{focused_text}` is not in the Rust 2015 implicit extern prelude"
                    ),
                );
            }
            if !routed.is_empty() {
                return candidates_outcome(routed);
            }
            // gated upstream: reached only inside a resolved Cargo library route
            // whose crate root the workspace does not index — the route
            // resolution itself is the workspace check.
            return boundary_unchecked(format!(
                "focused Rust owner `{focused_text}` resolves through Cargo but its crate root is not indexed"
            ));
        }
    }

    if let Some(fqn) = resolved_fqn
        && !(role == RustFocusedPathRole::Owner
            && focused_path != focused_text
            && uses_module_package_fallback
            && root_availability != Some(RustOwnerRootAvailability::Indexed))
        && !enclosing_module_self_root
    {
        let mut candidates: Vec<_> = support
            .fqn(fqn)
            .into_iter()
            .filter(|candidate| language_for_file(candidate.source()) == Language::Rust)
            .filter(|candidate| {
                role == RustFocusedPathRole::Declaration
                    || rust_role_accepts_imported(rust, RustBareReferenceRole::Owner, candidate)
            })
            .collect();
        if let Some(physical) = rust.candidates_in_same_cargo_target_root(file, candidates.clone())
            && !physical.is_empty()
        {
            candidates = physical;
        }
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }

    if role == RustFocusedPathRole::Owner {
        let skip_unavailable_scoped_fallback = focused_path != focused_text
            && uses_module_package_fallback
            && root_availability != Some(RustOwnerRootAvailability::Indexed);
        let mut candidates = if enclosing_module_self_root || skip_unavailable_scoped_fallback {
            Vec::new()
        } else {
            resolve_module_package(rust, token, file, focused_path)
                .into_iter()
                .flat_map(|fqn| support.fqn(&fqn))
                .filter(|candidate| {
                    rust_role_accepts_imported(rust, RustBareReferenceRole::Owner, candidate)
                })
                .collect::<Vec<_>>()
        };
        if focused_path == focused_text && !enclosing_module_self_root {
            candidates.extend(
                support
                    .file_identifier(file, focused_text)
                    .into_iter()
                    .filter(|candidate| {
                        rust_role_accepts_imported(rust, RustBareReferenceRole::Owner, candidate)
                    }),
            );
        }
        sort_units(&mut candidates);
        candidates.dedup();
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }

    if enclosing_module_self_root
        || rust_binder_has_external_binding(&binder, root_name)
        || matches!(
            root_availability,
            Some(RustOwnerRootAvailability::Boundary | RustOwnerRootAvailability::CargoBoundary)
        )
        || rust_extern_prelude_root(rust, token, support, file, refs, root, root_name)
    {
        if root_availability == Some(RustOwnerRootAvailability::CargoBoundary) {
            return boundary_unchecked(format!(
                "focused Rust path segment `{focused_text}` resolves through a declared Cargo dependency whose crate root is not indexed"
            ));
        }
        // Before a confident boundary claim, resolve the focused segment against
        // the enclosing type/trait scope: `Self::TransactionManager::run` names
        // the associated type `Connection::TransactionManager`, which shares its
        // spelling with an imported trait but is a distinct namespace and lives
        // in this file (issue #1126 diesel `TransactionManager`).
        if rust_qualified_head_is_proven_route(
            analyzer,
            token,
            rust,
            file,
            source,
            focused_path,
            site.focus_start_byte,
        ) && let Some(unit) =
            rust_enclosing_scope_type_fallback(analyzer, file, focused_text, site.focus_start_byte)
        {
            return candidates_outcome(vec![unit]);
        }
        // Only for a *bound* alias root (`use forc_pkg as pkg; pkg::Item`) do we
        // treat a resolvable workspace module as an honest namespace. When the
        // boundary is due to `enclosing_module_self_root`, the segment names the
        // extern-prelude crate that an inline `mod <name>` shadows (`mod
        // serde_json { serde_json::… }`), which is genuinely unindexed — keep the
        // boundary there.
        // Enclosing-scope fallback above returned early; the residual gate is the
        // #1089 workspace-module check (except for an inline `mod <name>` self-
        // root shadow, which stays a genuine boundary).
        return gated_boundary(
            || {
                !enclosing_module_self_root
                    && rust_focused_is_workspace_module_namespace(rust, token, file, focused_text)
            },
            format!(
                "focused Rust path segment `{focused_text}` crosses a crate/module boundary not indexed in this workspace"
            ),
            "workspace_module_namespace",
            format!(
                "`{focused_text}` names a Rust crate or module in this workspace, not a single indexed declaration"
            ),
        );
    }
    no_definition(
        "no_indexed_definition",
        format!(
            "focused Rust path segment `{focused_text}` did not resolve to an indexed definition"
        ),
    )
}

fn rust_enclosing_inline_module_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
) -> Vec<CodeUnit> {
    let mut ancestor = root.parent();
    let module = loop {
        let Some(node) = ancestor else {
            return Vec::new();
        };
        if node.kind() == "mod_item" {
            break node;
        }
        ancestor = node.parent();
    };
    let Some(name_node) = module.child_by_field_name("name") else {
        return Vec::new();
    };
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return Vec::new();
    }
    let mut candidates = support
        .file_identifier(file, name)
        .into_iter()
        .filter(CodeUnit::is_module)
        .filter(|candidate| {
            analyzer.ranges(candidate).iter().any(|range| {
                range.start_byte == module.start_byte() && range.end_byte == module.end_byte()
            })
        })
        .collect::<Vec<_>>();
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn rust_visible_extern_crate_binding(
    root: Node<'_>,
    source: &str,
    binding: &str,
) -> Option<String> {
    let mut ancestor = Some(root);
    while let Some(node) = ancestor {
        if matches!(node.kind(), "source_file" | "mod_item" | "block")
            && let Some(crate_name) = rust_extern_crate_binding_in_scope(node, source, binding)
        {
            return Some(crate_name);
        }
        ancestor = node.parent();
    }
    None
}

fn rust_extern_crate_binding_in_scope(
    scope: Node<'_>,
    source: &str,
    binding: &str,
) -> Option<String> {
    let items = if scope.kind() == "mod_item" {
        scope.child_by_field_name("body")?
    } else {
        scope
    };
    for index in 0..items.named_child_count() {
        let Some(node) = items.named_child(index) else {
            continue;
        };
        if node.kind() == "extern_crate_declaration" {
            let bound = node
                .child_by_field_name("alias")
                .or_else(|| node.child_by_field_name("name"))
                .map(|name| rust_node_text(name, source).trim() == binding)
                .unwrap_or(false);
            if bound {
                return node
                    .child_by_field_name("name")
                    .map(|name| rust_node_text(name, source).trim().to_string());
            }
        }
    }
    None
}

fn rust_path_root_matches_enclosing_module(root: Node<'_>, source: &str, root_name: &str) -> bool {
    let mut ancestor = root.parent();
    while let Some(node) = ancestor {
        if node.kind() == "mod_item"
            && node
                .child_by_field_name("name")
                .is_some_and(|name| rust_node_text(name, source).trim() == root_name)
        {
            return true;
        }
        ancestor = node.parent();
    }
    false
}

fn rust_path_segment_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "crate" | "self" | "super" | "default"
    )
}

fn rust_extern_prelude_root(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    refs: &RustReferenceContext<'_>,
    root: Node<'_>,
    root_name: &str,
) -> bool {
    matches!(root.kind(), "identifier" | "type_identifier")
        && refs.resolve_bare(root_name).is_none_or(|fqn| {
            !support.fqn(&fqn).into_iter().any(|candidate| {
                rust_role_accepts_imported(rust, RustBareReferenceRole::Owner, &candidate)
            })
        })
        && resolve_module_files(rust,token,  file, root_name).is_empty()
        // A module of this crate is evidence that the name is not an extern
        // crate, even where the bare spelling does not reach it (Rust 2018+
        // needs `crate::`). Crate-aware naming made that spelling explicit: the
        // crate-root prefix used to be empty, so the bare lookup above answered
        // for both. Without this the workspace's own `src/http.rs` would look
        // like an unindexed `http` dependency and turn a plain miss into a
        // confident boundary claim.
        && resolve_module_files(rust,token,  file, &format!("crate::{root_name}")).is_empty()
}

fn rust_focused_nonterminal_prefix<'tree>(focused: Node<'tree>) -> Option<Node<'tree>> {
    let mut prefix = focused;
    while let Some(parent) = prefix.parent() {
        if !matches!(
            parent.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        ) {
            break;
        }
        if parent
            .child_by_field_name("name")
            .is_some_and(|name| node_within(name, focused))
        {
            prefix = parent;
            continue;
        }
        break;
    }
    let parent = prefix.parent()?;
    if !matches!(
        parent.kind(),
        "scoped_identifier" | "scoped_type_identifier"
    ) {
        return None;
    }
    parent
        .child_by_field_name("path")
        .filter(|path| node_within(*path, prefix))
        .map(|_| prefix)
}

fn rust_scoped_prefix_fqn(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    refs: &RustReferenceContext<'_>,
    prefix: Node<'_>,
    source: &str,
) -> Option<String> {
    match prefix.kind() {
        "scoped_identifier" | "scoped_type_identifier" => {
            let path = prefix.child_by_field_name("path")?;
            let name = prefix.child_by_field_name("name")?;
            let path = rust_node_text(path, source).trim();
            let name = rust_node_text(name, source).trim();
            refs.resolve_scoped(path, name).or_else(|| {
                resolve_module_package(rust, token, file, rust_node_text(prefix, source).trim())
            })
        }
        "identifier" | "type_identifier" => {
            let name = rust_node_text(prefix, source).trim();
            refs.resolve_bare(name)
                .or_else(|| resolve_module_package(rust, token, file, name))
        }
        "crate" | "self" | "super" => {
            resolve_module_package(rust, token, file, rust_node_text(prefix, source).trim())
        }
        _ => None,
    }
}

fn rust_scoped_path_root(mut node: Node<'_>) -> Node<'_> {
    while matches!(node.kind(), "scoped_identifier" | "scoped_type_identifier") {
        let Some(path) = node.child_by_field_name("path") else {
            break;
        };
        node = path;
    }
    node
}

#[allow(clippy::too_many_arguments)]
fn resolve_rust_field(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
) -> Option<DefinitionLookupOutcome> {
    if !support.is_bounded()
        && let Some(outcome) = rust_token_tree_dotted_member_outcome(
            analyzer, token, support, file, source, tree, site, cache,
        )
    {
        return Some(outcome);
    }
    if let Some(node) = rust_smallest_named_node_covering(
        support,
        tree.root_node(),
        site.focus_start_byte,
        site.focus_end_byte,
    ) && let Some(field_expression) = rust_enclosing_field_expression_bounded(support, node)
    {
        if !support.scope_step() {
            return None;
        }
        let field = field_expression.child_by_field_name("field")?;
        if !support.scope_step() {
            return None;
        }
        let receiver = field_expression.child_by_field_name("value")?;
        if receiver.start_byte() <= site.focus_start_byte
            && site.focus_start_byte < receiver.end_byte()
        {
            return (receiver.kind() == "self").then(|| {
                no_definition(
                    LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND,
                    "the focused Rust receiver is a local expression, which is not indexed",
                )
            });
        }
        if !(field.start_byte() <= site.focus_start_byte
            && site.focus_start_byte < field.end_byte())
        {
            return None;
        }
        let member = rust_node_text(field, source).trim();
        let Some(owner) = rust_expression_type_fqn(
            analyzer,
            token,
            support,
            file,
            source,
            tree.root_node(),
            receiver,
            field_expression.start_byte(),
            cache,
        ) else {
            // The receiver's type could not be resolved to an indexed
            // definition at all (e.g. the owning struct is declared inside a
            // macro invocation Bifrost does not expand into declarations,
            // #1015). Returning `None` here used to fall all the way back to
            // `resolve_rust_unscoped`'s generic fallback, which reported the
            // *entire* dotted chain as unresolved with no hint (#1019). Name
            // the owner type when it can still be read syntactically from the
            // enclosing `impl` block so the caller has a concrete next query.
            return Some(rust_field_owner_unresolved_outcome(
                support, source, node, receiver, member,
            ));
        };
        let member_kind = rust_field_expression_member_kind(support, field_expression)?;
        let member_trace = RustMemberTrace::begin(analyzer, &owner);
        let considered = support.members_for_owner_name(&owner, member);
        let candidates = match member_trace.as_ref() {
            // Same filter, kept as a partition so the namespace losers the
            // untraced path drops are still named while the seam holds them.
            Some(state) => {
                let (candidates, rejected): (Vec<CodeUnit>, Vec<CodeUnit>) = considered
                    .into_iter()
                    .partition(|unit| rust_member_kind_matches(unit, member_kind));
                state.stage_direct(&candidates, &rejected);
                candidates
            }
            None => rust_member_candidates(considered, member_kind),
        };
        if candidates.is_empty()
            && !support.is_bounded()
            && member_kind == RustMemberKind::Function
            && let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer)
        {
            let refs = support.forward_reference_context(rust, token, file)?;
            let trait_candidates =
                match crate::analyzer::usages::rust_graph::resolve_trait_associated_item(
                    rust,
                    support,
                    &refs,
                    file,
                    &owner,
                    member,
                    field_expression.start_byte(),
                ) {
                    ReceiverAnalysisOutcome::Precise(resolved) => {
                        rust_member_candidates(resolved, RustMemberKind::Function)
                    }
                    ReceiverAnalysisOutcome::Ambiguous(_)
                    | ReceiverAnalysisOutcome::Unknown
                    | ReceiverAnalysisOutcome::Unsupported { .. }
                    | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
                };
            if !trait_candidates.is_empty() {
                if let Some(state) = member_trace.as_ref() {
                    state.stage_trait(&trait_candidates);
                }
                return Some(candidates_outcome(trait_candidates));
            }
        }
        return if candidates.is_empty() {
            Some(no_definition(
                "no_indexed_definition",
                format!(
                    "`{owner}.{member}` is not indexed as a Rust definition; try get_symbol_sources with \"{owner}.{member}\" or search_symbols for \"{member}\""
                ),
            ))
        } else {
            Some(candidates_outcome(candidates))
        };
    }
    None
}

/// Build an actionable `no_indexed_definition` outcome for a `receiver.member`
/// field access whose receiver type could not be resolved at all. When the
/// receiver is `self`, the enclosing `impl`'s type name can still be read
/// straight off the syntax tree even though it never resolved to an indexed
/// definition, so the hint can name it and suggest a concrete retry (#1019).
fn rust_field_owner_unresolved_outcome(
    support: &dyn RustDefinitionProvider,
    source: &str,
    node: Node<'_>,
    receiver: Node<'_>,
    member: &str,
) -> DefinitionLookupOutcome {
    if rust_node_text(receiver, source).trim() == "self"
        && let Some(owner_name) = rust_enclosing_impl_type_name_text(support, node, source)
    {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{member}` looks like a field of `{owner_name}`, but `{owner_name}` did not resolve to an indexed Rust definition (it may be declared inside a macro invocation Bifrost does not expand); try get_symbol_sources with \"{owner_name}.{member}\" or search_symbols for \"{member}\""
            ),
        );
    }
    no_definition(
        "no_indexed_definition",
        format!(
            "`{member}` did not resolve to an indexed Rust definition because its receiver's type could not be determined; try search_symbols for \"{member}\""
        ),
    )
}

/// Like [`rust_enclosing_impl_type_fqn`] but reads the impl's `Self` type name
/// straight from the syntax tree instead of resolving it to an indexed FQN, so
/// it still produces a name when the type itself is not indexed.
fn rust_enclosing_impl_type_name_text(
    support: &dyn RustDefinitionProvider,
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    let mut current = node.parent()?;
    loop {
        if !support.scope_step() {
            return None;
        }
        if current.kind() == "impl_item"
            && let Some(type_node) = current.child_by_field_name("type")
        {
            return rust_type_ref(support, type_node, source).map(|type_ref| type_ref.name);
        }
        current = current.parent()?;
    }
}

#[allow(clippy::too_many_arguments)]
fn rust_token_tree_dotted_member_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    if focused.parent()?.kind() != "token_tree" || focused.prev_sibling()?.kind() != "." {
        return None;
    }

    let mut chain = vec![focused];
    let mut current = focused;
    while let Some(separator) = current.prev_sibling() {
        if separator.kind() != "." {
            break;
        }
        let Some(receiver) = separator.prev_sibling() else {
            break;
        };
        if !matches!(receiver.kind(), "identifier" | "self") {
            break;
        }
        chain.push(receiver);
        current = receiver;
    }
    if chain.len() < 2 {
        return None;
    }
    chain.reverse();

    let root = chain[0];
    let mut owner = rust_expression_type_fqn(
        analyzer,
        token,
        support,
        file,
        source,
        tree.root_node(),
        root,
        focused.start_byte(),
        cache,
    )?;
    for field in &chain[1..chain.len() - 1] {
        let field_name = rust_node_text(*field, source).trim();
        owner = rust_field_type_fqn(
            analyzer,
            token,
            support,
            RustCurrentSyntax {
                file,
                source,
                root: tree.root_node(),
            },
            &owner,
            field_name,
            RustTypeMode::Direct,
            cache,
        )?;
    }

    let member = rust_node_text(focused, source).trim();
    let member_kind = if focused.next_sibling().is_some_and(|arguments| {
        arguments.kind() == "token_tree"
            && arguments.child(0).is_some_and(|open| open.kind() == "(")
    }) {
        RustMemberKind::Function
    } else {
        RustMemberKind::Field
    };
    let member_trace = RustMemberTrace::begin(analyzer, &owner);
    let considered = support.fqn(&format!("{owner}.{member}"));
    let mut candidates = match member_trace.as_ref() {
        Some(state) => {
            let (candidates, rejected): (Vec<CodeUnit>, Vec<CodeUnit>) = considered
                .into_iter()
                .partition(|unit| rust_member_kind_matches(unit, member_kind));
            state.stage_direct(&candidates, &rejected);
            candidates
        }
        None => rust_member_candidates(considered, member_kind),
    };
    if candidates.is_empty() && member_kind == RustMemberKind::Function {
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
        let refs = support.forward_reference_context(rust, token, file)?;
        candidates =
            match crate::analyzer::usages::rust_graph::resolve_trait_associated_item_matching(
                rust,
                support,
                &refs,
                file,
                &owner,
                member,
                CodeUnit::is_function,
                focused.start_byte(),
            ) {
                ReceiverAnalysisOutcome::Precise(resolved) => {
                    rust_member_candidates(resolved, RustMemberKind::Function)
                }
                ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Unknown
                | ReceiverAnalysisOutcome::Unsupported { .. }
                | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
            };
        if let Some(state) = member_trace.as_ref() {
            state.stage_trait(&candidates);
        }
    }
    if candidates.is_empty() {
        Some(no_definition(
            "no_indexed_definition",
            format!("`{owner}.{member}` is not indexed as a Rust definition"),
        ))
    } else {
        Some(candidates_outcome(candidates))
    }
}

fn reference_segments(
    site: &ResolvedReferenceSite,
    delimiter: &str,
    delimiter_width: usize,
) -> Option<Vec<(String, usize, usize)>> {
    let mut segments = Vec::new();
    let mut offset = 0usize;
    for part in site.text.split(delimiter) {
        if part.is_empty()
            || !part
                .chars()
                .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            return None;
        }
        let start = offset;
        let end = start + part.len();
        segments.push((part.to_string(), start, end));
        offset = end + delimiter_width;
    }
    Some(segments)
}

fn focus_segment_index(
    site: &ResolvedReferenceSite,
    segments: &[(String, usize, usize)],
) -> Option<usize> {
    let focus = site.focus_start_byte.checked_sub(site.range.start_byte)?;
    segments
        .iter()
        .position(|(_, start, end)| *start <= focus && focus < *end)
}

fn rust_enclosing_field_expression(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "field_expression" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn focused_rust_field_receiver(node: Node<'_>, focus_start: usize) -> bool {
    rust_enclosing_field_expression(node)
        .and_then(|field_expression| field_expression.child_by_field_name("value"))
        .is_some_and(|receiver| {
            receiver.start_byte() <= focus_start && focus_start < receiver.end_byte()
        })
}

pub(super) fn focused_site_is_field_receiver(root: Node<'_>, site: &ResolvedReferenceSite) -> bool {
    smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte).is_some_and(
        |node| node.kind() == "self" && focused_rust_field_receiver(node, site.focus_start_byte),
    )
}

fn rust_enclosing_field_expression_bounded<'tree>(
    support: &dyn RustDefinitionProvider,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    loop {
        if !support.scope_step() {
            return None;
        }
        if node.kind() == "field_expression" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustMemberKind {
    Field,
    Function,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustTypeMode {
    Direct,
    UnwrapContainer,
}

pub(crate) struct RustTypeLookupCache {
    declarations: HashMap<ProjectFile, Option<RustParsedDeclarationSource>>,
    allow_cold_parse: bool,
}

#[derive(Clone, Copy)]
struct RustCurrentSyntax<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'a>,
}

struct RustParsedDeclarationSource {
    source: String,
    tree: Tree,
}

impl RustTypeLookupCache {
    pub(crate) fn bounded_for_query() -> Self {
        Self {
            declarations: HashMap::default(),
            allow_cold_parse: false,
        }
    }

    fn parsed(&mut self, file: &ProjectFile) -> Option<&RustParsedDeclarationSource> {
        if !self.allow_cold_parse && !self.declarations.contains_key(file) {
            self.declarations.insert(file.clone(), None);
        }
        self.declarations
            .entry(file.clone())
            .or_insert_with(|| {
                let source = file.read_to_string().ok()?;
                let tree = lexical_scope::parse_rust_tree(&source)?;
                Some(RustParsedDeclarationSource { source, tree })
            })
            .as_ref()
    }

    #[cfg(test)]
    pub(crate) fn parsed_declaration_source_count_for_test(&self) -> usize {
        self.declarations.len()
    }
}

impl Default for RustTypeLookupCache {
    fn default() -> Self {
        Self {
            declarations: HashMap::default(),
            allow_cold_parse: true,
        }
    }
}

fn rust_field_expression_member_kind(
    support: &dyn RustDefinitionProvider,
    field_expression: Node<'_>,
) -> Option<RustMemberKind> {
    let mut function = field_expression;
    while let Some(parent) = function.parent()
        && parent.kind() == "generic_function"
        && parent.child_by_field_name("function") == Some(function)
    {
        if !support.scope_step() {
            return None;
        }
        function = parent;
    }
    if !support.scope_step() {
        return None;
    }
    if let Some(parent) = function.parent()
        && parent.kind() == "call_expression"
        && parent
            .child_by_field_name("function")
            .is_some_and(|callee| callee.id() == function.id())
    {
        Some(RustMemberKind::Function)
    } else {
        Some(RustMemberKind::Field)
    }
}

fn rust_member_kind_matches(unit: &CodeUnit, kind: RustMemberKind) -> bool {
    match kind {
        RustMemberKind::Field => unit.is_field(),
        RustMemberKind::Function => unit.is_function(),
    }
}

fn rust_member_candidates(candidates: Vec<CodeUnit>, kind: RustMemberKind) -> Vec<CodeUnit> {
    candidates
        .into_iter()
        .filter(|unit| rust_member_kind_matches(unit, kind))
        .collect()
}

/// The per-candidate member attribution the Rust `receiver.member` seams record
/// while they run (#1477).
///
/// It is built only while a trace is being recorded, and only from facts the
/// seam that builds it already holds: the receiver type the resolver looked the
/// member up on, and -- for the trait fallback -- the ancestor the production
/// walk expanded to reach it. Nothing here decides anything; the walk is
/// unchanged whether or not a recorder is installed.
///
/// Rust's two member seams are attributed differently on purpose:
///
/// - The direct lookup asks the declaration store for `owner.member`. It walks
///   no hierarchy, so every candidate it admits is depth zero with an empty
///   route. Its dispatch bucket is still not always the inherent one: a member
///   an `impl Trait for Type` block declares is indexed under `Type` and found
///   here, and the tree-sitter shape of its declaration is what says so.
/// - The trait fallback runs only when the direct lookup found nothing. It
///   expands the owner's direct ancestors and takes members declared by one of
///   them, which is exactly one hierarchy hop across an implementation edge.
struct RustMemberTrace<'a> {
    rust: &'a RustAnalyzer,
    /// The receiver's declared owner type, named by the same filters the trait
    /// fallback uses to pick its walk root. `None` when the owner name does not
    /// identify exactly one hierarchy-bearing non-trait declaration, which
    /// leaves the seam's candidates unattributed rather than guessed.
    owner: Option<CodeUnit>,
}

impl<'a> RustMemberTrace<'a> {
    /// `None` when nothing is recording, or when the analyzer is not the Rust
    /// analyzer whose hierarchy the attribution reads.
    ///
    /// The owner lookup deliberately goes to the analyzer's store rather than
    /// through `RustDefinitionProvider`. A provider lookup is charged against
    /// the resolution session's scope budget, so a recording run would spend
    /// budget the untraced run does not spend, and a request near its
    /// scope-node limit would exhaust the budget inside the real member lookup
    /// and answer differently while recording. The trace must explain the
    /// decision the product made, never change it, so every read this type
    /// performs -- this one, `get_direct_ancestors`, `structural_parent_of`,
    /// `parent_of` -- is a session-free store read. `definitions` is an exact
    /// indexed FQN lookup, so leaving it uncharged does not hide unbounded
    /// work either.
    fn begin(analyzer: &'a dyn IAnalyzer, owner_fqn: &str) -> Option<Self> {
        if !trace::recording() {
            return None;
        }
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
        // Deduplicated exactly as the provider deduplicates its own store
        // results, so "names exactly one owner" means the same thing here as it
        // did when this lookup went through the provider.
        let mut declarations: Vec<CodeUnit> = rust.definitions(owner_fqn).collect();
        sort_units(&mut declarations);
        declarations.dedup();
        let mut owners = declarations
            .into_iter()
            .filter(|unit| rust.supports_type_hierarchy(unit))
            .filter(|unit| !is_rust_trait_declaration(rust, unit));
        let owner = owners.next().filter(|_| owners.next().is_none());
        Some(Self { rust, owner })
    }

    fn direct_enrichment(&self, owner: &CodeUnit, unit: &CodeUnit) -> trace::MemberEnrichment {
        let dispatch_tier = if is_rust_trait_impl_member_declaration(self.rust, unit) {
            MemberDispatchTier::TraitOrInterface
        } else {
            MemberDispatchTier::InherentOrDirect
        };
        trace::MemberEnrichment {
            owner: owner.clone(),
            hierarchy_depth: 0,
            dispatch_tier,
            // The Rust member seams check the member's namespace and nothing
            // about the call shape, so the applicability axis (#1478) is
            // untested here, which is what `Unknown` states.
            applicability: ApplicabilityVerdict::Unknown,
            route: Vec::new(),
        }
    }

    /// Stage attribution for the candidates the direct-owner lookup admitted,
    /// and record the ones its namespace filter discarded while the seam still
    /// knows them.
    fn stage_direct(&self, selected: &[CodeUnit], rejected: &[CodeUnit]) {
        let Some(owner) = self.owner.as_ref() else {
            return;
        };
        for loser in rejected {
            trace::record(
                trace::TraceCandidate::rejected(
                    trace::TraceCandidateRef::Unit(loser.clone()),
                    None,
                    RejectionReason::WrongNamespace,
                )
                .with_member(self.direct_enrichment(owner, loser)),
            );
        }
        trace::stage_member_context(
            selected
                .iter()
                .map(|unit| (unit.fq_name(), self.direct_enrichment(owner, unit)))
                .collect(),
        );
    }

    /// Stage attribution for the candidates the trait fallback admitted. A
    /// candidate whose declaring ancestor cannot be confirmed -- the same
    /// parent-of-candidate identity the fallback itself filtered on, checked
    /// against the same direct-ancestor set it expanded -- is left
    /// unattributed instead of being given a route it may not have taken.
    fn stage_trait(&self, selected: &[CodeUnit]) {
        let Some(owner) = self.owner.as_ref() else {
            return;
        };
        let ancestors = self.rust.get_direct_ancestors(owner);
        trace::stage_member_context(
            selected
                .iter()
                .filter_map(|unit| {
                    let found_on = self
                        .rust
                        .structural_parent_of(unit)
                        .or_else(|| self.rust.parent_of(unit))
                        .filter(|parent| ancestors.contains(parent))?;
                    let enrichment = trace::MemberEnrichment {
                        owner: found_on.clone(),
                        hierarchy_depth: 1,
                        dispatch_tier: MemberDispatchTier::TraitOrInterface,
                        applicability: ApplicabilityVerdict::Unknown,
                        route: vec![trace::HierarchyHopRecord {
                            hop: 0,
                            from: owner.clone(),
                            to: found_on,
                            relation: HierarchyRelation::TraitImpl,
                        }],
                    };
                    Some((unit.fq_name(), enrichment))
                })
                .collect(),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn rust_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_expression_type_fqn_mode(
        analyzer,
        token,
        support,
        file,
        source,
        root,
        expression,
        before_byte,
        RustTypeMode::Direct,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn rust_expression_type_definition_fqn_cached(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_expression_type_fqn(
        analyzer,
        token,
        support,
        file,
        source,
        root,
        expression,
        before_byte,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn rust_expression_type_definition_candidates_cached(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
    cache: &mut RustTypeLookupCache,
) -> Vec<CodeUnit> {
    let Some(fqn) = rust_expression_type_fqn(
        analyzer,
        token,
        support,
        file,
        source,
        root,
        expression,
        before_byte,
        cache,
    ) else {
        return Vec::new();
    };
    rust_type_definition_candidates_for_fqn(
        analyzer,
        support,
        file,
        &fqn,
        before_byte,
        Some(RustCurrentSyntax { file, source, root }),
        cache,
    )
}

pub(crate) fn rust_field_definition_type_candidates_cached(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    field: &CodeUnit,
    cache: &mut RustTypeLookupCache,
) -> Vec<CodeUnit> {
    let Some(fqn) = rust_field_code_unit_type_fqn(
        analyzer,
        token,
        support,
        field.source(),
        None,
        field,
        RustTypeMode::Direct,
        cache,
    ) else {
        return Vec::new();
    };
    let reference_byte = support
        .ranges(analyzer, field)
        .into_iter()
        .next()
        .map(|range| range.start_byte)
        .unwrap_or_default();
    rust_type_definition_candidates_for_fqn(
        analyzer,
        support,
        field.source(),
        &fqn,
        reference_byte,
        None,
        cache,
    )
}

fn rust_type_definition_candidates_for_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    fqn: &str,
    reference_byte: usize,
    current_syntax: Option<RustCurrentSyntax<'_>>,
    cache: &mut RustTypeLookupCache,
) -> Vec<CodeUnit> {
    let mut candidates: Vec<_> = support
        .fqn(fqn)
        .into_iter()
        .filter(|unit| rust_is_type_definition(analyzer, unit))
        .collect();
    sort_units(&mut candidates);
    candidates.dedup();

    // Cargo target identity can only disambiguate multiple physical
    // declarations. Avoid building the workspace-wide route index for the
    // overwhelmingly common singleton lookup; doing so would hydrate every
    // Rust file in a warm persisted analyzer just to return the same result.
    if candidates.len() <= 1 {
        return candidates;
    }

    // Several Cargo targets may intentionally have the same analyzer FQN (for
    // example, two `examples/*.rs` binaries that each declare `Args`). When the
    // type expression names a declaration in its own file, retain that physical
    // identity instead of expanding the FQN back into every sibling target.
    let local_candidates = |root| {
        candidates
            .iter()
            .filter(|unit| unit.source() == file)
            .filter(|unit| {
                rust_definition_scope_visible_at(analyzer, support, unit, root, reference_byte)
            })
            .cloned()
            .collect()
    };
    let local: Vec<_> = if let Some(current) = current_syntax.filter(|current| current.file == file)
    {
        local_candidates(current.root)
    } else {
        cache
            .parsed(file)
            .map_or_else(Vec::new, |parsed| local_candidates(parsed.tree.root_node()))
    };
    if !local.is_empty() {
        return local;
    }
    if support.is_bounded() {
        return candidates;
    }
    if let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer)
        && let Some(scoped) = rust.candidates_in_same_cargo_target_root(file, candidates.clone())
        && !scoped.is_empty()
    {
        return scoped;
    }
    candidates
}

#[allow(clippy::too_many_arguments)]
fn rust_expression_type_fqn_mode(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    enum Frame<'tree> {
        Evaluate {
            expression: Node<'tree>,
            before_byte: usize,
            mode: RustTypeMode,
        },
        FinishField {
            field: Node<'tree>,
            mode: RustTypeMode,
        },
        FinishMethod {
            method: Node<'tree>,
            mode: RustTypeMode,
        },
        ContinueChildren {
            expression: Node<'tree>,
            next_index: usize,
            before_byte: usize,
            mode: RustTypeMode,
        },
    }

    let syntax = RustCurrentSyntax { file, source, root };
    let mut frames = vec![Frame::Evaluate {
        expression,
        before_byte,
        mode,
    }];
    let mut values = Vec::new();

    while let Some(frame) = frames.pop() {
        match frame {
            Frame::Evaluate {
                expression,
                before_byte,
                mode,
            } => {
                if !support.scope_step() {
                    return None;
                }
                match expression.kind() {
                    "self" if mode == RustTypeMode::Direct => {
                        values.push(rust_enclosing_impl_type_fqn(
                            analyzer, token, support, file, source, expression,
                        ));
                    }
                    "identifier" => {
                        let binding = rust_binding_type_fqn(
                            analyzer,
                            token,
                            support,
                            file,
                            source,
                            root,
                            rust_node_text(expression, source).trim(),
                            before_byte,
                            mode,
                            cache,
                        );
                        if binding.is_some() || mode != RustTypeMode::Direct {
                            values.push(binding);
                        } else {
                            let candidates = rust_callable_definition_candidates(
                                analyzer,
                                token,
                                support,
                                syntax,
                                expression,
                                before_byte,
                            );
                            values.push(rust_variant_constructed_type_fqn(
                                analyzer, support, candidates,
                            ));
                        }
                    }
                    "scoped_identifier" if mode == RustTypeMode::Direct => {
                        let candidates = rust_callable_definition_candidates(
                            analyzer,
                            token,
                            support,
                            syntax,
                            expression,
                            before_byte,
                        );
                        values.push(rust_variant_constructed_type_fqn(
                            analyzer, support, candidates,
                        ));
                    }
                    "field_expression" => {
                        if !support.scope_step() {
                            return None;
                        }
                        let Some(receiver) = expression.child_by_field_name("value") else {
                            values.push(None);
                            continue;
                        };
                        if !support.scope_step() {
                            return None;
                        }
                        let Some(field) = expression.child_by_field_name("field") else {
                            values.push(None);
                            continue;
                        };
                        frames.push(Frame::FinishField { field, mode });
                        frames.push(Frame::Evaluate {
                            expression: receiver,
                            before_byte,
                            mode: RustTypeMode::Direct,
                        });
                    }
                    "call_expression" => {
                        if !support.scope_step() {
                            return None;
                        }
                        let Some(function) = expression.child_by_field_name("function") else {
                            values.push(None);
                            continue;
                        };
                        if function.kind() == "field_expression" {
                            if !support.scope_step() {
                                return None;
                            }
                            let Some(method) = function.child_by_field_name("field") else {
                                values.push(None);
                                continue;
                            };
                            if !support.scope_step() {
                                return None;
                            }
                            let Some(receiver) = function.child_by_field_name("value") else {
                                values.push(None);
                                continue;
                            };
                            let method_name = rust_node_text(method, source).trim();
                            if matches!(method_name, "expect" | "unwrap" | "unwrap_or_default") {
                                frames.push(Frame::Evaluate {
                                    expression: receiver,
                                    before_byte: expression.start_byte(),
                                    mode: RustTypeMode::UnwrapContainer,
                                });
                            } else {
                                frames.push(Frame::FinishMethod { method, mode });
                                frames.push(Frame::Evaluate {
                                    expression: receiver,
                                    before_byte: expression.start_byte(),
                                    mode: RustTypeMode::Direct,
                                });
                            }
                        } else {
                            let candidates = rust_callable_definition_candidates(
                                analyzer,
                                token,
                                support,
                                syntax,
                                function,
                                expression.start_byte(),
                            );
                            values.push(rust_callable_return_type_fqn(
                                analyzer, token, support, syntax, candidates, mode, cache,
                            ));
                        }
                    }
                    "try_expression" => {
                        if !support.scope_step() {
                            return None;
                        }
                        if let Some(child) = expression.named_child(0) {
                            frames.push(Frame::ContinueChildren {
                                expression,
                                next_index: 1,
                                before_byte,
                                mode: RustTypeMode::UnwrapContainer,
                            });
                            frames.push(Frame::Evaluate {
                                expression: child,
                                before_byte,
                                mode: RustTypeMode::UnwrapContainer,
                            });
                        } else {
                            values.push(None);
                        }
                    }
                    "await_expression" | "parenthesized_expression" | "reference_expression" => {
                        if !support.scope_step() {
                            return None;
                        }
                        if let Some(child) = expression.named_child(0) {
                            frames.push(Frame::ContinueChildren {
                                expression,
                                next_index: 1,
                                before_byte,
                                mode,
                            });
                            frames.push(Frame::Evaluate {
                                expression: child,
                                before_byte,
                                mode,
                            });
                        } else {
                            values.push(None);
                        }
                    }
                    "struct_expression" if mode == RustTypeMode::Direct => {
                        if !support.scope_step() {
                            return None;
                        }
                        let Some(name) = expression.child_by_field_name("name") else {
                            values.push(None);
                            continue;
                        };
                        let variant = support.is_bounded().then(|| {
                            rust_callable_definition_candidates(
                                analyzer,
                                token,
                                support,
                                syntax,
                                name,
                                expression.start_byte(),
                            )
                        });
                        values.push(
                            variant
                                .and_then(|candidates| {
                                    rust_variant_constructed_type_fqn(analyzer, support, candidates)
                                })
                                .or_else(|| {
                                    rust_resolve_type_node_fqn(
                                        analyzer,
                                        token,
                                        support,
                                        file,
                                        source,
                                        name,
                                        Some(name.start_byte()),
                                    )
                                }),
                        );
                    }
                    _ => values.push(None),
                }
            }
            Frame::FinishField { field, mode } => {
                let owner = values.pop().flatten();
                values.push(owner.and_then(|owner| {
                    let member = rust_node_text(field, source).trim();
                    rust_field_type_fqn(
                        analyzer, token, support, syntax, &owner, member, mode, cache,
                    )
                }));
            }
            Frame::FinishMethod { method, mode } => {
                let owner = values.pop().flatten();
                values.push(owner.and_then(|owner| {
                    let method_name = rust_node_text(method, source).trim();
                    rust_callable_return_type_fqn(
                        analyzer,
                        token,
                        support,
                        syntax,
                        support.members_for_owner_name(&owner, method_name),
                        mode,
                        cache,
                    )
                }));
            }
            Frame::ContinueChildren {
                expression,
                next_index,
                before_byte,
                mode,
            } => {
                let child_value = values.pop().flatten();
                if child_value.is_some() {
                    values.push(child_value);
                    continue;
                }
                if !support.scope_step() {
                    return None;
                }
                if let Some(child) = expression.named_child(next_index) {
                    frames.push(Frame::ContinueChildren {
                        expression,
                        next_index: next_index + 1,
                        before_byte,
                        mode,
                    });
                    frames.push(Frame::Evaluate {
                        expression: child,
                        before_byte,
                        mode,
                    });
                } else {
                    values.push(None);
                }
            }
        }
    }

    values.pop().flatten()
}

#[allow(clippy::too_many_arguments)]
fn rust_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    let mut found = None;
    let mut ctx = RustBindingLookupCtx {
        analyzer,
        support,
        file,
        source,
        root,
        name,
        before_byte,
        mode,
        cache,
    };
    rust_collect_binding_type_fqn(&mut ctx, token, root, &mut found);
    found
}

struct RustBindingLookupCtx<'a, 'tree, 'cache> {
    analyzer: &'a dyn IAnalyzer,
    support: &'a dyn RustDefinitionProvider,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
    name: &'a str,
    before_byte: usize,
    mode: RustTypeMode,
    cache: &'cache mut RustTypeLookupCache,
}

fn rust_collect_binding_type_fqn(
    ctx: &mut RustBindingLookupCtx<'_, '_, '_>,
    token: QueryToken<'_>,
    root: Node<'_>,
    found: &mut Option<String>,
) {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if !ctx.support.scope_step() {
            return;
        }
        if node.start_byte() >= ctx.before_byte {
            continue;
        }
        match node.kind() {
            "parameter" => {
                if let Some((binding, type_node)) =
                    rust_typed_binding(ctx.support, node, ctx.source)
                    && binding == ctx.name
                    && let Some(fqn) = rust_resolve_type_node_fqn_mode(
                        ctx,
                        token,
                        type_node,
                        Some(type_node.start_byte()),
                    )
                {
                    *found = Some(fqn);
                }
            }
            "let_declaration" if node.end_byte() <= ctx.before_byte => {
                let pattern = node.child_by_field_name("pattern");
                if pattern.is_some() && !ctx.support.scope_step() {
                    return;
                }
                if let Some(binding) =
                    pattern.and_then(|pattern| rust_simple_identifier_text(pattern, ctx.source))
                    && binding == ctx.name
                {
                    let type_node = node.child_by_field_name("type");
                    if type_node.is_some() && !ctx.support.scope_step() {
                        return;
                    }
                    if let Some(type_node) = type_node
                        && let Some(fqn) = rust_resolve_type_node_fqn_mode(
                            ctx,
                            token,
                            type_node,
                            Some(type_node.start_byte()),
                        )
                    {
                        *found = Some(fqn);
                    } else {
                        let value = node.child_by_field_name("value");
                        if value.is_some() && !ctx.support.scope_step() {
                            return;
                        }
                        if let Some(value) = value
                            && let Some(fqn) = rust_expression_type_fqn_mode(
                                ctx.analyzer,
                                token,
                                ctx.support,
                                ctx.file,
                                ctx.source,
                                ctx.root,
                                value,
                                value.start_byte(),
                                ctx.mode,
                                ctx.cache,
                            )
                        {
                            *found = Some(fqn);
                        }
                    }
                }
            }
            _ => {}
        }

        for index in (0..node.named_child_count()).rev() {
            let Some(child) = node.named_child(index) else {
                continue;
            };
            if !ctx.support.scope_step() {
                return;
            }
            if child.start_byte() < ctx.before_byte
                && !rust_scope_boundary_excludes_reference(child, ctx.before_byte)
            {
                pending.push(child);
            }
        }
    }
}

fn rust_resolve_type_node_fqn_mode(
    ctx: &mut RustBindingLookupCtx<'_, '_, '_>,
    token: QueryToken<'_>,
    type_node: Node<'_>,
    reference_byte: Option<usize>,
) -> Option<String> {
    let target_node = match ctx.mode {
        RustTypeMode::Direct => type_node,
        RustTypeMode::UnwrapContainer => {
            rust_unwrap_container_type_node(ctx.support, type_node, ctx.source)?
        }
    };
    rust_resolve_type_node_fqn(
        ctx.analyzer,
        token,
        ctx.support,
        ctx.file,
        ctx.source,
        target_node,
        reference_byte,
    )
}

fn rust_scope_boundary_excludes_reference(node: Node<'_>, reference_byte: usize) -> bool {
    rust_is_scope_boundary(node.kind())
        && !(node.start_byte() <= reference_byte && reference_byte <= node.end_byte())
}

fn rust_is_scope_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "block"
            | "block_expression"
            | "closure_expression"
            | "const_item"
            | "enum_item"
            | "function_item"
            | "impl_item"
            | "macro_definition"
            | "mod_item"
            | "static_item"
            | "trait_item"
    )
}

fn rust_typed_binding<'tree>(
    support: &dyn RustDefinitionProvider,
    node: Node<'tree>,
    source: &str,
) -> Option<(String, Node<'tree>)> {
    if !support.scope_step() {
        return None;
    }
    let pattern = node.child_by_field_name("pattern")?;
    if !support.scope_step() {
        return None;
    }
    let name = rust_simple_identifier_text(pattern, source)?;
    let type_node = node.child_by_field_name("type")?;
    if !support.scope_step() {
        return None;
    }
    Some((name, type_node))
}

fn rust_callable_definition_candidates(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    syntax: RustCurrentSyntax<'_>,
    function: Node<'_>,
    reference_byte: usize,
) -> Vec<CodeUnit> {
    let RustCurrentSyntax {
        file, source, root, ..
    } = syntax;
    if matches!(
        function.kind(),
        "scoped_identifier" | "scoped_type_identifier"
    ) {
        if support.is_bounded() {
            return rust_bounded_scoped_callable_candidates(
                analyzer, token, support, file, source, function,
            );
        }
        let Some(path) = function.child_by_field_name("path") else {
            return Vec::new();
        };
        let Some(name) = function.child_by_field_name("name") else {
            return Vec::new();
        };
        let path = rust_node_text(path, source).trim();
        let name = rust_node_text(name, source).trim();
        if path.is_empty() || name.is_empty() {
            return Vec::new();
        }
        let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
            return Vec::new();
        };
        let Some(refs) = support.forward_reference_context(rust, token, file) else {
            return Vec::new();
        };
        return match crate::analyzer::usages::rust_graph::resolve_scoped_associated_item(
            rust,
            support,
            &refs,
            file,
            path,
            name,
            reference_byte,
        ) {
            ReceiverAnalysisOutcome::Precise(candidates) => candidates,
            ReceiverAnalysisOutcome::Ambiguous(_)
            | ReceiverAnalysisOutcome::Unknown
            | ReceiverAnalysisOutcome::Unsupported { .. }
            | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
        };
    }
    let Some(name) = rust_callable_name(support, function, source) else {
        return Vec::new();
    };
    rust_callable_candidates(analyzer, token, support, file, root, &name, reference_byte)
}

fn rust_bounded_scoped_callable_candidates(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
) -> Vec<CodeUnit> {
    if !support.scope_step() {
        return Vec::new();
    }
    let Some(name_node) = function.child_by_field_name("name") else {
        return Vec::new();
    };
    if !support.scope_step() {
        return Vec::new();
    }
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return Vec::new();
    }
    let Some(path) = function.child_by_field_name("path") else {
        return Vec::new();
    };
    if !support.scope_step() {
        return Vec::new();
    }
    if let Some(owner) = rust_resolve_type_node_fqn_bounded(
        analyzer,
        token,
        support,
        file,
        source,
        path,
        Some(path.start_byte()),
    ) {
        return support
            .members_for_owner_name(&owner, name)
            .into_iter()
            .filter(|candidate| candidate.is_function() || candidate.is_field())
            .collect();
    }
    let Some(components) = rust_structured_path_components(support, function, source) else {
        return Vec::new();
    };
    let Some(lexical_package) = rust_lexical_package_fqn(support, file, function, source) else {
        return Vec::new();
    };
    let Some(candidate) = resolve_rust_module_segments_with_crate(
        &lexical_package,
        &rust_crate_root_package(file),
        &components,
    ) else {
        return Vec::new();
    };
    let package = rust_package_name(file);
    let mut candidates = support.fqn(&candidate);
    let explicitly_rooted = components
        .first()
        .is_some_and(|root| matches!(root.as_str(), "crate" | "self" | "super"));
    if candidates.is_empty() && !package.is_empty() && !explicitly_rooted {
        candidates = support.fqn(&format!("{package}.{candidate}"));
    }
    candidates
        .into_iter()
        .filter(|candidate| candidate.is_function() || candidate.is_field())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn rust_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    syntax: RustCurrentSyntax<'_>,
    owner_fqn: &str,
    member: &str,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    let fields = support
        .members_for_owner_name(owner_fqn, member)
        .into_iter()
        .filter(CodeUnit::is_field)
        .collect::<Vec<_>>();
    if !support.is_bounded() {
        return fields.into_iter().find_map(|field| {
            rust_field_code_unit_type_fqn(
                analyzer,
                token,
                support,
                syntax.file,
                Some(syntax),
                &field,
                mode,
                cache,
            )
        });
    }
    let mut types = fields
        .into_iter()
        .filter_map(|field| {
            rust_field_code_unit_type_fqn(
                analyzer,
                token,
                support,
                syntax.file,
                Some(syntax),
                &field,
                mode,
                cache,
            )
        })
        .collect::<Vec<_>>();
    types.sort();
    types.dedup();
    (types.len() == 1).then(|| types.remove(0))
}

fn rust_callable_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    syntax: RustCurrentSyntax<'_>,
    candidates: Vec<CodeUnit>,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    if !support.is_bounded() {
        return candidates.into_iter().find_map(|candidate| {
            rust_variant_code_unit_type_fqn(analyzer, support, &candidate, mode).or_else(|| {
                rust_function_code_unit_return_type_fqn(
                    analyzer,
                    token,
                    support,
                    syntax.file,
                    Some(syntax),
                    &candidate,
                    mode,
                    cache,
                )
            })
        });
    }
    let mut types = candidates
        .into_iter()
        .filter_map(|candidate| {
            rust_variant_code_unit_type_fqn(analyzer, support, &candidate, mode).or_else(|| {
                rust_function_code_unit_return_type_fqn(
                    analyzer,
                    token,
                    support,
                    syntax.file,
                    Some(syntax),
                    &candidate,
                    mode,
                    cache,
                )
            })
        })
        .collect::<Vec<_>>();
    types.sort();
    types.dedup();
    (types.len() == 1).then(|| types.remove(0))
}

fn rust_variant_constructed_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    candidates: Vec<CodeUnit>,
) -> Option<String> {
    let mut owners = candidates
        .into_iter()
        .filter_map(|candidate| {
            rust_variant_code_unit_type_fqn(analyzer, support, &candidate, RustTypeMode::Direct)
        })
        .collect::<Vec<_>>();
    owners.sort();
    owners.dedup();
    (owners.len() == 1).then(|| owners.remove(0))
}

fn rust_variant_code_unit_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    candidate: &CodeUnit,
    mode: RustTypeMode,
) -> Option<String> {
    if !candidate.is_field() || mode != RustTypeMode::Direct {
        return None;
    }
    let mut owners = Vec::new();
    for metadata in support.signature_metadata(analyzer, candidate) {
        if !support.scope_step() {
            return None;
        }
        let Some(identity) = metadata.into_return_type_identity() else {
            continue;
        };
        let Some(owner) = rust_structured_type_identity_fqn(support, candidate.source(), &identity)
        else {
            continue;
        };
        owners.push(owner);
    }
    owners.sort();
    owners.dedup();
    (owners.len() == 1).then(|| owners.remove(0))
}

fn rust_structured_type_identity_fqn(
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    identity: &StructuredTypeIdentity,
) -> Option<String> {
    let name = identity.nominal_name_with(|| support.scope_step())?;
    if name.is_absolute() {
        return None;
    }
    let mut fqn = rust_package_name(file);
    for component in name.lexical_scope().iter().chain(name.path()) {
        if !support.scope_step() || component.is_empty() {
            return None;
        }
        if !fqn.is_empty() {
            fqn.push('.');
        }
        fqn.push_str(component);
    }
    let mut candidates = support
        .fqn(&fqn)
        .into_iter()
        .filter(CodeUnit::is_class)
        .collect::<Vec<_>>();
    sort_units(&mut candidates);
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0).fq_name())
}

#[allow(clippy::too_many_arguments)]
fn rust_field_code_unit_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    current_syntax: Option<RustCurrentSyntax<'_>>,
    field: &CodeUnit,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_code_unit_type_fqn(
        analyzer,
        token,
        support,
        file,
        current_syntax,
        field,
        "type",
        mode,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn rust_function_code_unit_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    current_syntax: Option<RustCurrentSyntax<'_>>,
    function: &CodeUnit,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_code_unit_type_fqn(
        analyzer,
        token,
        support,
        file,
        current_syntax,
        function,
        "return_type",
        mode,
        cache,
    )
}

#[allow(clippy::too_many_arguments)]
fn rust_code_unit_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    current_syntax: Option<RustCurrentSyntax<'_>>,
    code_unit: &CodeUnit,
    field_name: &str,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    if let Some(current) =
        current_syntax.filter(|current| current.file == file && code_unit.source() == file)
    {
        return rust_code_unit_type_fqn_from_syntax(
            analyzer,
            token,
            support,
            code_unit,
            field_name,
            mode,
            current.source,
            current.root,
        );
    }
    let parsed = cache.parsed(code_unit.source())?;
    rust_code_unit_type_fqn_from_syntax(
        analyzer,
        token,
        support,
        code_unit,
        field_name,
        mode,
        &parsed.source,
        parsed.tree.root_node(),
    )
}

#[allow(clippy::too_many_arguments)]
fn rust_code_unit_type_fqn_from_syntax(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    code_unit: &CodeUnit,
    field_name: &str,
    mode: RustTypeMode,
    source: &str,
    root: Node<'_>,
) -> Option<String> {
    let declaration = rust_code_unit_declaration_node(analyzer, support, code_unit, root)?;
    let type_node = declaration.child_by_field_name(field_name)?;
    if !support.scope_step() {
        return None;
    }
    let target_node = match mode {
        RustTypeMode::Direct => type_node,
        RustTypeMode::UnwrapContainer => {
            rust_unwrap_container_type_node(support, type_node, source)?
        }
    };
    rust_resolve_type_node_fqn(
        analyzer,
        token,
        support,
        code_unit.source(),
        source,
        target_node,
        Some(target_node.start_byte()),
    )
}

fn rust_code_unit_declaration_node<'tree>(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    code_unit: &CodeUnit,
    root: Node<'tree>,
) -> Option<Node<'tree>> {
    for range in support.ranges(analyzer, code_unit) {
        let Some(node) =
            rust_smallest_named_node_covering(support, root, range.start_byte, range.end_byte)
        else {
            continue;
        };
        if !support.scope_step() {
            return None;
        }
        if node.child_by_field_name("name").is_some() {
            return Some(node);
        }
    }
    None
}

fn rust_code_unit_range_is_enum_variant(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    code_unit: &CodeUnit,
    root: Node<'_>,
) -> bool {
    for range in support.ranges(analyzer, code_unit) {
        let Some(mut node) =
            rust_smallest_named_node_covering(support, root, range.start_byte, range.end_byte)
        else {
            continue;
        };
        loop {
            if !support.scope_step() {
                return false;
            }
            if node.kind() == "enum_variant"
                && node.child_by_field_name("name").is_some_and(|name| {
                    (range.start_byte <= name.start_byte() && name.end_byte() <= range.end_byte)
                        || (name.start_byte() <= range.start_byte
                            && range.end_byte <= name.end_byte())
                })
            {
                return true;
            }
            let Some(parent) = node.parent() else {
                break;
            };
            node = parent;
        }
    }
    false
}

pub(crate) fn rust_resolve_type_node_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
    reference_byte: Option<usize>,
) -> Option<String> {
    if support.is_bounded() {
        return rust_resolve_type_node_fqn_bounded(
            analyzer,
            token,
            support,
            file,
            source,
            type_node,
            reference_byte,
        );
    }
    let type_ref = rust_type_ref(support, type_node, source)?;
    let name = type_ref.name.as_str();
    if type_ref.path.is_none() && name == "Self" {
        return rust_enclosing_impl_type_fqn(analyzer, token, support, file, source, type_node);
    }
    if let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) {
        let refs = support.forward_reference_context(rust, token, file)?;
        if let Some(path) = type_ref.path.as_deref() {
            if let Some(resolved) = refs.resolve_scoped(path, name).filter(|resolved| {
                support
                    .fqn(resolved)
                    .into_iter()
                    .any(|unit| rust_is_type_definition(analyzer, &unit))
            }) {
                return Some(resolved);
            }
            let named = rust_named_type_node(support, type_node)?;
            let path_node = named.child_by_field_name("path")?;
            let owner_fqn = crate::analyzer::usages::rust_graph::lexical_explicit_import_fqn(
                rust, token, support, file, source, path_node,
            )?;
            let mut candidates = support
                .members_for_owner_name(&owner_fqn, name)
                .into_iter()
                .filter(|unit| rust_is_type_definition(analyzer, unit))
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>();
            candidates.sort();
            candidates.dedup();
            return (candidates.len() == 1).then(|| candidates.remove(0));
        }
        if let Some(reference_byte) = reference_byte {
            if let Some(local) =
                rust_local_type_fqn_visible_at(analyzer, support, file, name, reference_byte)
            {
                return Some(local);
            }
        } else if let Some(resolved) = refs.resolve_bare(name)
            && support
                .fqn(&resolved)
                .into_iter()
                .any(|unit| rust_is_type_definition(analyzer, &unit))
            && rust_type_fqn_visible_from_file(file, &resolved)
        {
            return Some(resolved.to_string());
        }
        if let Some(imported) =
            rust_import_type_fqn(rust, token, support, file, name, reference_byte)
        {
            return Some(imported);
        }
    }
    support
        .fqn(name)
        .into_iter()
        .find(|unit| rust_is_type_definition(analyzer, unit))
        .map(|unit| unit.fq_name().to_string())
}

fn rust_resolve_type_node_fqn_bounded(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
    reference_byte: Option<usize>,
) -> Option<String> {
    let named = rust_named_type_node(support, type_node)?;
    let components = rust_structured_path_components(support, named, source)?;
    let (name, owner) = components.split_last()?;
    if owner.is_empty() && name == "Self" {
        return rust_enclosing_impl_type_fqn(analyzer, token, support, file, source, type_node);
    }

    if owner.is_empty() {
        if let Some(reference_byte) = reference_byte
            && let Some(local) = rust_local_type_fqn_visible_at_bounded(
                analyzer,
                support,
                file,
                rust_root_node(support, type_node)?,
                name,
                reference_byte,
            )
        {
            return Some(local);
        }
        let package = rust_package_name(file);
        let lexical_module = rust_lexical_module_fqn(support, type_node, source)?;
        let local_owner = match (package.is_empty(), lexical_module.is_empty()) {
            (true, true) => String::new(),
            (false, true) => package,
            (true, false) => lexical_module,
            (false, false) => format!("{package}.{lexical_module}"),
        };
        let local_fqn = if local_owner.is_empty() {
            name.clone()
        } else {
            format!("{local_owner}.{name}")
        };
        return rust_unique_type_fqn(analyzer, support, &local_fqn);
    }

    let candidate = if owner.first().is_some_and(|root| root == "Self") {
        let self_fqn =
            rust_enclosing_impl_type_fqn(analyzer, token, support, file, source, type_node)?;
        std::iter::once(self_fqn)
            .chain(owner[1..].iter().cloned())
            .chain(std::iter::once(name.clone()))
            .collect::<Vec<_>>()
            .join(".")
    } else {
        let lexical_package = rust_lexical_package_fqn(support, file, type_node, source)?;
        resolve_rust_module_segments_with_crate(
            &lexical_package,
            &rust_crate_root_package(file),
            &components,
        )?
    };
    rust_unique_type_fqn(analyzer, support, &candidate).or_else(|| {
        if components
            .first()
            .is_some_and(|root| matches!(root.as_str(), "crate" | "self" | "super"))
        {
            return None;
        }
        let package = rust_package_name(file);
        (!package.is_empty())
            .then(|| format!("{package}.{candidate}"))
            .and_then(|candidate| rust_unique_type_fqn(analyzer, support, &candidate))
    })
}

fn rust_lexical_module_fqn(
    support: &dyn RustDefinitionProvider,
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    let mut components = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if !support.scope_step() {
            return None;
        }
        if parent.kind() == "mod_item" {
            let name = parent.child_by_field_name("name")?;
            if !support.scope_step() {
                return None;
            }
            let name = rust_node_text(name, source).trim();
            if name.is_empty() {
                return None;
            }
            components.push(name.to_string());
        }
        current = parent.parent();
    }
    components.reverse();
    Some(components.join("."))
}

fn rust_lexical_package_fqn(
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    let package = rust_package_name(file);
    let lexical_module = rust_lexical_module_fqn(support, node, source)?;
    Some(match (package.is_empty(), lexical_module.is_empty()) {
        (true, true) => String::new(),
        (false, true) => package,
        (true, false) => lexical_module,
        (false, false) => format!("{package}.{lexical_module}"),
    })
}

fn rust_unique_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    fqn: &str,
) -> Option<String> {
    let mut candidates = support
        .fqn(fqn)
        .into_iter()
        .filter(|unit| rust_is_type_definition(analyzer, unit))
        .map(|unit| unit.fq_name())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn rust_local_type_fqn_visible_at_bounded(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    root: Node<'_>,
    name: &str,
    reference_byte: usize,
) -> Option<String> {
    let reference_mod = lexical_scope::enclosing_mod_item_range_at(root, reference_byte);
    let mut candidates = support
        .file_identifier(file, name)
        .into_iter()
        .filter(|unit| rust_is_type_definition(analyzer, unit))
        .filter(|unit| {
            let Some(declaration) = rust_code_unit_declaration_node(analyzer, support, unit, root)
            else {
                return false;
            };
            rust_node_scope_visible_at(support, declaration, reference_byte)
                && lexical_scope::enclosing_mod_item_range_at(root, declaration.start_byte())
                    == reference_mod
        })
        .map(|unit| unit.fq_name())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn rust_structured_path_components(
    support: &dyn RustDefinitionProvider,
    node: Node<'_>,
    source: &str,
) -> Option<Vec<String>> {
    let mut components = Vec::new();
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
        if !support.scope_step() {
            return None;
        }
        match current.kind() {
            "type_identifier" | "identifier" | "self" | "super" | "crate" => {
                let text = rust_node_text(current, source).trim();
                if text.is_empty() {
                    return None;
                }
                components.push(text.to_string());
            }
            "scoped_type_identifier" | "scoped_identifier" => {
                let path = current.child_by_field_name("path")?;
                if !support.scope_step() {
                    return None;
                }
                let name = current.child_by_field_name("name")?;
                if !support.scope_step() {
                    return None;
                }
                pending.push(name);
                pending.push(path);
            }
            "generic_type" | "generic_function" => {
                let base = current
                    .child_by_field_name("type")
                    .or_else(|| current.child_by_field_name("function"))?;
                if !support.scope_step() {
                    return None;
                }
                pending.push(base);
            }
            "qualified_type" => {
                let inner = current.child_by_field_name("type")?;
                if !support.scope_step() {
                    return None;
                }
                pending.push(inner);
            }
            _ => return None,
        }
    }
    (!components.is_empty()).then_some(components)
}

pub(crate) fn rust_is_type_definition(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    unit.is_class()
        || analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(unit))
}

#[derive(Debug)]
struct RustTypeRef {
    path: Option<String>,
    name: String,
}

fn rust_type_ref(
    support: &dyn RustDefinitionProvider,
    type_node: Node<'_>,
    source: &str,
) -> Option<RustTypeRef> {
    let mut node = rust_named_type_node(support, type_node)?;
    loop {
        if !support.scope_step() {
            return None;
        }
        match node.kind() {
            "generic_type" | "generic_function" => {
                node = node
                    .child_by_field_name("type")
                    .or_else(|| node.child_by_field_name("function"))?;
                continue;
            }
            "qualified_type" => {
                node = node.child_by_field_name("type")?;
                continue;
            }
            _ => break,
        }
    }
    match node.kind() {
        "type_identifier" | "identifier" | "self" | "super" | "crate" => {
            let name = rust_node_text(node, source).trim();
            (!name.is_empty()).then(|| RustTypeRef {
                path: None,
                name: name.to_string(),
            })
        }
        "scoped_type_identifier" | "scoped_identifier" => {
            let name = node.child_by_field_name("name")?;
            if !support.scope_step() {
                return None;
            }
            let name = rust_node_text(name, source).trim();
            if name.is_empty() {
                return None;
            }
            Some(RustTypeRef {
                path: node
                    .child_by_field_name("path")
                    .and_then(|path| rust_type_path_text(support, path, source)),
                name: name.to_string(),
            })
        }
        _ => None,
    }
}

fn rust_named_type_node<'tree>(
    support: &dyn RustDefinitionProvider,
    type_node: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut pending = vec![type_node];
    while let Some(node) = pending.pop() {
        if !support.scope_step() {
            return None;
        }
        match node.kind() {
            "reference_type"
            | "pointer_type"
            | "array_type"
            | "bracketed_type"
            | "higher_ranked_trait_bound" => {
                let child = node.child_by_field_name("type")?;
                if !support.scope_step() {
                    return None;
                }
                pending.push(child);
            }
            "generic_type"
            | "generic_function"
            | "qualified_type"
            | "scoped_type_identifier"
            | "scoped_identifier"
            | "type_identifier"
            | "identifier"
            | "self"
            | "super"
            | "crate" => return Some(node),
            _ => {
                for index in (0..node.named_child_count()).rev() {
                    let Some(child) = node.named_child(index) else {
                        continue;
                    };
                    if !support.scope_step() {
                        return None;
                    }
                    pending.push(child);
                }
            }
        }
    }
    None
}

fn rust_type_path_text(
    support: &dyn RustDefinitionProvider,
    mut path: Node<'_>,
    source: &str,
) -> Option<String> {
    loop {
        if !support.scope_step() {
            return None;
        }
        if matches!(path.kind(), "generic_type" | "generic_function") {
            path = path
                .child_by_field_name("type")
                .or_else(|| path.child_by_field_name("function"))?;
            continue;
        }
        break;
    }
    match path.kind() {
        "scoped_type_identifier"
        | "scoped_identifier"
        | "identifier"
        | "self"
        | "super"
        | "crate" => {
            let text = rust_node_text(path, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        _ => {
            let text = rust_node_text(path, source).trim();
            (!text.is_empty()).then(|| text.to_string())
        }
    }
}

fn rust_unwrap_container_type_node<'tree>(
    support: &dyn RustDefinitionProvider,
    type_node: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let node = rust_named_type_node(support, type_node)?;
    let type_ref = rust_type_ref(support, node, source)?;
    let is_container = matches!(
        (type_ref.path.as_deref(), type_ref.name.as_str()),
        (None, "Result")
            | (Some("std::result"), "Result")
            | (Some("anyhow"), "Result")
            | (None, "Option")
            | (Some("std::option"), "Option")
    );
    if !is_container {
        return None;
    }
    let type_arguments = node.child_by_field_name("type_arguments")?;
    if !support.scope_step() {
        return None;
    }
    let mut cursor = type_arguments.walk();
    let first = type_arguments.named_children(&mut cursor).next()?;
    if !support.scope_step() {
        return None;
    }
    rust_named_type_node(support, first)
}

fn rust_import_type_fqn(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    name: &str,
    reference_byte: Option<usize>,
) -> Option<String> {
    let visible = reference_byte
        .zip(file.read_to_string().ok())
        .map(|(reference_byte, source)| {
            rust_visible_import_resolution(
                rust,
                token,
                support,
                file,
                &source,
                reference_byte,
                name,
                RustBareReferenceRole::Type,
            )
        });
    let imported = match visible {
        Some(
            RustVisibleImportResolution::Resolved(candidates)
            | RustVisibleImportResolution::GlobResolved(candidates),
        ) => candidates,
        Some(
            RustVisibleImportResolution::BoundButUnindexed
            | RustVisibleImportResolution::GlobBoundButUnindexed,
        ) => Vec::new(),
        Some(RustVisibleImportResolution::Unbound) | None => {
            rust_imported_export_candidates(rust, token, support, file, name, reference_byte)
        }
    };
    let mut candidates: Vec<_> = imported
        .into_iter()
        .filter(|unit| unit.is_class())
        .collect();
    sort_units(&mut candidates);
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0).fq_name())
}

fn rust_type_fqn_visible_from_file(file: &ProjectFile, fqn: &str) -> bool {
    rust_fqn_package(fqn) == rust_local_package_name(file)
}

fn rust_local_type_fqn_visible_at(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    name: &str,
    reference_byte: usize,
) -> Option<String> {
    let source = file.read_to_string().ok()?;
    let tree = lexical_scope::parse_rust_tree(&source)?;
    let reference_mod =
        lexical_scope::enclosing_mod_item_range_at(tree.root_node(), reference_byte);
    let mut candidates: Vec<_> = support
        .file_identifier(file, name)
        .into_iter()
        .filter(|unit| unit.is_class())
        .filter(|unit| {
            let Some(declaration) =
                rust_code_unit_declaration_node(analyzer, support, unit, tree.root_node())
            else {
                return false;
            };
            rust_node_scope_visible_at(support, declaration, reference_byte)
                && lexical_scope::enclosing_mod_item_range_at(
                    tree.root_node(),
                    declaration.start_byte(),
                ) == reference_mod
        })
        .collect();
    sort_units(&mut candidates);
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0).fq_name())
}

fn rust_definition_scope_visible_at(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    definition: &CodeUnit,
    root: Node<'_>,
    reference_byte: usize,
) -> bool {
    let Some(definition_node) =
        rust_code_unit_declaration_node(analyzer, support, definition, root)
    else {
        return false;
    };
    rust_node_scope_visible_at(support, definition_node, reference_byte)
}

fn rust_node_scope_visible_at(
    support: &dyn RustDefinitionProvider,
    definition_node: Node<'_>,
    reference_byte: usize,
) -> bool {
    let mut current = definition_node.parent();
    while let Some(parent) = current {
        if !support.scope_step() {
            return false;
        }
        if matches!(
            parent.kind(),
            "block" | "function_item" | "impl_item" | "trait_item" | "mod_item"
        ) {
            return parent.start_byte() <= reference_byte && reference_byte < parent.end_byte();
        }
        current = parent.parent();
    }
    true
}

fn rust_root_node<'tree>(
    support: &dyn RustDefinitionProvider,
    mut node: Node<'tree>,
) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if !support.scope_step() {
            return None;
        }
        node = parent;
    }
    Some(node)
}

fn rust_fqn_package(fqn: &str) -> String {
    // Rust identifiers cannot contain a literal `.`, so re-tokenizing the
    // `package.short_name`-shaped fqn with the shared structured splitter and
    // dropping the terminal segment reproduces `rsplit_once('.')`'s package
    // prefix exactly.
    let parts = crate::analyzer::symbol_lookup::parse_symbol_path(Language::Rust, fqn);
    match parts.split_last() {
        Some((_, prefix)) => prefix.join("."),
        None => String::new(),
    }
}

fn rust_local_package_name(file: &ProjectFile) -> String {
    let rel = file.rel_path();
    let mut components: Vec<_> = rel
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_string())
        .collect();

    if components.first().map(|component| component.as_str()) == Some("src") {
        components.remove(0);
    }
    if components.is_empty() {
        return String::new();
    }

    let file_name = components.pop().unwrap_or_default();
    let stem = std::path::Path::new(&file_name)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();

    if stem == "lib" || stem == "main" || stem == "mod" {
        components.join(".")
    } else if rel.starts_with("src") {
        components
            .into_iter()
            .chain(std::iter::once(stem.to_string()))
            .filter(|component| !component.is_empty())
            .collect::<Vec<_>>()
            .join(".")
    } else {
        components.join(".")
    }
}

fn rust_enclosing_impl_type_fqn(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<String> {
    let mut current = node.parent()?;
    loop {
        if !support.scope_step() {
            return None;
        }
        if current.kind() == "impl_item"
            && let Some(type_node) = current.child_by_field_name("type")
        {
            let resolved = rust_resolve_type_node_fqn(
                analyzer,
                token,
                support,
                file,
                source,
                type_node,
                Some(type_node.start_byte()),
            )?;
            let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
                return Some(resolved);
            };
            let mut candidates = support
                .fqn(&resolved)
                .into_iter()
                .filter(|unit| rust_is_type_definition(analyzer, unit));
            let Some(candidate) = candidates.next() else {
                return Some(resolved);
            };
            if candidates.next().is_some() {
                return Some(resolved);
            }
            if support.is_bounded() {
                return Some(candidate.fq_name());
            }
            return canonical_rust_hierarchy_type(rust, token, candidate)
                .map(|unit| unit.fq_name())
                .or(Some(resolved));
        }
        current = current.parent()?;
    }
}

fn rust_named_candidates(
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = support.file_identifier(file, name);
    candidates.extend(support.fqn(name));
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn rust_callable_candidates(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    root: Node<'_>,
    name: &str,
    reference_byte: usize,
) -> Vec<CodeUnit> {
    let mut candidates = rust_named_candidates(support, file, name);
    if support.is_bounded() {
        candidates.retain(|definition| {
            definition.source() == file
                && rust_definition_scope_visible_at(
                    analyzer,
                    support,
                    definition,
                    root,
                    reference_byte,
                )
        });
        if candidates.is_empty()
            && support.observe_cancellation()
            && let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer)
        {
            candidates = rust_imported_export_candidates(
                rust,
                token,
                support,
                file,
                name,
                Some(reference_byte),
            );
        }
        return candidates;
    }
    if candidates.is_empty()
        && let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer)
    {
        candidates =
            rust_imported_export_candidates(rust, token, support, file, name, Some(reference_byte));
    }
    candidates
}

fn rust_callable_name(
    support: &dyn RustDefinitionProvider,
    node: Node<'_>,
    source: &str,
) -> Option<String> {
    if !support.scope_step() {
        return None;
    }
    match node.kind() {
        "identifier" => Some(rust_node_text(node, source).trim().to_string()),
        "scoped_identifier" => node
            .child_by_field_name("name")
            .filter(|_| support.scope_step())
            .map(|name| rust_node_text(name, source).trim().to_string()),
        _ => None,
    }
}

fn rust_simple_identifier_text(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(rust_node_text(node, source).trim().to_string()),
        _ => None,
    }
}

/// Same identifier-kind-gated `r#` stripping as
/// `crate::analyzer::rust::declarations::rust_node_text` (#1128): reference
/// text read here (e.g. `self.r#type`'s `field` node) must agree with the
/// normalized declaration names built on the extraction side.
fn rust_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    crate::analyzer::common::node_ident_text(
        node,
        source,
        false,
        &crate::analyzer::common::RUST_IDENTIFIER_SIGIL,
    )
}

fn rust_imported_export_candidates(
    rust: &crate::analyzer::RustAnalyzer,
    token: QueryToken<'_>,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    reference: &str,
    reference_byte: Option<usize>,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    let targets = if let Some(reference_byte) = reference_byte
        && let Ok(source) = file.read_to_string()
    {
        if lexical_scope::name_shadowed_at(&source, reference, reference_byte) {
            Vec::new()
        } else {
            let binder = lexical_scope::visible_import_binder_at(&source, reference_byte);
            let targets =
                resolve_imported_export_from_binder_forward(rust, token, file, &binder, reference);
            if targets.is_empty() && rust_binder_has_external_binding(&binder, reference) {
                return Vec::new();
            }
            targets
        }
    } else {
        let binder = rust.import_binder_of(token, file);
        let targets =
            resolve_imported_export_from_binder_forward(rust, token, file, &binder, reference);
        if targets.is_empty() && rust_binder_has_external_binding(&binder, reference) {
            return Vec::new();
        }
        targets
    };
    for (target_file, target_name) in targets {
        candidates.extend(support.file_identifier(&target_file, &target_name));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn rust_binder_has_external_binding(binder: &ImportBinder, reference: &str) -> bool {
    binder
        .bindings
        .iter()
        .any(|(local_name, binding)| match binding.kind {
            ImportKind::Named | ImportKind::Namespace if local_name == reference => true,
            ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => false,
            ImportKind::Named | ImportKind::Namespace => false,
        })
}

fn rust_reference_looks_external(reference: &str) -> bool {
    // fqname-M4: peeks at the raw first `::`-split token, including the empty
    // token an absolute-path reference (`::std::foo`) produces; the shared
    // structured splitter (`parse_symbol_path`) filters empty segments, which
    // would shift "which token is first" for that one lead-`::` shape and is
    // not proven equivalent here. Left as a narrow root-token peek rather than
    // a full path decomposition.
    reference
        .split("::")
        .next()
        // `Self` roots a path into the lexically enclosing type's own
        // members, never a crate boundary; treat it like `self`/`crate`/`super`.
        .is_some_and(|root| {
            !matches!(root, "crate" | "self" | "super" | "Self") && root != reference
        })
}

/// Resolve a type-shaped name to a workspace-internal declaration that lives
/// in an *enclosing type/trait/impl/enum* scope of the reference — an
/// associated type, nested type, or the enclosing type itself.
///
/// An explicit `use` binds a bare name in the *module* namespace only; Rust
/// keeps associated types and imported types distinct. A field/enum variant is
/// deliberately not eligible here: bare `PTR::read` cannot use an enclosing
/// `RData::PTR` variant as a path owner, and an explicitly imported but
/// unindexed `PTR` must remain a boundary instead of being stolen by that
/// variant (#1283). Consulting enclosing classes before a boundary still
/// preserves the #1126 safety net for workspace traits and associated types.
fn rust_enclosing_scope_type_fallback(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    name: &str,
    byte: usize,
) -> Option<CodeUnit> {
    resolve_in_enclosing_scopes(analyzer, file, name, byte, CodeUnit::is_class)
}

/// Whether the head of a `::`-qualified unrooted path names a route that is
/// actually in scope here: a visible `use` binding, or a module this file
/// declares outright.
///
/// The enclosing-scope fallback below composes `{enclosing scope prefix} +
/// reference`, so at a crate root file it would spell the crate-relative path
/// that Rust 2018+ requires an explicit `crate::` for -- and would answer with
/// a same-named module the reference never named (`http::Version` inside
/// `src/http.rs` with no `http` dependency), or with a module that exists only
/// inside unproven macro content. Both are boundaries, not definitions. Before
/// crate-aware naming the composed candidate had an empty crate-root prefix and
/// could not match anything, which hid this route by accident; the predicate
/// makes the requirement explicit.
fn rust_qualified_head_is_proven_route(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    rust: &RustAnalyzer,
    file: &ProjectFile,
    source: &str,
    path: &str,
    byte: usize,
) -> bool {
    let Some((head, _)) = path.split_once("::") else {
        // An unqualified name carries no route to prove; the enclosing-scope
        // walk is then the ordinary lexical rule.
        return true;
    };
    let head = head.trim();
    // Rooted and lexical heads name a scope directly rather than going through
    // the crate-root-relative route this gate is about.
    if matches!(head, "crate" | "self" | "super" | "Self") {
        return true;
    }
    if head.is_empty() {
        return false;
    }
    if analyzer
        .declarations(file)
        .into_iter()
        .any(|unit| unit.is_module() && unit.identifier() == head)
    {
        return true;
    }
    lexical_scope::visible_import_binders_at(source, byte)
        .into_iter()
        .any(|binder| {
            !resolve_visible_import_targets_forward(rust, token, file, &binder, head).is_empty()
        })
}

/// True when the focused owner/qualifier resolves to a Rust crate or module that
/// is indexed in this workspace — e.g. a `use forc_pkg::{self as pkg}` alias
/// whose `pkg` root routes through cargo to a workspace crate. Such a qualifier
/// names a namespace, not a single declaration, so the honest outcome is
/// `no_definition`, never a confident "crosses an unindexed boundary" claim
/// (issue #1089: sway forc-pkg exposed as `pkg`).
fn rust_focused_is_workspace_module_namespace(
    rust: &RustAnalyzer,
    token: QueryToken<'_>,
    file: &ProjectFile,
    focused_text: &str,
) -> bool {
    !resolve_module_files(rust, token, file, focused_text).is_empty()
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use crate::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;
    use crate::analyzer::{Language, Range};
    use crate::path_utils::rel_path_string;
    use crate::test_support::AnalyzerFixture;

    fn site_for_last(source: &str, file: &ProjectFile, target: &str) -> ResolvedReferenceSite {
        let start_byte = source.rfind(target).expect("target");
        let end_byte = start_byte + target.len();
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        ResolvedReferenceSite {
            path: rel_path_string(file),
            text: target.to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        }
    }

    fn site_for_expression(
        source: &str,
        file: &ProjectFile,
        expression: &str,
        target: &str,
    ) -> ResolvedReferenceSite {
        let expression_start = source.find(expression).expect("expression");
        let target_start = expression.rfind(target).expect("target in expression");
        let start_byte = expression_start + target_start;
        let end_byte = start_byte + target.len();
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        ResolvedReferenceSite {
            path: rel_path_string(file),
            text: target.to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line,
                end_line: start_line,
            },
            focus_start_byte: start_byte,
            focus_end_byte: end_byte,
        }
    }

    fn site_for_qualified_expression(
        source: &str,
        file: &ProjectFile,
        expression: &str,
        target: &str,
    ) -> ResolvedReferenceSite {
        let start_byte = source.find(expression).expect("expression");
        let end_byte = start_byte + expression.len();
        let focus_start_byte = start_byte + expression.rfind(target).expect("target in expression");
        let focus_end_byte = focus_start_byte + target.len();
        let start_line = source[..start_byte]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        ResolvedReferenceSite {
            path: rel_path_string(file),
            text: expression.to_string(),
            range: Range {
                start_byte,
                end_byte,
                start_line,
                end_line: start_line,
            },
            focus_start_byte,
            focus_end_byte,
        }
    }

    fn assert_opaque_macro_reference_resolves(
        source: &str,
        expression: &str,
        target: &str,
        expected_fqn: &str,
    ) {
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", source)]);
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = lexical_scope::parse_rust_tree(source).expect("Rust tree");
        let site = site_for_qualified_expression(source, &file, expression, target);
        let rust =
            resolve_analyzer::<RustAnalyzer>(fixture.analyzer.analyzer()).expect("Rust analyzer");
        let support = AnalyzerRustDefinitionProvider::new(rust, false);
        let mut cache = RustTypeLookupCache::default();
        let value = resolve_rust(
            fixture.analyzer.analyzer(),
            scope.token(),
            &support,
            &file,
            source,
            Some(&tree),
            &site,
            &mut cache,
            None,
        );

        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            value
                .definitions
                .iter()
                .any(|definition| definition.fq_name() == expected_fqn),
            "{value:#?}"
        );
    }

    #[test]
    fn opaque_macro_keeps_structured_qualified_path_resolution() {
        assert_opaque_macro_reference_resolves(
            "enum State { Ready }\nfn ready(state: &State) -> bool { matches!(state, State::Ready) }\n",
            "State::Ready",
            "Ready",
            "State.Ready",
        );
    }

    #[test]
    fn opaque_macro_keeps_structured_receiver_member_resolution() {
        assert_opaque_macro_reference_resolves(
            "struct DbColumn { r#type: String }\nimpl DbColumn { fn describe(&self) -> String { format!(\"{}\", self.r#type) } }\n",
            "self.r#type",
            "r#type",
            "DbColumn.type",
        );
    }

    #[test]
    fn tt_matcher_keeps_structured_receiver_member_resolution() {
        assert_opaque_macro_reference_resolves(
            "macro_rules! render { ($($tt:tt)*) => {}; }\nstruct AlertType;\nimpl AlertType { fn default_title(&self) {} }\nstruct NodeAlert { alert_type: AlertType }\nfn render_alert(alert: &NodeAlert) { render!(alert.alert_type.default_title()); }\n",
            "alert.alert_type.default_title",
            "default_title",
            "AlertType.default_title",
        );
    }

    #[test]
    fn opaque_macro_keeps_structured_tuple_constructor_resolution() {
        assert_opaque_macro_reference_resolves(
            "fn build() { let _ = vec![Item(1)]; }\nstruct Item(u8);\n",
            "Item",
            "Item",
            "Item",
        );
    }

    #[test]
    fn nested_opaque_macro_keeps_exact_imported_pattern_resolution() {
        assert_opaque_macro_reference_resolves(
            "fn ready(state: State) -> bool { assert!(matches!(state, Ready)); true }\nenum State { Ready }\nuse State::*;\n",
            "Ready",
            "Ready",
            "State.Ready",
        );
    }

    fn member_fixture() -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
        let source = r#"
struct Service;

impl Service {
    fn run(&self) {}
}

fn use_service(service: Service) {
    service.run();
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let call_start = source.rfind("service.run()").expect("member call");
        let start_byte = call_start + "service.".len();
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

    fn wide_deep_member_fixture() -> (
        AnalyzerFixture,
        ProjectFile,
        String,
        Tree,
        ResolvedReferenceSite,
    ) {
        let statements = (0..96)
            .map(|index| format!("    let value{index} = {index};\n    let _ = value{index};\n"))
            .collect::<String>();
        let expression = format!("{}service{}.run()", "(".repeat(24), ")".repeat(24));
        let source = format!(
            "struct Service;\n\nimpl Service {{\n    fn run(&self) {{}}\n}}\n\nfn use_service(service: Service) {{\n{statements}    {expression};\n}}\n"
        );
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let call_start = source.rfind(&expression).expect("member call");
        let start_byte = call_start + expression.rfind("run").expect("member name");
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
    fn bounded_definition_lookup_resolves_typed_receiver_member() {
        let (fixture, file, source, tree, site) = member_fixture();
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, work } = outcome else {
            panic!("member lookup should complete");
        };
        assert!(work.scope_nodes > 0);
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition] if definition.fq_name() == "Service.run"
            ),
            "{value:#?}"
        );
    }

    /// The #1477 member trace is emission-only: recording explains the decision
    /// the resolver made and must never change it. Under a bounded session the
    /// only way it could is by spending scope budget, because a request that
    /// runs out of budget answers `Exceeded` with no definitions. So the pin is
    /// exact: at *every* scope-node budget from one up to the amount the
    /// unrecorded lookup spends, the recorded run must charge the same work and
    /// reach the same answer. A budget-charging owner lookup in the trace fails
    /// this at the budgets near the top of the range, where the extra charge is
    /// what exhausts the budget inside the real member lookup.
    #[test]
    fn recording_a_member_lookup_charges_the_same_bounded_budget() {
        #[derive(Debug, PartialEq, Eq)]
        enum Answer {
            Complete(DefinitionLookupStatus, Vec<String>),
            Exceeded(ReceiverBudgetLimit),
            Cancelled,
        }

        let (fixture, file, source, tree, site) = member_fixture();
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let resolve = |max_scope_nodes: usize| {
            let outcome = resolve_rust_bounded(
                fixture.analyzer.analyzer(),
                scope.token(),
                &file,
                &source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget {
                    max_scope_nodes,
                    ..ReceiverAnalysisBudget::default()
                },
                None,
            );
            let work = outcome.work();
            let answer = match outcome {
                BoundedResolution::Complete { value, .. } => Answer::Complete(
                    value.status,
                    value
                        .definitions
                        .iter()
                        .map(|definition| definition.fq_name())
                        .collect(),
                ),
                BoundedResolution::Exceeded { limit, .. } => Answer::Exceeded(limit),
                BoundedResolution::Cancelled { .. } => Answer::Cancelled,
            };
            (answer, work)
        };

        let spent = {
            let (answer, work) = resolve(ReceiverAnalysisBudget::default().max_scope_nodes);
            assert_eq!(
                answer,
                Answer::Complete(
                    DefinitionLookupStatus::Resolved,
                    vec!["Service.run".to_string()]
                )
            );
            assert!(work.scope_nodes > 0);
            work.scope_nodes
        };

        for max_scope_nodes in 1..=spent {
            let untraced = resolve(max_scope_nodes);
            let traced = {
                let _recorder = trace::TraceSession::install();
                assert!(trace::recording());
                resolve(max_scope_nodes)
            };
            assert_eq!(
                traced, untraced,
                "recording changed the answer or the charged work at a scope budget of {max_scope_nodes}"
            );
        }

        // The range is only a real test if its top end actually resolves the
        // member, which is what makes the budgets just below it the tight ones.
        assert_eq!(
            resolve(spent).0,
            Answer::Complete(
                DefinitionLookupStatus::Resolved,
                vec!["Service.run".to_string()]
            )
        );
    }

    #[test]
    fn issue_1228_bounded_definition_lookup_resolves_imported_bare_call() {
        let source = r#"
use crate::navigation::get_definitions_by_location;

pub fn dispatch() {
    get_definitions_by_location();
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("src/lib.rs", "mod navigation;\nmod service;\n"),
                (
                    "src/navigation.rs",
                    "pub fn get_definitions_by_location() {}\n",
                ),
                ("src/service.rs", &source),
            ],
        );
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/service.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "get_definitions_by_location");

        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("imported call lookup should complete");
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition]
                    if definition.identifier() == "get_definitions_by_location"
                        && rel_path_string(definition.source()) == "src/navigation.rs"
            ),
            "{value:#?}"
        );
    }

    #[test]
    fn issue_2324_crate_facade_module_reexport_resolves_to_physical_dependency() {
        let source =
            "pub use engine::api;\nuse crate::api::target;\n\npub fn call() { target(); }\n";
        let fixture = AnalyzerFixture::new(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"engine\", \"facade\"]\nresolver = \"2\"\n",
            ),
            (
                "engine/Cargo.toml",
                "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            ("engine/src/lib.rs", "pub mod api;\n"),
            ("engine/src/api.rs", "pub fn target() {}\n"),
            (
                "facade/Cargo.toml",
                "[package]\nname = \"facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nengine = { path = \"../engine\" }\n",
            ),
            ("facade/src/lib.rs", source),
        ]);
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "facade/src/lib.rs");
        let tree = lexical_scope::parse_rust_tree(source).expect("Rust tree");
        let site = site_for_last(source, &file, "target");

        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("facade re-export lookup should complete");
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition]
                    if definition.fq_name() == "engine.api.target"
                        && rel_path_string(definition.source()) == "engine/src/api.rs"
            ),
            "{value:#?}"
        );
    }

    #[test]
    fn bounded_definition_lookup_resolves_file_backed_super_import_prefix() {
        let source = r#"
pub struct PlannerItem;

#[cfg(test)]
mod tests {
    use super::*;
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("src/lib.rs", "pub mod domain_events;\n"),
                ("src/domain_events/mod.rs", "pub mod planner;\n"),
                ("src/domain_events/planner.rs", &source),
            ],
        );
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/domain_events/planner.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_expression(&source, &file, "use super::*", "super");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("super import lookup should complete");
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            value.definitions.iter().any(|definition| {
                definition.is_module() && definition.fq_name() == "domain_events.planner"
            }),
            "super must resolve to the enclosing file-backed module: {value:#?}"
        );
        assert!(
            value
                .definitions
                .iter()
                .all(|definition| definition.fq_name() != "domain_events"),
            "super must not skip the enclosing file-backed module: {value:#?}"
        );
    }

    #[test]
    fn full_definition_lookup_resolves_grouped_imported_module_prefix() {
        let source = r#"
use crate::schema::{accounts, assets};

fn consume(_: assets::Table, _: accounts::Table) {}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("src/lib.rs", "pub mod app;\npub mod schema;\n"),
                (
                    "src/schema.rs",
                    "pub mod accounts { pub struct Table; }\npub mod assets { pub struct Table; }\n",
                ),
                ("src/app.rs", &source),
            ],
        );
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/app.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_expression(&source, &file, "assets::Table", "assets");
        let rust =
            resolve_analyzer::<RustAnalyzer>(fixture.analyzer.analyzer()).expect("Rust analyzer");
        let support = AnalyzerRustDefinitionProvider::new(rust, false);
        let mut cache = RustTypeLookupCache::default();
        let value = resolve_rust(
            fixture.analyzer.analyzer(),
            scope.token(),
            &support,
            &file,
            &source,
            Some(&tree),
            &site,
            &mut cache,
            None,
        );

        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            value.definitions.iter().any(|definition| {
                definition.is_module() && definition.fq_name() == "schema.assets"
            }),
            "the imported prefix must resolve to the exact schema module: {value:#?}"
        );
        assert!(
            value
                .definitions
                .iter()
                .all(|definition| definition.fq_name() != "schema.accounts"),
            "the sibling grouped import must stay unrelated: {value:#?}"
        );
    }

    #[test]
    fn full_definition_lookup_resolves_lowercase_alias_to_its_imported_function() {
        let source = r#"
use crate::with_tracing::linear_no_bias as linear;

fn call() {
    linear();
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("src/lib.rs", "pub mod consumer;\npub mod with_tracing;\n"),
                (
                    "src/with_tracing.rs",
                    "pub fn linear_no_bias() {}\npub fn linear() {}\n",
                ),
                ("src/consumer.rs", &source),
            ],
        );
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/consumer.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "linear");
        let rust =
            resolve_analyzer::<RustAnalyzer>(fixture.analyzer.analyzer()).expect("Rust analyzer");
        let support = AnalyzerRustDefinitionProvider::new(rust, false);
        let mut cache = RustTypeLookupCache::default();
        let value = resolve_rust(
            fixture.analyzer.analyzer(),
            scope.token(),
            &support,
            &file,
            &source,
            Some(&tree),
            &site,
            &mut cache,
            None,
        );

        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            value
                .definitions
                .iter()
                .any(|definition| definition.fq_name() == "with_tracing.linear_no_bias"),
            "the alias must resolve to the imported function: {value:#?}"
        );
        assert!(
            value
                .definitions
                .iter()
                .all(|definition| definition.fq_name() != "with_tracing.linear"),
            "the same-named sibling must remain a near-miss: {value:#?}"
        );
    }

    #[test]
    fn full_definition_lookup_resolves_alias_binder_to_its_imported_function() {
        let source = r#"
use crate::with_tracing::linear_no_bias as linear;

fn call() {
    linear();
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("src/lib.rs", "pub mod consumer;\npub mod with_tracing;\n"),
                (
                    "src/with_tracing.rs",
                    "pub fn linear_no_bias() {}\npub fn linear() {}\n",
                ),
                ("src/consumer.rs", &source),
            ],
        );
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/consumer.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_expression(
            &source,
            &file,
            "use crate::with_tracing::linear_no_bias as linear",
            "linear",
        );
        let rust =
            resolve_analyzer::<RustAnalyzer>(fixture.analyzer.analyzer()).expect("Rust analyzer");
        let support = AnalyzerRustDefinitionProvider::new(rust, false);
        let mut cache = RustTypeLookupCache::default();
        let value = resolve_rust(
            fixture.analyzer.analyzer(),
            scope.token(),
            &support,
            &file,
            &source,
            Some(&tree),
            &site,
            &mut cache,
            None,
        );

        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            value
                .definitions
                .iter()
                .any(|definition| definition.fq_name() == "with_tracing.linear_no_bias"),
            "the alias binder must resolve to the imported function: {value:#?}"
        );
        assert!(
            value
                .definitions
                .iter()
                .all(|definition| definition.fq_name() != "with_tracing.linear"),
            "the same-named sibling must remain a near-miss: {value:#?}"
        );
    }

    #[test]
    fn full_definition_lookup_keeps_multi_segment_module_aliases() {
        let source = r#"
use crate::options as package;

fn call() {
    let _ = package::Options;
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("src/lib.rs", "pub mod consumer;\npub mod options;\n"),
                ("src/options.rs", "pub struct Options;\n"),
                ("src/consumer.rs", &source),
            ],
        );
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/consumer.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_expression(&source, &file, "package::Options", "Options");
        let rust =
            resolve_analyzer::<RustAnalyzer>(fixture.analyzer.analyzer()).expect("Rust analyzer");
        let support = AnalyzerRustDefinitionProvider::new(rust, false);
        let mut cache = RustTypeLookupCache::default();
        let value = resolve_rust(
            fixture.analyzer.analyzer(),
            scope.token(),
            &support,
            &file,
            &source,
            Some(&tree),
            &site,
            &mut cache,
            None,
        );

        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            value
                .definitions
                .iter()
                .any(|definition| definition.fq_name() == "options.Options"),
            "the module alias must still route to its nested type: {value:#?}"
        );
    }

    #[test]
    fn grouped_unindexed_import_does_not_fall_back_to_same_named_crate_module() {
        let source = r#"
use crate::schema::{accounts, activities};

mod tests {
    use super::*;

    fn consume() {
        let _ = activities::activity_type_override;
    }
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                (
                    "src/lib.rs",
                    "pub mod activities;\npub mod app;\npub mod schema;\n",
                ),
                ("src/activities.rs", "pub struct Repository;\n"),
                (
                    "src/schema.rs",
                    "diesel::table! { accounts (id) { id -> Text } }\ndiesel::table! { activities (id) { id -> Text, activity_type_override -> Nullable<Text> } }\n",
                ),
                ("src/app.rs", &source),
            ],
        );
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/app.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_expression(
            &source,
            &file,
            "activities::activity_type_override",
            "activities",
        );
        let rust =
            resolve_analyzer::<RustAnalyzer>(fixture.analyzer.analyzer()).expect("Rust analyzer");
        let support = AnalyzerRustDefinitionProvider::new(rust, false);
        let mut cache = RustTypeLookupCache::default();
        let value = resolve_rust(
            fixture.analyzer.analyzer(),
            scope.token(),
            &support,
            &file,
            &source,
            Some(&tree),
            &site,
            &mut cache,
            None,
        );

        assert!(
            matches!(
                value.status,
                DefinitionLookupStatus::NoDefinition
                    | DefinitionLookupStatus::UnresolvableImportBoundary
            ),
            "an unindexed explicit import must remain unresolved: {value:#?}"
        );
        assert!(
            value.definitions.is_empty(),
            "the explicit schema import must block the unrelated crate module: {value:#?}"
        );
    }

    #[test]
    fn grouped_self_import_terminal_resolves_imported_module() {
        let source = "use crate::schema::{self, assets};\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[
                ("src/lib.rs", "pub mod app;\npub mod schema;\n"),
                ("src/schema.rs", "pub mod assets {}\n"),
                ("src/app.rs", source),
            ],
        );
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/app.rs");
        let tree = lexical_scope::parse_rust_tree(source).expect("Rust tree");
        let site = site_for_expression(source, &file, "crate::schema::{self, assets}", "self");
        let rust =
            resolve_analyzer::<RustAnalyzer>(fixture.analyzer.analyzer()).expect("Rust analyzer");
        let support = AnalyzerRustDefinitionProvider::new(rust, false);
        let mut cache = RustTypeLookupCache::default();
        let value = resolve_rust(
            fixture.analyzer.analyzer(),
            scope.token(),
            &support,
            &file,
            source,
            Some(&tree),
            &site,
            &mut cache,
            None,
        );

        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            value
                .definitions
                .iter()
                .any(|definition| definition.is_module() && definition.fq_name() == "schema"),
            "grouped `self` must resolve to the imported module: {value:#?}"
        );
        assert!(
            value
                .definitions
                .iter()
                .all(|definition| definition.fq_name() != "app"),
            "grouped `self` must not resolve to the lexical module: {value:#?}"
        );
    }

    #[test]
    fn bounded_cache_does_not_own_primary_query_syntax() {
        let cache = RustTypeLookupCache::bounded_for_query();

        assert!(
            cache.declarations.is_empty(),
            "bounded query setup must not clone the primary source or syntax tree"
        );
        assert!(!cache.allow_cold_parse);
    }

    #[test]
    fn bounded_factory_lookup_rejects_unrelated_nested_same_name() {
        let source = r#"
struct Hidden;

impl Hidden {
    fn run(&self) {}
}

fn declares_local_factory() {
    fn make() -> Hidden {
        Hidden
    }
    let _ = make();
}

fn outside_scope() {
    make().run();
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", &source)]);
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("lookup should finish without selecting the hidden factory");
        };
        assert_eq!(
            value.status,
            DefinitionLookupStatus::NoDefinition,
            "{value:#?}"
        );
        assert!(value.definitions.is_empty(), "{value:#?}");
    }

    #[test]
    fn bounded_bare_type_does_not_escape_its_file_module() {
        let root = r#"
pub struct Service;

impl Service {
    pub fn run(&self) {}
}
"#;
        let source = r#"
pub fn use_service(service: Service) {
    service.run();
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(
            Language::Rust,
            &[("src/lib.rs", root), ("src/foo.rs", &source)],
        );
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/foo.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("lookup should finish without selecting an out-of-module type");
        };
        assert_eq!(
            value.status,
            DefinitionLookupStatus::NoDefinition,
            "{value:#?}"
        );
        assert!(value.definitions.is_empty(), "{value:#?}");
    }

    #[test]
    fn bounded_bare_type_does_not_escape_an_inline_module() {
        let source = r#"
struct Service;

impl Service {
    fn run(&self) {}
}

mod nested {
    fn use_service(service: Service) {
        service.run();
    }
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", &source)]);
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("lookup should finish without selecting a parent-module type");
        };
        assert_eq!(
            value.status,
            DefinitionLookupStatus::NoDefinition,
            "{value:#?}"
        );
        assert!(value.definitions.is_empty(), "{value:#?}");
    }

    #[test]
    fn bounded_super_type_uses_inline_module_ancestry() {
        let source = r#"
struct Service;

impl Service {
    fn run(&self) {}
}

mod nested {
    fn use_service(service: super::Service) {
        service.run();
    }
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", &source)]);
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("inline-module super type lookup should complete");
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition] if definition.fq_name() == "Service.run"
            ),
            "{value:#?}"
        );
    }

    #[test]
    fn bounded_self_type_uses_inline_module_ancestry() {
        let source = r#"
mod nested {
    struct Service;

    impl Service {
        fn run(&self) {}
    }

    fn use_service(service: self::Service) {
        service.run();
    }
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", &source)]);
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("inline-module self type lookup should complete");
        };
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition] if definition.fq_name() == "nested.Service.run"
            ),
            "{value:#?}"
        );
    }

    #[test]
    fn bounded_crate_type_does_not_fall_back_to_file_module() {
        let source = r#"
struct Service;

impl Service {
    fn run(&self) {}
}

fn use_service(service: crate::Service) {
    service.run();
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/foo.rs", &source)]);
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/foo.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );

        let BoundedResolution::Complete { value, .. } = outcome else {
            panic!("explicit crate type lookup should complete");
        };
        assert_eq!(
            value.status,
            DefinitionLookupStatus::NoDefinition,
            "{value:#?}"
        );
        assert!(value.definitions.is_empty(), "{value:#?}");
    }

    #[test]
    fn bounded_enum_variant_constructions_resolve_the_exact_owner_member() {
        let source = r#"
enum State {
    Unit,
    Tuple(i32),
    Struct { value: i32 },
}

impl State {
    fn run(&self) {}
}

mod unrelated {
    pub enum State {
        Unit,
        Tuple(i32),
        Struct { value: i32 },
    }

    impl State {
        pub fn run(&self) {}
    }
}

fn use_state() {
    State::Unit.run();
    State::Tuple(1).run();
    (State::Struct { value: 1 }).run();
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", &source)]);
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");

        for expression in [
            "State::Unit.run()",
            "State::Tuple(1).run()",
            "(State::Struct { value: 1 }).run()",
        ] {
            let site = site_for_expression(&source, &file, expression, "run");
            let outcome = resolve_rust_bounded(
                fixture.analyzer.analyzer(),
                scope.token(),
                &file,
                &source,
                Some(&tree),
                &site,
                ReceiverAnalysisBudget::default(),
                None,
            );
            let BoundedResolution::Complete { value, .. } = outcome else {
                panic!("{expression} should complete: {outcome:#?}");
            };
            assert_eq!(
                value.status,
                DefinitionLookupStatus::Resolved,
                "{expression}: {value:#?}"
            );
            assert!(
                matches!(
                    value.definitions.as_slice(),
                    [definition] if definition.fq_name() == "State.run"
                ),
                "{expression}: {value:#?}"
            );
        }
    }

    #[test]
    fn bounded_enum_variant_construction_honors_budget_and_cancellation() {
        let source = r#"
enum State {
    Tuple(i32),
}

impl State {
    fn run(&self) {}
}

fn use_state() {
    State::Tuple(1).run();
}
"#
        .to_string();
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", &source)]);
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_expression(&source, &file, "State::Tuple(1).run()", "run");

        let tiny = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::tiny(),
            None,
        );
        assert!(
            matches!(tiny, BoundedResolution::Exceeded { .. }),
            "{tiny:#?}"
        );

        let cancellation = CancellationToken::cancel_after_checks_for_test(4);
        let cancelled = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );
        assert!(
            matches!(cancelled, BoundedResolution::Cancelled { .. }),
            "{cancelled:#?}"
        );
    }

    #[test]
    fn bounded_receiver_typing_is_stack_safe_for_deep_reference_chains() {
        const DEPTH: usize = 4_096;
        let receiver = format!("{}Service {{}}", "&".repeat(DEPTH));
        let source = format!(
            "struct Service;\n\nimpl Service {{\n    fn run(&self) {{}}\n}}\n\nfn use_service() {{\n    ({receiver}).run();\n}}\n"
        );
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", &source)]);
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = lexical_scope::parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 100_000,
            ..ReceiverAnalysisBudget::default()
        };
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            budget,
            None,
        );

        let BoundedResolution::Complete { value, work } = outcome else {
            panic!("deep reference chain should complete without exhausting the process stack");
        };
        assert!(work.scope_nodes > DEPTH, "{work:#?}");
        assert_eq!(value.status, DefinitionLookupStatus::Resolved, "{value:#?}");
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition] if definition.fq_name() == "Service.run"
            ),
            "{value:#?}"
        );
    }

    #[test]
    fn bounded_definition_lookup_stops_at_scope_budget() {
        let (fixture, file, source, tree, site) = wide_deep_member_fixture();
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let budget = ReceiverAnalysisBudget::tiny();
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
            &file,
            &source,
            Some(&tree),
            &site,
            budget,
            None,
        );

        assert!(matches!(
            outcome,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));
    }

    #[test]
    fn bounded_definition_lookup_stops_on_cancellation() {
        let (fixture, file, source, tree, site) = wide_deep_member_fixture();
        let scope = crate::analyzer::AnalyzerQueryScope::new(fixture.analyzer.analyzer());
        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
            scope.token(),
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
