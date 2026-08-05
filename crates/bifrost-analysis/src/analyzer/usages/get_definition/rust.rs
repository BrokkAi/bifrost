use super::*;
use crate::analyzer::rust::field_roles::{
    RustFieldNameRole, RustStructFieldContainer, classify_rust_field_name,
};
use crate::analyzer::rust::lexical_scope;
use crate::analyzer::rust::rust_focused_use_path;
use crate::analyzer::rust::{
    resolve_rust_import_package_scoped, resolve_rust_module_segments_with_crate,
    rust_crate_root_package, rust_package_name,
};
use crate::analyzer::usages::rust_graph::{
    RustDefinitionProvider, resolve_rust_path_fqn, rust_smallest_named_node_covering,
};
use crate::analyzer::{RustReferenceContext, SignatureMetadata, StructuredTypeIdentity};
use crate::hash::{HashMap, HashSet};
use std::cell::RefCell;

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

    fn cancellable_full(rust: &'a RustAnalyzer, session: &'a ResolutionSession) -> Self {
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

    fn forward_reference_context(
        &self,
        rust: &RustAnalyzer,
        file: &ProjectFile,
    ) -> Option<std::sync::Arc<RustReferenceContext>> {
        match self.session {
            Some(session) => rust.forward_reference_context_of_with_progress(file, &|| {
                session.observe_cancellation()
            }),
            None => Some(rust.forward_reference_context_of(file)),
        }
    }

    fn ranges(&self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Vec<Range> {
        match self.session {
            Some(session) => {
                session.query_limited_rows(|limit| self.rust.ranges_limited(unit, limit))
            }
            None => analyzer.ranges(unit),
        }
    }

    fn signature_metadata(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Vec<SignatureMetadata> {
        match self.session {
            Some(session) => session
                .query_limited_rows(|limit| self.rust.signature_metadata_limited(unit, limit)),
            None => analyzer.signature_metadata(unit),
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
            None => self.rust.definitions(fqn).collect(),
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
                .declarations(file)
                .into_iter()
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
                .definitions(&format!("{owner_fqn}.{name}"))
                .collect(),
        };
        sort_units(&mut units);
        units.dedup();
        units
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_rust(
    analyzer: &dyn IAnalyzer,
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
        analyzer, support, file, source, tree, site, cache, operation,
    );
    if !support.observe_cancellation() {
        return outcome;
    }
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return outcome;
    };
    let Some(scope) = rust_cargo_reference_scope(rust, file, source, tree, site) else {
        return outcome;
    };
    let direct_crate_reference =
        tree.and_then(|tree| rust_direct_crate_root_reference(source, tree, site));
    rust_scope_forward_candidates_to_cargo_target(
        rust,
        support,
        file,
        scope,
        direct_crate_reference,
        outcome,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_rust_cancellable(
    analyzer: &dyn IAnalyzer,
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
        analyzer, &support, file, source, tree, site, cache, operation,
    );
    session.finish(outcome)
}

pub(crate) fn resolve_rust_bounded(
    analyzer: &dyn IAnalyzer,
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
    let outcome =
        resolve_rust_bounded_in_session(analyzer, &support, file, source, tree, site, &mut cache);
    session.finish(outcome)
}

fn resolve_rust_bounded_in_session(
    analyzer: &dyn IAnalyzer,
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

    if let Some(outcome) =
        rust_rooted_use_prefix_outcome(analyzer, support.rust, support, file, source, tree, site)
    {
        return outcome;
    }

    if let Some(outcome) = resolve_rust_field(analyzer, support, file, source, tree, site, cache) {
        return outcome;
    }

    if node.kind() == "self" && focused_rust_field_receiver(node, site.focus_start_byte) {
        return no_definition(
            "local_receiver",
            "the focused Rust receiver is a local expression, which is not indexed",
        );
    }

    if node.kind() == "self"
        && let Some(owner) = rust_enclosing_impl_type_fqn(analyzer, support, file, source, node)
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
            rust_bounded_scoped_callable_candidates(analyzer, support, file, source, function)
        } else {
            rust_callable_name(support, function, source)
                .map(|name| {
                    rust_callable_candidates(
                        analyzer,
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
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> Option<RustCargoReferenceScope> {
    let tree = tree?;
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    if let Some(focused_use) = rust_focused_use_path(focused, source)
        && let Some(targets) = rust_import_path_target_files(rust, file, &focused_use.segments)
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
            let mut targets = rust
                .resolve_visible_import_targets_forward(file, &binder, root)
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
    file: &ProjectFile,
    segments: &[String],
) -> Option<Vec<ProjectFile>> {
    for prefix_len in (1..=segments.len()).rev() {
        let module_specifier = segments[..prefix_len].join("::");
        let targets = rust.resolve_module_files(file, &module_specifier);
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
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    scope: RustCargoReferenceScope,
    direct_crate_reference: Option<(String, RustBareReferenceRole)>,
    mut outcome: DefinitionLookupOutcome,
) -> DefinitionLookupOutcome {
    if let Some((name, role)) = direct_crate_reference.as_ref() {
        let roots = rust.cargo_target_roots_for_file(file);
        let mut candidates = rust
            .usage_crate_export_targets(file, name)
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
    // the CodeUnit signature. Same-file declarations can nevertheless share
    // its analyzer FQN (for example impls for `T` and `&[T]`). Preserve every
    // exact outcome from those files while still admitting other-file replicas
    // for the Cargo target router to select between independent roots.
    let exact_lexical_self_files = if matches!(&scope, RustCargoReferenceScope::LexicalSelf) {
        outcome
            .definitions
            .iter()
            .map(|definition| definition.source().clone())
            .collect::<HashSet<_>>()
    } else {
        HashSet::default()
    };
    let mut expanded = outcome.definitions.clone();
    for definition in &outcome.definitions {
        expanded.extend(
            support
                .fqn(&definition.fq_name())
                .into_iter()
                .filter(|candidate| {
                    !exact_lexical_self_files.contains(candidate.source())
                        && rust_same_declaration_namespace(rust, definition, candidate)
                }),
        );
        expanded.extend(
            support
                .file_identifier(file, definition.identifier())
                .into_iter()
                .filter(|candidate| {
                    !exact_lexical_self_files.contains(candidate.source())
                        && candidate.fq_name() == definition.fq_name()
                        && rust_same_declaration_namespace(rust, definition, candidate)
                }),
        );
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
            rust_rooted_use_prefix_outcome(analyzer, rust, support, file, source, tree, site)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_struct_field_name_outcome(analyzer, support, file, source, tree, site)
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
            rust_exact_reference_role_outcome(analyzer, support, file, source, tree, site)
    {
        return outcome;
    }
    // Preserve the exact focused segment of structured Rust paths before
    // whole-expression member handling can collapse an owner focus such as
    // `EventInfo` in `vec![EventInfo::default()]` to the terminal method.
    if let Some(tree) = tree
        && let Some(outcome) = rust_focused_token_tree_prefix_outcome(
            analyzer, rust, support, file, source, tree, site,
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
        && (lexical_scope::is_pattern_binding_identifier(node)
            || lexical_scope::name_shadowed_in_tree(
                tree.root_node(),
                source,
                reference,
                site.focus_start_byte,
            ))
    {
        return no_definition(
            "local_binding",
            format!("`{reference}` is a local Rust binding, which is not indexed"),
        );
    }
    if let Some(tree) = tree
        && let Some(operation) = operation
        && let Some(outcome) = rust_qualified_associated_type_navigation_outcome(
            rust, analyzer, support, file, source, tree, site, operation,
        )
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) = rust_impl_associated_type_declaration_outcome(
            rust, support, file, source, tree, site, operation,
        )
    {
        return outcome;
    }
    if reference.contains('.')
        && let Some(tree) = tree
        && let Some(outcome) =
            resolve_rust_field(analyzer, support, file, source, tree, site, cache)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(candidates) =
            rust_self_scoped_associated_type_candidates(analyzer, file, source, tree, site)
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
        && let Some(self_type) = rust_enclosing_impl_type_fqn(analyzer, support, file, source, node)
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
                    let Some(refs) = support.forward_reference_context(rust, file) else {
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
            analyzer, rust, support, file, source, tree, site,
        )
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_focused_use_path_outcome(analyzer, rust, support, file, source, tree, site)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_focused_scoped_prefix_outcome(analyzer, rust, support, file, source, tree, site)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(candidates) = rust_focused_terminal_scoped_type_candidates(
            analyzer, rust, support, file, source, tree, site,
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
        let Some(refs) = support.forward_reference_context(rust, file) else {
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
                analyzer, rust, support, file, source, tree, site, name, role,
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
                    "local_binding",
                    format!("`{reference}` is a local Rust item, which is not indexed"),
                );
            }
            match rust_visible_import_resolution(
                rust,
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
                        .flatten();
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
                    );
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
                    ) {
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
                    // Only an unbound name may fall back to a lexically enclosing
                    // declaration. An explicit import is authoritative even when a
                    // same-named type exists in the surrounding file/module.
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
                    lexical.map_or_else(
                        || {
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
                            trace_selected_units(&module, PrecedenceTier::PackageOrModule);
                            module
                        },
                        |unit| {
                            trace_selected_units(
                                std::slice::from_ref(&unit),
                                PrecedenceTier::OwnMember,
                            );
                            vec![unit]
                        },
                    )
                }
            }
        } else {
            let Some(refs) = support.forward_reference_context(rust, file) else {
                return no_definition("cancelled", "Rust definition resolution was cancelled");
            };
            refs.resolve_bare(reference)
                .map(|fqn| support.fqn(fqn))
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
        if let Some(unit) =
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
                "declaration_site",
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
                    "local_binding",
                    "Rust shorthand struct-pattern fields introduce local bindings",
                ));
            }
            let field_name = &source[name.byte_range()];
            let Some(owner) = rust_resolve_type_node_fqn(
                analyzer,
                support,
                file,
                source,
                owner_type,
                Some(owner_type.start_byte()),
            )
            .or_else(|| {
                rust_resolve_struct_pattern_variant_owner(
                    analyzer, support, file, source, owner_type, field_name,
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
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    owner_type: Node<'_>,
    field_name: &str,
) -> Option<String> {
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
    let type_ref = rust_type_ref(support, owner_type, source)?;
    let refs = support.forward_reference_context(rust, file)?;
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
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
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
            "local_lifetime",
            "Rust lifetime parameters are lexical bindings and are not indexed definitions",
        ));
    }
    if focused.kind() == "self" && focused_rust_field_receiver(focused, site.focus_start_byte) {
        return Some(no_definition(
            "local_receiver",
            "the focused Rust receiver is a local expression, which is not indexed",
        ));
    }

    let focused_name = rust_node_text(focused, source).trim();
    if focused.kind() == "type_identifier"
        && rust_type_parameter_visible_from(focused, source, focused_name)
    {
        return Some(no_definition(
            "local_type_parameter",
            format!("`{focused_name}` is a lexical Rust type parameter, which is not indexed"),
        ));
    }

    if let Some(type_binding) = rust_enclosing_type_binding_name(focused) {
        return Some(rust_type_binding_name_outcome(
            analyzer,
            support,
            file,
            source,
            type_binding,
        ));
    }

    if let Some(macro_invocation) = rust_enclosing_macro_name(focused) {
        return rust_macro_name_outcome(
            analyzer,
            support,
            file,
            source,
            tree,
            site,
            macro_invocation,
            focused,
        );
    }

    if matches!(focused.kind(), "identifier" | "shorthand_field_identifier")
        && (lexical_scope::is_pattern_binding_identifier(focused)
            || (lexical_scope::name_shadowed_in_tree(
                tree.root_node(),
                source,
                focused_name,
                site.focus_start_byte,
            ) && (rust_identifier_is_explicit_receiver(focused)
                || !site.text.contains(['.', ':']))))
    {
        return Some(no_definition(
            "local_binding",
            format!("`{focused_name}` is a local Rust binding, which is not indexed"),
        ));
    }
    None
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
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
    let refs = support.forward_reference_context(rust, file)?;
    let name_node = macro_name.child_by_field_name("name").unwrap_or(macro_name);
    let name = rust_node_text(name_node, source).trim();
    let candidates = if let Some(path) = macro_name.child_by_field_name("path") {
        let path = rust_node_text(path, source).trim();
        refs.resolve_scoped(path, name)
            .into_iter()
            .flat_map(|fqn| support.fqn(&fqn))
            .filter(CodeUnit::is_macro)
            .collect()
    } else {
        match rust_visible_import_resolution(
            rust,
            support,
            file,
            source,
            site.focus_start_byte,
            name,
            RustBareReferenceRole::Macro,
        ) {
            RustVisibleImportResolution::Resolved(candidates)
            | RustVisibleImportResolution::GlobResolved(candidates) => candidates,
            RustVisibleImportResolution::BoundButUnindexed => {
                // An unresolvable macro import must not blind the reference to a
                // workspace-declared macro of the same name in an enclosing
                // scope: macros keep their own namespace, so consult it before
                // claiming an unindexed boundary (#1158, the macro-namespace
                // analogue of the type-namespace fallback its siblings run).
                if let Some(unit) = resolve_in_enclosing_scopes(
                    analyzer,
                    file,
                    name,
                    site.focus_start_byte,
                    CodeUnit::is_macro,
                ) {
                    return Some(candidates_outcome(vec![unit]));
                }
                // gated upstream: the macro-namespace enclosing-scope fallback
                // above is the workspace check.
                return Some(boundary_unchecked(format!(
                    "Rust macro `{name}` is imported across a crate/module boundary that is not indexed"
                )));
            }
            RustVisibleImportResolution::GlobBoundButUnindexed => {
                return Some(boundary_unchecked(format!(
                    "Rust macro `{name}` is inherited from an unindexed import"
                )));
            }
            RustVisibleImportResolution::Unbound => rust_current_module_candidates(
                analyzer,
                rust,
                support,
                file,
                tree.root_node(),
                site.focus_start_byte,
                site.focus_end_byte,
                name,
                RustBareReferenceRole::Macro,
            ),
        }
    };
    Some(if candidates.is_empty() {
        no_definition(
            "unindexed_macro",
            format!("Rust macro `{name}` did not resolve to an indexed macro definition"),
        )
    } else {
        candidates_outcome(candidates)
    })
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
                            file,
                            source,
                            scope_start,
                            &binding.module_specifier,
                        ) {
                            expected_fqns.insert(format!("{package}.{imported}"));
                            if role == RustBareReferenceRole::Value {
                                expected_fqns.insert(format!("{package}._module_.{imported}"));
                            }
                        }
                    }
                    ImportKind::Namespace => {
                        if let Some(fqn) = resolve_rust_import_package_scoped(
                            rust,
                            file,
                            source,
                            scope_start,
                            &binding.module_specifier,
                        ) {
                            expected_fqns.insert(fqn);
                        }
                    }
                    _ => {}
                }
            }
        }
        let mut targets = rust_forward_import_targets(rust, file, &binder, reference);
        let mut scoped_glob_resolution = None;
        let mut routed_glob_candidates = Vec::new();
        if !explicitly_bound {
            scoped_glob_resolution = rust_scoped_glob_forward_import_candidates(
                rust,
                support,
                file,
                source,
                scope_start,
                &binder,
                reference,
                role,
            );
            routed_glob_candidates =
                rust_glob_forward_export_candidates(rust, file, &binder, reference, role);
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
        for (target_file, target_name) in targets {
            let resolved =
                rust_import_target_candidates(rust, support, target_file, target_name, role);
            candidates.extend(resolved.candidates);
            crossed_unindexed_explicit_binding |= resolved.crossed_unindexed_explicit_binding;
        }
        if !explicitly_bound {
            candidates.retain(|candidate| {
                rust_glob_import_exposes_candidate(
                    rust,
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
            } else if candidates.is_empty() {
                candidates = expected_fqns
                    .iter()
                    .flat_map(|fqn| support.fqn(fqn))
                    .filter(|candidate| rust_role_accepts_imported(rust, role, candidate))
                    .collect();
            }
        }
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
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
    role: RustBareReferenceRole,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
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
        let module_files = rust.resolve_module_files(file, &binding.module_specifier);
        let Some(fqn) = rust.forward_export_fqn_from_files(&module_files, reference) else {
            continue;
        };
        let definitions = rust.get_definitions(&fqn);
        candidates.extend(
            definitions
                .into_iter()
                .filter(|candidate| rust_role_accepts_imported(rust, role, candidate)),
        );
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

#[allow(clippy::too_many_arguments)]
fn rust_glob_import_exposes_candidate(
    rust: &RustAnalyzer,
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
    let Some(refs) = support.forward_reference_context(rust, file) else {
        return false;
    };
    binder
        .bindings
        .values()
        .filter(|binding| binding.kind == ImportKind::Glob)
        .any(|binding| {
            let scoped_package = resolve_rust_import_package_scoped(
                rust,
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
                module_files = rust.resolve_module_files(file, &binding.module_specifier);
            }
            rust.forward_export_fqn_from_files(&module_files, reference)
                .is_some_and(|export_fqn| export_fqn == candidate.fq_name())
        })
}

#[allow(clippy::too_many_arguments)]
fn rust_scoped_glob_forward_import_candidates(
    rust: &RustAnalyzer,
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
        let Some(package) = resolve_rust_import_package_scoped(
            rust,
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
                    .reference_context_of(&target_file)
                    .resolve_bare(reference)
                    .into_iter()
                    .flat_map(|fqn| support.fqn(fqn))
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

struct RustImportTargetCandidates {
    candidates: Vec<CodeUnit>,
    crossed_unindexed_explicit_binding: bool,
}

fn rust_import_target_candidates(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    target_file: ProjectFile,
    target_name: String,
    role: RustBareReferenceRole,
) -> RustImportTargetCandidates {
    let mut candidates = Vec::new();
    let mut crossed_explicit_binding = false;
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
        let binder = lexical_scope::visible_import_binder_at(&source, 0);
        if rust_binder_has_external_binding(&binder, &name) {
            crossed_explicit_binding = true;
            if let Some(fqn) = rust.reference_context_of(&file).resolve_bare(&name) {
                candidates.extend(
                    support
                        .fqn(fqn)
                        .into_iter()
                        .filter(|candidate| rust_role_accepts_imported(rust, role, candidate)),
                );
            }
            continue;
        }
        pending.extend(rust_forward_import_targets(rust, &file, &binder, &name));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    RustImportTargetCandidates {
        crossed_unindexed_explicit_binding: crossed_explicit_binding && candidates.is_empty(),
        candidates,
    }
}

fn rust_forward_import_targets(
    rust: &RustAnalyzer,
    file: &ProjectFile,
    binder: &ImportBinder,
    reference: &str,
) -> Vec<(ProjectFile, String)> {
    rust.resolve_visible_import_targets_forward(file, binder, reference)
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
    let reference_module = enclosing.iter().find(|unit| unit.is_module());
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
            let mut parent = analyzer.parent_of(candidate);
            let mut candidate_module = None;
            while let Some(unit) = parent {
                if unit.is_module() {
                    candidate_module = Some(unit);
                    break;
                }
                parent = analyzer.parent_of(&unit);
            }
            if reference_module.is_some() {
                candidate_module.as_ref() == reference_module
            } else {
                analyzer
                    .ranges(candidate)
                    .first()
                    .map(|range| {
                        rust_declaration_syntax_module_range(root, range, candidate.is_module())
                            == reference_syntax_module
                    })
                    .unwrap_or(reference_syntax_module.is_none())
            }
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
            (candidate.is_class() && rust.has_rust_value_constructor(candidate))
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
    (candidate.is_class() && rust.has_rust_value_constructor(candidate))
        || (candidate.is_function() && rust_declaration_is_free_function(rust, candidate))
        || (candidate.is_field()
            && (rust_declaration_is_value_item(rust, candidate)
                || rust_declaration_is_enum_variant(rust, candidate)))
}

fn rust_callable_namespace_candidate(rust: &RustAnalyzer, candidate: &CodeUnit) -> bool {
    candidate.is_class()
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
    rust_declaration_matches(rust, candidate, |node| node.kind() == "enum_variant")
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

fn rust_impl_associated_type_declaration_outcome(
    rust: &RustAnalyzer,
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
        let candidate =
            rust.rust_associated_type_declaration_for_exact_node(file, type_item, associated_type)?;
        return Some(candidates_outcome(vec![candidate]));
    }
    let trait_type = impl_item.child_by_field_name("trait")?;
    let trait_fqn = rust_resolve_type_node_fqn(
        rust,
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
        support,
        file,
        source,
        owner_type,
        Some(owner_type.start_byte()),
    )?;
    let trait_fqn = rust_resolve_type_node_fqn(
        analyzer,
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
    let associated_type = resolve_in_enclosing_scopes(
        analyzer,
        file,
        name,
        site.focus_start_byte,
        CodeUnit::is_field,
    )?;
    Some(vec![associated_type])
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
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    member: &str,
    role: RustBareReferenceRole,
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
    let owners = rust_current_module_candidates(
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
    let mut candidates = owners
        .into_iter()
        .flat_map(|owner| support.members_for_owner_name(&owner.fq_name(), member))
        .filter(|candidate| rust_role_accepts_scoped(rust, role, candidate))
        .collect::<Vec<_>>();
    candidates.extend(rust_cargo_root_member_candidates(
        rust, support, file, source, path, member,
    ));
    candidates.retain(|candidate| rust_role_accepts_scoped(rust, role, candidate));
    sort_units(&mut candidates);
    candidates.dedup();
    (!candidates.is_empty()).then_some(candidates)
}

#[allow(clippy::too_many_arguments)]
fn rust_focused_terminal_scoped_type_candidates(
    analyzer: &dyn IAnalyzer,
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
    let refs = support.forward_reference_context(rust, file)?;
    let owners =
        rust_scoped_owner_candidates_from_path(analyzer, rust, support, file, source, path, &refs)?;
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

fn rust_scoped_owner_candidates_from_path(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    path: Node<'_>,
    refs: &RustReferenceContext,
) -> Option<Vec<CodeUnit>> {
    let owner_text = rust_node_text(path, source).trim();
    if owner_text.is_empty() {
        return None;
    }

    let mut candidates = Vec::new();
    if owner_text == "Self" {
        if let Some(owner) = rust_enclosing_impl_type_fqn(analyzer, support, file, source, path) {
            candidates.extend(support.fqn(&owner));
        }
    } else if let Some(fqn) = rust_scoped_prefix_fqn(rust, file, refs, path, source) {
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
            .then(|| rust.resolve_module_package(file, cargo_route))
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
        if let Some(fqn) = rust.resolve_module_package(file, owner_text) {
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

fn rust_rooted_use_prefix_outcome(
    analyzer: &dyn IAnalyzer,
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
    let fqn =
        resolve_rust_import_package_scoped(rust, file, source, focused.start_byte(), focused_text)?;
    let mut candidates = support
        .fqn(&fqn)
        .into_iter()
        .filter(CodeUnit::is_module)
        .collect::<Vec<_>>();
    sort_units(&mut candidates);
    candidates.dedup();
    (!candidates.is_empty()).then(|| candidates_outcome(candidates))
}

#[allow(clippy::too_many_arguments)]
fn rust_focused_use_path_outcome(
    analyzer: &dyn IAnalyzer,
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
    let role = if rust_focused_nonterminal_prefix(focused).is_some() {
        RustFocusedPathRole::Owner
    } else {
        RustFocusedPathRole::Declaration
    };
    let refs = support.forward_reference_context(rust, file)?;
    let rooted_segments =
        crate::analyzer::symbol_lookup::parse_symbol_path(Language::Rust, &focused_path.full_path);
    let resolved_fqn = if matches!(
        rooted_segments.first().map(String::as_str),
        Some("self" | "super")
    ) {
        resolve_rust_import_package_scoped(
            rust,
            file,
            source,
            focused.start_byte(),
            &focused_path.full_path,
        )
    } else {
        crate::analyzer::usages::rust_graph::resolve_rust_path_fqn(
            rust,
            &refs,
            file,
            &focused_path.full_path,
        )
    };
    Some(rust_focused_prefix_resolution_outcome(
        analyzer,
        rust,
        support,
        file,
        source,
        site,
        &refs,
        focused_path.root,
        focused_text,
        &focused_path.full_path,
        role,
        resolved_fqn.as_deref(),
        false,
    ))
}

#[allow(clippy::too_many_arguments)]
fn rust_focused_terminal_scoped_declaration_outcome(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
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
    let owner_root = rust_scoped_path_root(owner_path);
    let owner_root_name = rust_node_text(owner_root, source).trim();
    let owner_availability = rust_owner_root_availability(
        analyzer,
        rust,
        support,
        file,
        source,
        site,
        owner_root,
        owner_root_name,
    );

    let refs = support.forward_reference_context(rust, file)?;
    let role = rust_bare_reference_role(tree, site, source).unwrap_or(RustBareReferenceRole::Value);
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
            analyzer, rust, support, file, source, tree, site, &member, role,
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

    let refs = support.forward_reference_context(rust, file)?;
    let uses_module_package_fallback =
        rust_scoped_prefix_uses_module_package_fallback(rust, file, &refs, prefix, source);
    let resolved_fqn = rust_scoped_prefix_fqn(rust, file, &refs, prefix, source);
    let root = rust_scoped_path_root(prefix);
    Some(rust_focused_prefix_resolution_outcome(
        analyzer,
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
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
) -> Option<DefinitionLookupOutcome> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
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
    let refs = support.forward_reference_context(rust, file)?;
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
                    && !rust
                        .resolve_module_files(file, &binding.module_specifier)
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
    file: &ProjectFile,
    refs: &RustReferenceContext,
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
        && rust
            .resolve_module_package(file, rust_node_text(prefix, source).trim())
            .is_some()
}

#[allow(clippy::too_many_arguments)]
fn rust_focused_prefix_resolution_outcome(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    refs: &RustReferenceContext,
    root: Node<'_>,
    focused_text: &str,
    focused_path: &str,
    role: RustFocusedPathRole,
    resolved_fqn: Option<&str>,
    uses_module_package_fallback: bool,
) -> DefinitionLookupOutcome {
    let root_name = rust_node_text(root, source).trim();
    let root_availability = (role == RustFocusedPathRole::Owner).then(|| {
        rust_owner_root_availability(analyzer, rust, support, file, source, site, root, root_name)
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
                if let Some(unit) = rust_enclosing_scope_type_fallback(
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
                    || rust_focused_is_workspace_module_namespace(rust, file, focused_text),
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
                    || rust_focused_is_workspace_module_namespace(rust, file, focused_text),
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
            .then(|| rust.resolve_module_package(file, cargo_route))
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
            rust.resolve_module_package(file, focused_path)
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
        || rust_extern_prelude_root(rust, support, file, refs, root, root_name)
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
        if let Some(unit) =
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
                    && rust_focused_is_workspace_module_namespace(rust, file, focused_text)
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
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    refs: &RustReferenceContext,
    root: Node<'_>,
    root_name: &str,
) -> bool {
    matches!(root.kind(), "identifier" | "type_identifier")
        && refs.resolve_bare(root_name).is_none_or(|fqn| {
            !support.fqn(fqn).into_iter().any(|candidate| {
                rust_role_accepts_imported(rust, RustBareReferenceRole::Owner, &candidate)
            })
        })
        && rust.resolve_module_files(file, root_name).is_empty()
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
    file: &ProjectFile,
    refs: &RustReferenceContext,
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
                rust.resolve_module_package(file, rust_node_text(prefix, source).trim())
            })
        }
        "identifier" | "type_identifier" => {
            let name = rust_node_text(prefix, source).trim();
            refs.resolve_bare(name)
                .map(str::to_string)
                .or_else(|| rust.resolve_module_package(file, name))
        }
        "crate" | "self" | "super" => {
            rust.resolve_module_package(file, rust_node_text(prefix, source).trim())
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

fn resolve_rust_field(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    cache: &mut RustTypeLookupCache,
) -> Option<DefinitionLookupOutcome> {
    if !support.is_bounded()
        && let Some(outcome) = rust_token_tree_dotted_member_outcome(
            analyzer, support, file, source, tree, site, cache,
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
                    "local_receiver",
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
        let candidates =
            rust_member_candidates(support.members_for_owner_name(&owner, member), member_kind);
        if candidates.is_empty()
            && !support.is_bounded()
            && member_kind == RustMemberKind::Function
            && let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer)
        {
            let refs = support.forward_reference_context(rust, file)?;
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
    let mut candidates =
        rust_member_candidates(support.fqn(&format!("{owner}.{member}")), member_kind);
    if candidates.is_empty() && member_kind == RustMemberKind::Function {
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
        let refs = support.forward_reference_context(rust, file)?;
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

fn rust_member_candidates(candidates: Vec<CodeUnit>, kind: RustMemberKind) -> Vec<CodeUnit> {
    candidates
        .into_iter()
        .filter(|unit| match kind {
            RustMemberKind::Field => unit.is_field(),
            RustMemberKind::Function => unit.is_function(),
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn rust_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
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
    support: &dyn RustDefinitionProvider,
    field: &CodeUnit,
    cache: &mut RustTypeLookupCache,
) -> Vec<CodeUnit> {
    let Some(fqn) = rust_field_code_unit_type_fqn(
        analyzer,
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
                            analyzer, support, file, source, expression,
                        ));
                    }
                    "identifier" => {
                        let binding = rust_binding_type_fqn(
                            analyzer,
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
                                support,
                                syntax,
                                function,
                                expression.start_byte(),
                            );
                            values.push(rust_callable_return_type_fqn(
                                analyzer, support, syntax, candidates, mode, cache,
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
                    rust_field_type_fqn(analyzer, support, syntax, &owner, member, mode, cache)
                }));
            }
            Frame::FinishMethod { method, mode } => {
                let owner = values.pop().flatten();
                values.push(owner.and_then(|owner| {
                    let method_name = rust_node_text(method, source).trim();
                    rust_callable_return_type_fqn(
                        analyzer,
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
    rust_collect_binding_type_fqn(&mut ctx, root, &mut found);
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
                analyzer, support, file, source, function,
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
        let Some(refs) = support.forward_reference_context(rust, file) else {
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
    rust_callable_candidates(analyzer, support, file, root, &name, reference_byte)
}

fn rust_bounded_scoped_callable_candidates(
    analyzer: &dyn IAnalyzer,
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

fn rust_field_code_unit_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    current_syntax: Option<RustCurrentSyntax<'_>>,
    field: &CodeUnit,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_code_unit_type_fqn(
        analyzer,
        support,
        file,
        current_syntax,
        field,
        "type",
        mode,
        cache,
    )
}

fn rust_function_code_unit_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    current_syntax: Option<RustCurrentSyntax<'_>>,
    function: &CodeUnit,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_code_unit_type_fqn(
        analyzer,
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
        support,
        code_unit,
        field_name,
        mode,
        &parsed.source,
        parsed.tree.root_node(),
    )
}

fn rust_code_unit_type_fqn_from_syntax(
    analyzer: &dyn IAnalyzer,
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
                    name.start_byte() <= range.start_byte && range.end_byte <= name.end_byte()
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
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
    reference_byte: Option<usize>,
) -> Option<String> {
    if support.is_bounded() {
        return rust_resolve_type_node_fqn_bounded(
            analyzer,
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
        return rust_enclosing_impl_type_fqn(analyzer, support, file, source, type_node);
    }
    if let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) {
        let refs = support.forward_reference_context(rust, file)?;
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
                rust, support, file, source, path_node,
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
                .fqn(resolved)
                .into_iter()
                .any(|unit| rust_is_type_definition(analyzer, &unit))
            && rust_type_fqn_visible_from_file(file, resolved)
        {
            return Some(resolved.to_string());
        }
        if let Some(imported) = rust_import_type_fqn(rust, support, file, name, reference_byte) {
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
        return rust_enclosing_impl_type_fqn(analyzer, support, file, source, type_node);
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
        let self_fqn = rust_enclosing_impl_type_fqn(analyzer, support, file, source, type_node)?;
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
            rust_imported_export_candidates(rust, support, file, name, reference_byte)
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
            return rust
                .canonical_rust_hierarchy_type(candidate)
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
            candidates =
                rust_imported_export_candidates(rust, support, file, name, Some(reference_byte));
        }
        return candidates;
    }
    if candidates.is_empty()
        && let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer)
    {
        candidates =
            rust_imported_export_candidates(rust, support, file, name, Some(reference_byte));
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
                rust.resolve_imported_export_from_binder_forward(file, &binder, reference);
            if targets.is_empty() && rust_binder_has_external_binding(&binder, reference) {
                return Vec::new();
            }
            targets
        }
    } else {
        let binder = rust.import_binder_of(file);
        let targets = rust.resolve_imported_export_from_binder_forward(file, &binder, reference);
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

/// True when the focused owner/qualifier resolves to a Rust crate or module that
/// is indexed in this workspace — e.g. a `use forc_pkg::{self as pkg}` alias
/// whose `pkg` root routes through cargo to a workspace crate. Such a qualifier
/// names a namespace, not a single declaration, so the honest outcome is
/// `no_definition`, never a confident "crosses an unindexed boundary" claim
/// (issue #1089: sway forc-pkg exposed as `pkg`).
fn rust_focused_is_workspace_module_namespace(
    rust: &RustAnalyzer,
    file: &ProjectFile,
    focused_text: &str,
) -> bool {
    !rust.resolve_module_files(file, focused_text).is_empty()
}

pub(super) fn parse_rust_tree(source: &str) -> Option<Tree> {
    lexical_scope::parse_rust_tree(source)
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
        let tree = parse_rust_tree(&source).expect("Rust tree");
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
        let tree = parse_rust_tree(&source).expect("Rust tree");
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
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/service.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "get_definitions_by_location");

        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/domain_events/planner.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_expression(&source, &file, "use super::*", "super");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/app.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_expression(&source, &file, "assets::Table", "assets");
        let rust =
            resolve_analyzer::<RustAnalyzer>(fixture.analyzer.analyzer()).expect("Rust analyzer");
        let support = AnalyzerRustDefinitionProvider::new(rust, false);
        let mut cache = RustTypeLookupCache::default();
        let value = resolve_rust(
            fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/app.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");
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
        let file = ProjectFile::new(fixture.project_root(), "src/app.rs");
        let tree = parse_rust_tree(source).expect("Rust tree");
        let site = site_for_expression(source, &file, "crate::schema::{self, assets}", "self");
        let rust =
            resolve_analyzer::<RustAnalyzer>(fixture.analyzer.analyzer()).expect("Rust analyzer");
        let support = AnalyzerRustDefinitionProvider::new(rust, false);
        let mut cache = RustTypeLookupCache::default();
        let value = resolve_rust(
            fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/foo.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/foo.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");

        for expression in [
            "State::Unit.run()",
            "State::Tuple(1).run()",
            "(State::Struct { value: 1 }).run()",
        ] {
            let site = site_for_expression(&source, &file, expression, "run");
            let outcome = resolve_rust_bounded(
                fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_expression(&source, &file, "State::Tuple(1).run()", "run");

        let tiny = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
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
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let tree = parse_rust_tree(&source).expect("Rust tree");
        let site = site_for_last(&source, &file, "run");
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 100_000,
            ..ReceiverAnalysisBudget::default()
        };
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
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
        let budget = ReceiverAnalysisBudget::tiny();
        let outcome = resolve_rust_bounded(
            fixture.analyzer.analyzer(),
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
        let cancellation = CancellationToken::cancel_after_checks_for_test(12);
        let outcome = resolve_rust_bounded(
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
