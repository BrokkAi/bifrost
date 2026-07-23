use super::*;
use crate::analyzer::RustReferenceContext;
use crate::analyzer::rust::field_roles::{
    RustFieldNameRole, RustStructFieldContainer, classify_rust_field_name,
};
use crate::analyzer::rust::lexical_scope;
use crate::analyzer::rust::rust_focused_use_path;
use crate::analyzer::rust::{
    RustReferenceNamespace, resolve_rust_module_segments_with_crate, rust_crate_root_package,
    rust_package_name,
};
use crate::analyzer::usages::rust_graph::RustDefinitionProvider;
use crate::hash::{HashMap, HashSet};
use std::cell::RefCell;

pub(crate) struct AnalyzerRustDefinitionProvider<'a> {
    rust: &'a RustAnalyzer,
    session: Option<&'a ResolutionSession>,
    cache_lookups: bool,
    fqns: RefCell<HashMap<String, Vec<CodeUnit>>>,
    file_identifiers: RefCell<HashMap<(ProjectFile, String), Vec<CodeUnit>>>,
}

impl<'a> AnalyzerRustDefinitionProvider<'a> {
    pub(crate) fn new(rust: &'a RustAnalyzer, cache_lookups: bool) -> Self {
        Self {
            rust,
            session: None,
            cache_lookups,
            fqns: RefCell::new(HashMap::default()),
            file_identifiers: RefCell::new(HashMap::default()),
        }
    }

    pub(crate) fn bounded(rust: &'a RustAnalyzer, session: &'a ResolutionSession) -> Self {
        Self {
            rust,
            session: Some(session),
            cache_lookups: true,
            fqns: RefCell::new(HashMap::default()),
            file_identifiers: RefCell::new(HashMap::default()),
        }
    }
}

impl RustDefinitionProvider for AnalyzerRustDefinitionProvider<'_> {
    fn is_bounded(&self) -> bool {
        self.session.is_some()
    }

    fn ranges(&self, analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> Vec<Range> {
        match self.session {
            Some(session) => {
                session.query_limited_rows(|limit| self.rust.ranges_limited(unit, limit))
            }
            None => analyzer.ranges(unit),
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
    let outcome = resolve_rust_unscoped(
        analyzer, support, file, source, tree, site, cache, operation,
    );
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
    let mut cache = RustTypeLookupCache::bounded_for_query(file, source, tree);
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
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_reference_node",
            "no Rust syntax node exists at the reference location",
        );
    };

    if let Some(outcome) = resolve_rust_field(analyzer, support, file, source, tree, site, cache) {
        return outcome;
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

    if rust_node_is_type_reference(node)
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

    let function = rust_enclosing_call_function(node);
    if let Some(function) = function {
        let candidates = if matches!(
            function.kind(),
            "scoped_identifier" | "scoped_type_identifier"
        ) {
            rust_bounded_scoped_callable_candidates(analyzer, support, file, source, function)
        } else {
            rust_callable_name(function, source)
                .map(|name| {
                    rust_callable_candidates(analyzer, support, file, &name, function.start_byte())
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

fn rust_node_is_type_reference(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
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

fn rust_enclosing_call_function(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        let parent = node.parent()?;
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
            rust_struct_field_name_outcome(analyzer, support, file, source, tree, site)
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
    let refs = rust.forward_reference_context_of(file);
    if let Some(tree) = tree
        && let Some(outcome) = rust_focused_token_tree_prefix_outcome(
            analyzer, rust, support, file, source, tree, site, &refs,
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
                    let refs = rust.forward_reference_context_of(file);
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
                candidates
            }
            None => support.fqn(&self_type),
        };
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }
    if let Some(tree) = tree
        && let Some(outcome) =
            rust_focused_use_path_outcome(analyzer, rust, support, file, source, tree, site, &refs)
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(outcome) = rust_focused_scoped_prefix_outcome(
            analyzer, rust, support, file, source, tree, site, &refs,
        )
    {
        return outcome;
    }
    if let Some(tree) = tree
        && let Some(candidates) = rust_focused_terminal_scoped_type_candidates(
            analyzer, rust, support, file, source, tree, site, &refs,
        )
    {
        return candidates_outcome(candidates);
    }
    let (candidates, scoped_lookup_failed) = if let Some((path, name)) = reference.rsplit_once("::")
    {
        let role = tree
            .and_then(|tree| rust_bare_reference_role(tree, site, source))
            .unwrap_or(RustBareReferenceRole::Callable);
        let resolved =
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
                ReceiverAnalysisOutcome::Precise(candidates) => candidates
                    .into_iter()
                    .filter(|candidate| rust_role_accepts_scoped(rust, role, candidate))
                    .collect(),
                ReceiverAnalysisOutcome::Ambiguous(_)
                | ReceiverAnalysisOutcome::Unknown
                | ReceiverAnalysisOutcome::Unsupported { .. }
                | ReceiverAnalysisOutcome::ExceededBudget { .. } => Vec::new(),
            };
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
                RustVisibleImportResolution::Resolved(candidates) => candidates,
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
                    if local.is_empty() { candidates } else { local }
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
                    if let Some(unit) = lexical {
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
                        return candidates_outcome(local);
                    }
                    return boundary(format!(
                        "`{reference}` is explicitly imported across a Rust crate/module boundary that is not indexed"
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
                            rust_current_module_candidates(
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
                        },
                        |unit| vec![unit],
                    )
                }
            }
        } else {
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
        return boundary(format!(
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
            container: RustStructFieldContainer::Literal,
        } if name.start_byte() == site.focus_start_byte
            && name.end_byte() == site.focus_end_byte =>
        {
            let Some(owner) = rust_resolve_type_node_fqn(
                analyzer,
                support,
                file,
                source,
                owner_type,
                Some(owner_type.start_byte()),
            ) else {
                return Some(no_definition(
                    "unresolved_struct_owner",
                    "Rust struct literal owner could not be resolved",
                ));
            };
            let name = &source[name.byte_range()];
            let candidates = support
                .fqn(&format!("{owner}.{name}"))
                .into_iter()
                .filter(CodeUnit::is_field)
                .collect();
            Some(candidates_outcome(candidates))
        }
        RustFieldNameRole::Reference {
            container: RustStructFieldContainer::Pattern,
            ..
        }
        | RustFieldNameRole::Other
        | RustFieldNameRole::Declaration { .. }
        | RustFieldNameRole::Reference { .. } => None,
    }
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
    Unbound,
}

/// Resolve an unqualified identifier represented directly by a macro token
/// tree through the same structured, position-aware path used by forward
/// definition lookup. Raw token trees do not carry ordinary expression/type
/// parents, so callers supply the namespace established from the queried
/// declaration. A result is returned only when that namespace resolves to one
/// physical declaration identity.
#[allow(clippy::too_many_arguments)]
pub(crate) fn rust_forward_bare_token_reference_fqn(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    namespace: RustReferenceNamespace,
) -> Option<String> {
    let reference = rust_node_text(node, source).trim();
    if reference.is_empty() {
        return None;
    }
    let role = match namespace {
        RustReferenceNamespace::Type => RustBareReferenceRole::Type,
        RustReferenceNamespace::Macro => RustBareReferenceRole::Macro,
        RustReferenceNamespace::PathPrefix => RustBareReferenceRole::Owner,
        RustReferenceNamespace::Value | RustReferenceNamespace::Any => {
            if node.next_sibling().is_some_and(|arguments| {
                arguments.kind() == "token_tree"
                    && arguments.child(0).is_some_and(|open| open.kind() == "(")
            }) {
                RustBareReferenceRole::Callable
            } else {
                RustBareReferenceRole::Value
            }
        }
    };
    let mut root = node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    if namespace != RustReferenceNamespace::Macro
        && lexical_scope::local_item_name_shadowed_in_tree(
            root,
            source,
            reference,
            node.start_byte(),
        )
    {
        return None;
    }
    let current_module = || {
        rust_current_module_candidates(
            analyzer,
            rust,
            support,
            file,
            root,
            node.start_byte(),
            node.end_byte(),
            reference,
            role,
        )
    };
    let mut candidates = match rust_visible_import_resolution(
        rust,
        support,
        file,
        source,
        node.start_byte(),
        reference,
        role,
    ) {
        RustVisibleImportResolution::Resolved(candidates) => candidates,
        RustVisibleImportResolution::GlobResolved(candidates) => {
            let local = current_module();
            if local.is_empty() { candidates } else { local }
        }
        RustVisibleImportResolution::BoundButUnindexed => return None,
        RustVisibleImportResolution::Unbound => current_module(),
    };
    sort_units(&mut candidates);
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0).fq_name())
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
    let refs = rust.forward_reference_context_of(file);
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
                return Some(boundary(format!(
                    "Rust macro `{name}` is imported across a crate/module boundary that is not indexed"
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
                        if let Some(package) = resolve_import_package_scoped(
                            rust,
                            file,
                            source,
                            scope_start,
                            &binding.module_specifier,
                        ) {
                            expected_fqns.insert(format!("{package}.{imported}"));
                        }
                    }
                    ImportKind::Namespace => {
                        if let Some(fqn) = resolve_import_package_scoped(
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
        let mut candidates = Vec::new();
        for (target_file, target_name) in targets {
            candidates.extend(rust_import_target_candidates(
                rust,
                support,
                target_file,
                target_name,
                role,
            ));
        }
        if explicitly_bound && !expected_fqns.is_empty() {
            let exact: Vec<_> = candidates
                .iter()
                .filter(|candidate| expected_fqns.contains(&candidate.fq_name()))
                .cloned()
                .collect();
            if !exact.is_empty() {
                candidates = exact;
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
    }
    RustVisibleImportResolution::Unbound
}

/// Resolve an import's module specifier to its package, scope-aware:
/// `self`/`super` prefixes resolve against the lexical module the import
/// statement lives in (file package + inline `mod` path at the binder's
/// scope start), so `use super::X` from a nested module means the parent
/// inline module — not the file's parent package, which is where the
/// file-level resolver incorrectly looked (#1074: `use super::ProgUpdate`
/// from `mod tests` claimed the same-file type "is not indexed").
fn resolve_import_package_scoped(
    rust: &RustAnalyzer,
    file: &ProjectFile,
    source: &str,
    scope_start: usize,
    module_specifier: &str,
) -> Option<String> {
    let first = module_specifier.split("::").next()?;
    if !matches!(first, "self" | "super") {
        return rust.resolve_module_package(file, module_specifier);
    }
    let file_package = crate::analyzer::rust::rust_package_name(file);
    let lexical_package = lexical_scope::lexical_package_at(&file_package, source, scope_start);
    let crate_package = crate::analyzer::rust::rust_crate_root_package(file);
    let segments: Vec<&str> = module_specifier
        .split("::")
        .filter(|segment| !segment.is_empty())
        .collect();
    crate::analyzer::rust::resolve_rust_module_segments_with_crate(
        &lexical_package,
        &crate_package,
        &segments,
    )
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
    let Some(first) = module_specifier.split("::").next() else {
        return false;
    };
    if !matches!(first, "self" | "super") {
        return false;
    }
    let file_package = crate::analyzer::rust::rust_package_name(file);
    let lexical_package = lexical_scope::lexical_package_at(&file_package, source, scope_start);
    let crate_package = crate::analyzer::rust::rust_crate_root_package(file);
    let segments: Vec<&str> = module_specifier
        .split("::")
        .filter(|segment| !segment.is_empty())
        .collect();
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
    let first = module_specifier.split("::").next()?;
    if !matches!(first, "self" | "super") {
        return None;
    }
    let file_package = crate::analyzer::rust::rust_package_name(file);
    let lexical_package = lexical_scope::lexical_package_at(&file_package, source, scope_start);
    let crate_package = crate::analyzer::rust::rust_crate_root_package(file);
    let segments: Vec<&str> = module_specifier
        .split("::")
        .filter(|segment| !segment.is_empty())
        .collect();
    let resolved = crate::analyzer::rust::resolve_rust_module_segments_with_crate(
        &lexical_package,
        &crate_package,
        &segments,
    )?;
    let (parent, name) = resolved.rsplit_once('.')?;
    (parent == file_package).then(|| name.to_string())
}

fn rust_import_target_candidates(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    target_file: ProjectFile,
    target_name: String,
    role: RustBareReferenceRole,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
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
        pending.extend(rust_forward_import_targets(rust, &file, &binder, &name));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
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
        RustBareReferenceRole::Value => rust_value_namespace_candidate(rust, candidate),
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
                || (candidate.is_field() && rust_declaration_is_value_item(rust, candidate))
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
        || (candidate.is_field() && rust_declaration_is_value_item(rust, candidate))
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
    let scoped = rust_enclosing_scoped_type_identifier_name(
        node,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
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

#[allow(clippy::too_many_arguments)]
fn rust_focused_terminal_scoped_type_candidates(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    refs: &RustReferenceContext,
) -> Option<Vec<CodeUnit>> {
    let focused =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)?;
    let scoped = rust_enclosing_scoped_type_identifier_name(
        focused,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    let full_path = rust_node_text(scoped, source).trim();
    let fqn =
        crate::analyzer::usages::rust_graph::resolve_rust_path_fqn(rust, refs, file, full_path)?;
    let mut candidates = support
        .fqn(&fqn)
        .into_iter()
        .filter(|candidate| rust_is_type_definition(analyzer, candidate))
        .collect::<Vec<_>>();
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
fn rust_focused_use_path_outcome(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    refs: &RustReferenceContext,
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
    let resolved_fqn = crate::analyzer::usages::rust_graph::resolve_rust_path_fqn(
        rust,
        refs,
        file,
        &focused_path.full_path,
    );
    Some(rust_focused_prefix_resolution_outcome(
        analyzer,
        rust,
        support,
        file,
        source,
        site,
        refs,
        focused_path.root,
        focused_text,
        &focused_path.full_path,
        role,
        resolved_fqn.as_deref(),
    ))
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
    refs: &RustReferenceContext,
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

    let resolved_fqn = rust_scoped_prefix_fqn(rust, file, refs, prefix, source);
    let root = rust_scoped_path_root(prefix);
    Some(rust_focused_prefix_resolution_outcome(
        analyzer,
        rust,
        support,
        file,
        source,
        site,
        refs,
        root,
        focused_text,
        prefix_text,
        RustFocusedPathRole::Owner,
        resolved_fqn.as_deref(),
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
    refs: &RustReferenceContext,
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
    let resolved_fqn = crate::analyzer::usages::rust_graph::resolve_rust_token_tree_paths(
        rust, support, refs, file, source, token_tree,
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
        refs,
        root,
        focused_text,
        prefix,
        RustFocusedPathRole::Owner,
        resolved_fqn.as_deref(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustFocusedPathRole {
    Owner,
    Declaration,
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
) -> DefinitionLookupOutcome {
    let root_name = rust_node_text(root, source).trim();
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
                let mut syntax_root = root;
                while let Some(parent) = syntax_root.parent() {
                    syntax_root = parent;
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
                return candidates_outcome(if local.is_empty() { imported } else { local });
            }
            RustVisibleImportResolution::BoundButUnindexed => {
                return boundary(format!(
                    "focused Rust owner `{focused_text}` is explicitly imported across a crate/module boundary that is not indexed"
                ));
            }
            RustVisibleImportResolution::Unbound => {}
        }

        let mut syntax_root = root;
        while let Some(parent) = syntax_root.parent() {
            syntax_root = parent;
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
            return boundary(format!(
                "focused Rust owner `{focused_text}` resolves through Cargo but its crate root is not indexed"
            ));
        }
    }

    if let Some(fqn) = resolved_fqn
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
        let mut candidates = if enclosing_module_self_root {
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
        || rust_extern_prelude_root(rust, support, file, refs, root, root_name)
    {
        return boundary(format!(
            "focused Rust path segment `{focused_text}` crosses a crate/module boundary not indexed in this workspace"
        ));
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
    if let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
        && let Some(field_expression) = rust_enclosing_field_expression(node)
    {
        let field = field_expression.child_by_field_name("field")?;
        let receiver = field_expression.child_by_field_name("value")?;
        if receiver.start_byte() <= site.focus_start_byte
            && site.focus_end_byte <= receiver.end_byte()
        {
            if rust_node_text(receiver, source).trim() == "self"
                && let Some(owner) =
                    rust_enclosing_impl_type_fqn(analyzer, support, file, source, node)
            {
                let candidates = support.fqn(&owner);
                if !candidates.is_empty() {
                    return Some(candidates_outcome(candidates));
                }
            }
            return Some(no_definition(
                "local_receiver",
                "the focused Rust receiver is a local expression, which is not indexed",
            ));
        }
        if !(field.start_byte() <= site.focus_start_byte && site.focus_end_byte <= field.end_byte())
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
                source, node, receiver, member,
            ));
        };
        let candidates = rust_member_candidates(
            support.members_for_owner_name(&owner, member),
            rust_field_expression_member_kind(field_expression),
        );
        if candidates.is_empty()
            && !support.is_bounded()
            && rust_field_expression_member_kind(field_expression) == RustMemberKind::Function
            && let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer)
        {
            let refs = rust.forward_reference_context_of(file);
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
    source: &str,
    node: Node<'_>,
    receiver: Node<'_>,
    member: &str,
) -> DefinitionLookupOutcome {
    if rust_node_text(receiver, source).trim() == "self"
        && let Some(owner_name) = rust_enclosing_impl_type_name_text(node, source)
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
fn rust_enclosing_impl_type_name_text(node: Node<'_>, source: &str) -> Option<String> {
    let mut current = node.parent()?;
    loop {
        if current.kind() == "impl_item"
            && let Some(type_node) = current.child_by_field_name("type")
        {
            return rust_type_ref(type_node, source).map(|type_ref| type_ref.name);
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
            file,
            source,
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
        let refs = rust.forward_reference_context_of(file);
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

struct RustParsedDeclarationSource {
    source: String,
    tree: Tree,
}

impl RustTypeLookupCache {
    pub(crate) fn bounded_for_query(file: &ProjectFile, source: &str, tree: Option<&Tree>) -> Self {
        let mut declarations = HashMap::default();
        declarations.insert(
            file.clone(),
            tree.map(|tree| RustParsedDeclarationSource {
                source: source.to_owned(),
                tree: tree.clone(),
            }),
        );
        Self {
            declarations,
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

fn rust_field_expression_member_kind(field_expression: Node<'_>) -> RustMemberKind {
    let mut function = field_expression;
    while let Some(parent) = function.parent()
        && parent.kind() == "generic_function"
        && parent.child_by_field_name("function") == Some(function)
    {
        function = parent;
    }
    if let Some(parent) = function.parent()
        && parent.kind() == "call_expression"
        && parent
            .child_by_field_name("function")
            .is_some_and(|callee| callee.id() == function.id())
    {
        RustMemberKind::Function
    } else {
        RustMemberKind::Field
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
    rust_type_definition_candidates_for_fqn(analyzer, support, file, &fqn, before_byte, cache)
}

pub(crate) fn rust_type_node_definition_candidates_cached(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
    cache: &mut RustTypeLookupCache,
) -> Vec<CodeUnit> {
    let reference_byte = type_node.start_byte();
    let Some(fqn) = rust_resolve_type_node_fqn(
        analyzer,
        support,
        file,
        source,
        type_node,
        Some(reference_byte),
    ) else {
        return Vec::new();
    };
    rust_type_definition_candidates_for_fqn(analyzer, support, file, &fqn, reference_byte, cache)
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
        cache,
    )
}

fn rust_type_definition_candidates_for_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    fqn: &str,
    reference_byte: usize,
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
    let local: Vec<_> = cache.parsed(file).map_or_else(Vec::new, |parsed| {
        candidates
            .iter()
            .filter(|unit| unit.source() == file)
            .filter(|unit| {
                rust_definition_scope_visible_at(
                    analyzer,
                    support,
                    unit,
                    parsed.tree.root_node(),
                    reference_byte,
                )
            })
            .cloned()
            .collect()
    });
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
    match expression.kind() {
        "self" if mode == RustTypeMode::Direct => {
            rust_enclosing_impl_type_fqn(analyzer, support, file, source, expression)
        }
        "identifier" => rust_binding_type_fqn(
            analyzer,
            support,
            file,
            source,
            root,
            rust_node_text(expression, source).trim(),
            before_byte,
            mode,
            cache,
        ),
        "field_expression" => {
            let receiver = expression.child_by_field_name("value")?;
            let field = expression.child_by_field_name("field")?;
            let owner = rust_expression_type_fqn(
                analyzer,
                support,
                file,
                source,
                root,
                receiver,
                before_byte,
                cache,
            )?;
            let member = rust_node_text(field, source).trim();
            rust_field_type_fqn(analyzer, support, file, source, &owner, member, mode, cache)
        }
        "call_expression" => rust_call_expression_type_fqn(
            analyzer, support, file, source, root, expression, mode, cache,
        ),
        "try_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                rust_expression_type_fqn_mode(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    child,
                    before_byte,
                    RustTypeMode::UnwrapContainer,
                    cache,
                )
            })
        }
        "await_expression" | "parenthesized_expression" | "reference_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                rust_expression_type_fqn_mode(
                    analyzer,
                    support,
                    file,
                    source,
                    root,
                    child,
                    before_byte,
                    mode,
                    cache,
                )
            })
        }
        "struct_expression" if mode == RustTypeMode::Direct => {
            let name = expression.child_by_field_name("name")?;
            rust_resolve_type_node_fqn(
                analyzer,
                support,
                file,
                source,
                name,
                Some(name.start_byte()),
            )
        }
        _ => None,
    }
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
        if node.start_byte() >= ctx.before_byte {
            continue;
        }
        match node.kind() {
            "parameter" => {
                if let Some((binding, type_node)) = rust_typed_binding(node, ctx.source)
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
                if let Some(binding) = node
                    .child_by_field_name("pattern")
                    .and_then(|pattern| rust_simple_identifier_text(pattern, ctx.source))
                    && binding == ctx.name
                {
                    if let Some(type_node) = node.child_by_field_name("type")
                        && let Some(fqn) = rust_resolve_type_node_fqn_mode(
                            ctx,
                            type_node,
                            Some(type_node.start_byte()),
                        )
                    {
                        *found = Some(fqn);
                    } else if let Some(value) = node.child_by_field_name("value")
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
            _ => {}
        }

        for index in (0..node.named_child_count()).rev() {
            let Some(child) = node.named_child(index) else {
                continue;
            };
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
        RustTypeMode::UnwrapContainer => rust_unwrap_container_type_node(type_node, ctx.source)?,
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

fn rust_typed_binding<'tree>(node: Node<'tree>, source: &str) -> Option<(String, Node<'tree>)> {
    let pattern = node.child_by_field_name("pattern")?;
    let name = rust_simple_identifier_text(pattern, source)?;
    let type_node = node.child_by_field_name("type")?;
    Some((name, type_node))
}

#[allow(clippy::too_many_arguments)]
fn rust_call_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    let function = call.child_by_field_name("function")?;
    if function.kind() == "field_expression"
        && let Some(method) = function.child_by_field_name("field")
        && let Some(receiver) = function.child_by_field_name("value")
    {
        let method_name = rust_node_text(method, source).trim();
        if matches!(method_name, "expect" | "unwrap" | "unwrap_or_default") {
            return rust_expression_type_fqn_mode(
                analyzer,
                support,
                file,
                source,
                root,
                receiver,
                call.start_byte(),
                RustTypeMode::UnwrapContainer,
                cache,
            );
        }
        let owner = rust_expression_type_fqn(
            analyzer,
            support,
            file,
            source,
            root,
            receiver,
            call.start_byte(),
            cache,
        )?;
        return rust_callable_return_type_fqn(
            analyzer,
            support,
            file,
            support.members_for_owner_name(&owner, method_name),
            mode,
            cache,
        );
    }
    let candidates = rust_callable_definition_candidates(
        analyzer,
        support,
        file,
        source,
        function,
        call.start_byte(),
    );
    rust_callable_return_type_fqn(analyzer, support, file, candidates, mode, cache)
}

fn rust_callable_definition_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
    reference_byte: usize,
) -> Vec<CodeUnit> {
    if function.kind() == "scoped_identifier" {
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
        let refs = rust.forward_reference_context_of(file);
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
    let Some(name) = rust_callable_name(function, source) else {
        return Vec::new();
    };
    rust_callable_candidates(analyzer, support, file, &name, reference_byte)
}

fn rust_bounded_scoped_callable_candidates(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
) -> Vec<CodeUnit> {
    let Some(name_node) = function.child_by_field_name("name") else {
        return Vec::new();
    };
    let name = rust_node_text(name_node, source).trim();
    if name.is_empty() {
        return Vec::new();
    }
    let Some(path) = function.child_by_field_name("path") else {
        return Vec::new();
    };
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
            .filter(CodeUnit::is_function)
            .collect();
    }
    let Some(components) = rust_structured_path_components(function, source) else {
        return Vec::new();
    };
    let Some(candidate) = resolve_rust_module_segments_with_crate(
        &rust_package_name(file),
        &rust_crate_root_package(file),
        &components,
    ) else {
        return Vec::new();
    };
    let package = rust_package_name(file);
    let mut candidates = support.fqn(&candidate);
    if candidates.is_empty() && !package.is_empty() {
        candidates = support.fqn(&format!("{package}.{candidate}"));
    }
    candidates
        .into_iter()
        .filter(CodeUnit::is_function)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn rust_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    _source: &str,
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
            rust_field_code_unit_type_fqn(analyzer, support, file, &field, mode, cache)
        });
    }
    let mut types = fields
        .into_iter()
        .filter_map(|field| {
            rust_field_code_unit_type_fqn(analyzer, support, file, &field, mode, cache)
        })
        .collect::<Vec<_>>();
    types.sort();
    types.dedup();
    (types.len() == 1).then(|| types.remove(0))
}

fn rust_callable_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    candidates: Vec<CodeUnit>,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    if !support.is_bounded() {
        return candidates.into_iter().find_map(|candidate| {
            rust_function_code_unit_return_type_fqn(
                analyzer, support, file, &candidate, mode, cache,
            )
        });
    }
    let mut types = candidates
        .into_iter()
        .filter_map(|candidate| {
            rust_function_code_unit_return_type_fqn(
                analyzer, support, file, &candidate, mode, cache,
            )
        })
        .collect::<Vec<_>>();
    types.sort();
    types.dedup();
    (types.len() == 1).then(|| types.remove(0))
}

fn rust_field_code_unit_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    field: &CodeUnit,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_code_unit_type_fqn(analyzer, support, file, field, "type", mode, cache)
}

fn rust_function_code_unit_return_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    function: &CodeUnit,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    rust_code_unit_type_fqn(
        analyzer,
        support,
        file,
        function,
        "return_type",
        mode,
        cache,
    )
}

fn rust_code_unit_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &dyn RustDefinitionProvider,
    _file: &ProjectFile,
    code_unit: &CodeUnit,
    field_name: &str,
    mode: RustTypeMode,
    cache: &mut RustTypeLookupCache,
) -> Option<String> {
    let parsed = cache.parsed(code_unit.source())?;
    let declaration =
        rust_code_unit_declaration_node(analyzer, support, code_unit, parsed.tree.root_node())?;
    let type_node = declaration.child_by_field_name(field_name)?;
    let target_node = match mode {
        RustTypeMode::Direct => type_node,
        RustTypeMode::UnwrapContainer => {
            rust_unwrap_container_type_node(type_node, &parsed.source)?
        }
    };
    rust_resolve_type_node_fqn(
        analyzer,
        support,
        code_unit.source(),
        &parsed.source,
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
    support
        .ranges(analyzer, code_unit)
        .iter()
        .filter_map(|range| root.descendant_for_byte_range(range.start_byte, range.end_byte))
        .find(|node| node.child_by_field_name("name").is_some())
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
    let type_ref = rust_type_ref(type_node, source)?;
    let name = type_ref.name.as_str();
    if type_ref.path.is_none() && name == "Self" {
        return rust_enclosing_impl_type_fqn(analyzer, support, file, source, type_node);
    }
    if let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) {
        let refs = rust.forward_reference_context_of(file);
        if let Some(path) = type_ref.path.as_deref() {
            if let Some(resolved) = refs.resolve_scoped(path, name).filter(|resolved| {
                support
                    .fqn(resolved)
                    .into_iter()
                    .any(|unit| rust_is_type_definition(analyzer, &unit))
            }) {
                return Some(resolved);
            }
            let named = rust_named_type_node(type_node)?;
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
    let named = rust_named_type_node(type_node)?;
    let components = rust_structured_path_components(named, source)?;
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
                name,
                reference_byte,
            )
        {
            return Some(local);
        }
        let package = rust_package_name(file);
        let local_fqn = if package.is_empty() {
            name.clone()
        } else {
            format!("{package}.{name}")
        };
        return rust_unique_type_fqn(analyzer, support, &local_fqn)
            .or_else(|| rust_unique_type_fqn(analyzer, support, name));
    }

    let candidate = if owner.first().is_some_and(|root| root == "Self") {
        let self_fqn = rust_enclosing_impl_type_fqn(analyzer, support, file, source, type_node)?;
        std::iter::once(self_fqn)
            .chain(owner[1..].iter().cloned())
            .chain(std::iter::once(name.clone()))
            .collect::<Vec<_>>()
            .join(".")
    } else {
        resolve_rust_module_segments_with_crate(
            &rust_package_name(file),
            &rust_crate_root_package(file),
            &components,
        )?
    };
    rust_unique_type_fqn(analyzer, support, &candidate).or_else(|| {
        let package = rust_package_name(file);
        (!package.is_empty())
            .then(|| format!("{package}.{candidate}"))
            .and_then(|candidate| rust_unique_type_fqn(analyzer, support, &candidate))
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
    name: &str,
    reference_byte: usize,
) -> Option<String> {
    let mut candidates = support
        .file_identifier(file, name)
        .into_iter()
        .filter(|unit| rust_is_type_definition(analyzer, unit))
        .filter(|unit| {
            support.ranges(analyzer, unit).into_iter().any(|range| {
                range.start_byte <= reference_byte
                    || !matches!(
                        unit.kind(),
                        crate::analyzer::CodeUnitType::Function
                            | crate::analyzer::CodeUnitType::Field
                    )
            })
        })
        .map(|unit| unit.fq_name())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn rust_structured_path_components(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut components = Vec::new();
    let mut pending = vec![node];
    while let Some(current) = pending.pop() {
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
                let name = current.child_by_field_name("name")?;
                pending.push(name);
                pending.push(path);
            }
            "generic_type" | "generic_function" => {
                pending.push(
                    current
                        .child_by_field_name("type")
                        .or_else(|| current.child_by_field_name("function"))?,
                );
            }
            "qualified_type" => pending.push(current.child_by_field_name("type")?),
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

fn rust_type_ref(type_node: Node<'_>, source: &str) -> Option<RustTypeRef> {
    let node = rust_named_type_node(type_node)?;
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
            let name = rust_node_text(name, source).trim();
            if name.is_empty() {
                return None;
            }
            Some(RustTypeRef {
                path: node
                    .child_by_field_name("path")
                    .and_then(|path| rust_type_path_text(path, source)),
                name: name.to_string(),
            })
        }
        "generic_type" | "generic_function" => {
            let base = node
                .child_by_field_name("type")
                .or_else(|| node.child_by_field_name("function"))?;
            rust_type_ref(base, source)
        }
        "qualified_type" => {
            let inner = node.child_by_field_name("type")?;
            rust_type_ref(inner, source)
        }
        _ => None,
    }
}

fn rust_named_type_node(type_node: Node<'_>) -> Option<Node<'_>> {
    match type_node.kind() {
        "reference_type" | "pointer_type" | "array_type" | "bracketed_type" => type_node
            .child_by_field_name("type")
            .and_then(rust_named_type_node),
        "higher_ranked_trait_bound" => type_node
            .child_by_field_name("type")
            .and_then(rust_named_type_node),
        "generic_type" | "generic_function" | "qualified_type" => Some(type_node),
        "scoped_type_identifier"
        | "scoped_identifier"
        | "type_identifier"
        | "identifier"
        | "self"
        | "super"
        | "crate" => Some(type_node),
        _ => {
            let mut cursor = type_node.walk();
            type_node
                .named_children(&mut cursor)
                .find_map(rust_named_type_node)
        }
    }
}

fn rust_type_path_text(path: Node<'_>, source: &str) -> Option<String> {
    match path.kind() {
        "generic_type" | "generic_function" => path
            .child_by_field_name("type")
            .or_else(|| path.child_by_field_name("function"))
            .and_then(|base| rust_type_path_text(base, source)),
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
    type_node: Node<'tree>,
    source: &str,
) -> Option<Node<'tree>> {
    let node = rust_named_type_node(type_node)?;
    let type_ref = rust_type_ref(node, source)?;
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
    let mut cursor = type_arguments.walk();
    type_arguments
        .named_children(&mut cursor)
        .next()
        .and_then(rust_named_type_node)
}

fn rust_import_type_fqn(
    rust: &RustAnalyzer,
    support: &dyn RustDefinitionProvider,
    file: &ProjectFile,
    name: &str,
    reference_byte: Option<usize>,
) -> Option<String> {
    let mut candidates: Vec<_> =
        rust_imported_export_candidates(rust, support, file, name, reference_byte)
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
            rust_node_scope_visible_at(declaration, reference_byte)
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
    rust_node_scope_visible_at(definition_node, reference_byte)
}

fn rust_node_scope_visible_at(definition_node: Node<'_>, reference_byte: usize) -> bool {
    lexical_scope::enclosing_visibility_scope_range(definition_node)
        .is_none_or(|(start, end)| start <= reference_byte && reference_byte < end)
}

fn rust_fqn_package(fqn: &str) -> &str {
    fqn.rsplit_once('.')
        .map(|(package, _)| package)
        .unwrap_or("")
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
    name: &str,
    reference_byte: usize,
) -> Vec<CodeUnit> {
    let mut candidates = rust_named_candidates(support, file, name);
    if candidates.is_empty()
        && !support.is_bounded()
        && let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer)
    {
        candidates =
            rust_imported_export_candidates(rust, support, file, name, Some(reference_byte));
    }
    candidates
}

fn rust_callable_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(rust_node_text(node, source).trim().to_string()),
        "scoped_identifier" => node
            .child_by_field_name("name")
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

fn rust_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
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
    reference
        .split("::")
        .next()
        .is_some_and(|root| !matches!(root, "crate" | "self" | "super") && root != reference)
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
    fn bounded_definition_lookup_stops_at_scope_budget() {
        let (fixture, file, source, tree, site) = member_fixture();
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
        let (fixture, file, source, tree, site) = member_fixture();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
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
