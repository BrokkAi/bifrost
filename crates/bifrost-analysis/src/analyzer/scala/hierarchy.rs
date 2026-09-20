use super::*;
use crate::analyzer::ImportInfo;
use crate::analyzer::jvm::external::JvmExternalDeclarations;
use crate::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use crate::analyzer::usages::scala_graph::{ScalaNameResolver, ScalaProjectTypes};
use crate::analyzer::usages::{
    ExternalMemberFamilyAnswer, ExternalMemberFamilyIncompleteReason, ExternalMemberFamilyStatus,
    JvmExternalMemberIdentity, JvmReceiverSemantics, MemberFacts,
};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_jvm::scala::graph::namespace::ScalaTypeNamespaceResolution;
use std::sync::Arc;

#[derive(Clone)]
struct ScalaHierarchyOwnerContext {
    supertype_lookup_paths: Vec<ScalaSupertypeLookupPath>,
    imports: Vec<ImportInfo>,
}

enum ScalaHierarchyPackageResolution {
    NoMatch,
    Resolved(String),
    AuthoritativeMiss,
}

/// Where one spelled Scala supertype lands when the indexed workspace declares
/// nothing under that name (#3454).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScalaExternalRootLanding {
    /// The spelling names the queried external root itself, so a template that
    /// spells it sits below that root.
    ExternalRoot,
    /// The spelling names something else: a different external declaration, or
    /// a name the shared surface does not answer at all.
    Other,
    /// More than one visible wildcard import could bind the spelling, so which
    /// declaration it denotes cannot be told from the queried root.
    Ambiguous,
}

impl TypeHierarchyProvider for ScalaAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors = self.resolve_direct_ancestors(token, code_unit);
        self.direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        let uncancelled = crate::cancellation::CancellationToken::default();
        self.get_direct_descendants_within(
            code_unit,
            &crate::analyzer::DescendantIndexScope::whole_workspace(&uncancelled),
        )
        .expect("a descendant walk that cannot stop always completes")
    }

    /// Scala keeps one index, not one per [`crate::analyzer::DescendantIndexVariant`].
    ///
    /// The #908 lazy index is a single cheap global pass that records only the
    /// simple supertype names each class spells; ancestor resolution is
    /// deferred to the candidates that could match the queried owner. There is
    /// no eager per-class ancestor build to prune, so a second variant would
    /// double a cheap pass to save nothing. What the scope does carry here is
    /// the deadline, polled once per candidate whose ancestors are resolved --
    /// that resolution is the expensive step.
    fn get_direct_descendants_within(
        &self,
        code_unit: &CodeUnit,
        scope: &crate::analyzer::DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        if scope.cancellation().is_cancelled() {
            return None;
        }
        self.lazy_hierarchy_index
            .get_or_init(|| self.build_lazy_hierarchy_index())
            .direct_descendants_while(token, self, code_unit, scope)
    }
}

/// Candidate-scoped Scala descendant lookup.
///
/// Building the whole-workspace descendant graph eagerly (issue #908) resolved
/// every class's ancestors up front, which is `O(N)` per class because each
/// `ScalaNameResolver` rebuilds the enclosing package's binding table — an
/// `O(N^2)` build that blocked the first inverse-member query for minutes on
/// large workspaces. Instead we do a single cheap global pass that records only
/// the parser-derived *simple names* each class spells as a direct supertype
/// (no resolution), then resolve ancestors on demand for just the classes whose
/// spelled supertype could name a queried owner. The per-class resolution is
/// memoized in the analyzer's `direct_ancestors` cache, so a transitive
/// descendant walk pays for the subtree it actually touches, not the workspace.
pub(crate) struct ScalaLazyHierarchyIndex {
    /// Bulk-projected hierarchy context per class (imports + supertype paths),
    /// captured without point-hydrating any file so ancestor resolution never
    /// re-reads a file state.
    contexts: HashMap<CodeUnit, ScalaHierarchyOwnerContext>,
    /// Shared project-types snapshot used by every ancestor resolution.
    types: Arc<ScalaProjectTypes>,
    /// Same-fq-name candidate identities, used to reconcile a resolved ancestor
    /// to the concrete declaration identity a descendant query is keyed on
    /// (mirrors `build_direct_descendant_index_from_candidates`).
    types_by_fq_name: HashMap<String, Vec<CodeUnit>>,
    /// Classes indexed by each simple supertype name they spell. A class can
    /// only be a descendant of `owner` if it spells `owner`'s simple name, so
    /// this prunes ancestor resolution to the relevant candidates.
    candidates_by_supertype_simple: HashMap<String, Vec<CodeUnit>>,
    /// The number of class candidates the pass admitted, before any hierarchy
    /// context narrowed them. One external-root walk charges this as its base
    /// scan, the Scala counterpart of Java's admitted-declaration count.
    class_candidate_count: usize,
}

impl ScalaLazyHierarchyIndex {
    /// The number of class declarations this pass indexed.
    fn class_candidate_count(&self) -> usize {
        self.class_candidate_count
    }

    /// Every class that spells `owner` as a direct supertype, under the
    /// caller's deadline. Polled once per candidate: one candidate is one
    /// ancestor resolution, which is the whole cost of this walk.
    fn direct_descendants_while(
        &self,
        token: QueryToken<'_>,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        scope: &crate::analyzer::DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        if !owner.is_class() {
            return Some(HashSet::default());
        }
        let simple = crate::analyzer::scala::scala_simple_type_name(owner);
        let Some(candidates) = self.candidates_by_supertype_simple.get(&simple) else {
            return Some(HashSet::default());
        };
        let mut descendants = HashSet::default();
        for candidate in candidates {
            if scope.cancellation().is_cancelled() {
                return None;
            }
            let ancestors = self.ancestors_of(token, scala, candidate);
            if ancestors
                .iter()
                .any(|ancestor| self.reconcile_ancestor(ancestor, candidate) == *owner)
            {
                descendants.insert(candidate.clone());
            }
        }
        Some(descendants)
    }

    /// Resolve a candidate's direct ancestors, reading through the analyzer's
    /// shared `direct_ancestors` cache so repeated subtree walks and later
    /// `get_direct_ancestors` queries never re-resolve or point-hydrate.
    fn ancestors_of(
        &self,
        token: QueryToken<'_>,
        scala: &ScalaAnalyzer,
        candidate: &CodeUnit,
    ) -> Arc<Vec<CodeUnit>> {
        if let Some(cached) = scala.direct_ancestors.get(candidate) {
            return cached;
        }
        let ancestors = self
            .contexts
            .get(candidate)
            .map(|context| {
                scala.resolve_direct_ancestor_units_with_context(
                    token,
                    candidate,
                    &self.types,
                    context,
                )
            })
            .unwrap_or_default();
        let ancestors = Arc::new(ancestors);
        scala
            .direct_ancestors
            .insert(candidate.clone(), Arc::clone(&ancestors));
        ancestors
    }

    /// Map a resolved ancestor to the concrete same-source declaration identity
    /// when the fq-name is uniquely sourced, matching the identity contract of
    /// the eager `DirectDescendantIndex` edge construction.
    fn reconcile_ancestor(&self, ancestor: &CodeUnit, candidate: &CodeUnit) -> CodeUnit {
        self.types_by_fq_name
            .get(&ancestor.fq_name())
            .and_then(|same_name| {
                let mut same_source = same_name
                    .iter()
                    .filter(|unit| unit.source() == candidate.source());
                let exact = same_source.next()?;
                same_source.next().is_none().then(|| exact.clone())
            })
            .unwrap_or_else(|| ancestor.clone())
    }
}

impl ScalaAnalyzer {
    fn build_lazy_hierarchy_index(&self) -> ScalaLazyHierarchyIndex {
        let _scope = crate::profiling::scope("ScalaAnalyzer::build_lazy_hierarchy_index");
        let file_states = self.bulk_file_states(self.analyzed_files(), BulkFileStateSource::Omit);
        let mut candidates = Vec::new();
        let mut contexts: HashMap<CodeUnit, ScalaHierarchyOwnerContext> = HashMap::default();
        let mut seen = HashSet::default();
        for state in file_states.values() {
            for candidate in state
                .definition_lookup_units
                .iter()
                .chain(&state.declarations)
                .filter(|candidate| candidate.is_class())
            {
                if seen.insert(candidate.clone()) {
                    candidates.push(candidate.clone());
                }
                if let Some(context) = hierarchy_owner_context_from_state(state, candidate) {
                    contexts.insert(candidate.clone(), context);
                }
            }
        }
        let types = self.project_types_from_file_states(file_states);

        // Cheap global pass: group same-fq-name identities and index each class
        // by the simple names it spells as direct supertypes. No resolution.
        let mut types_by_fq_name: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for candidate in &candidates {
            types_by_fq_name
                .entry(candidate.fq_name())
                .or_default()
                .push(candidate.clone());
        }
        let mut candidates_by_supertype_simple: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for (candidate, context) in &contexts {
            let mut keys: HashSet<String> = HashSet::default();
            for path in &context.supertype_lookup_paths {
                let Some(leaf) = path.segments().last() else {
                    continue;
                };
                // The spelled leaf is the query key for a directly-named owner.
                keys.insert(leaf.clone());
                // An `import a.b.Real as Leaf` renames the spelled leaf, so the
                // owner's real simple name differs from what is spelled. Index
                // the candidate under the import target's simple name too, so a
                // descendant query keyed on the real name still finds it.
                for import in &context.imports {
                    if import.is_wildcard {
                        continue;
                    }
                    if import.identifier.as_deref() != Some(leaf.as_str()) {
                        continue;
                    }
                    if let Some(real) = scala_import_path(import)
                        .as_deref()
                        .and_then(|path| path.rsplit('.').next())
                        .filter(|real| *real != leaf.as_str())
                    {
                        keys.insert(real.to_string());
                    }
                }
            }
            for key in keys {
                candidates_by_supertype_simple
                    .entry(key)
                    .or_default()
                    .push(candidate.clone());
            }
        }

        ScalaLazyHierarchyIndex {
            class_candidate_count: candidates.len(),
            contexts,
            types,
            types_by_fq_name,
            candidates_by_supertype_simple,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn type_relations(&self, token: QueryToken<'_>) -> &[TypeRelation] {
        self.type_relations
            .get_or_init(|| self.collect_type_relations(token))
            .as_slice()
    }

    #[allow(dead_code)]
    fn collect_type_relations(&self, token: QueryToken<'_>) -> Vec<TypeRelation> {
        let types = self.project_types();
        let traits = self.scala_trait_fqns();
        self.all_declarations()
            .filter(|unit| unit.is_class())
            .flat_map(|unit| self.resolve_direct_ancestor_relations(token, &unit, &types, &traits))
            .collect()
    }

    fn resolve_direct_ancestors(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
    ) -> Vec<CodeUnit> {
        let types = self.project_types();
        self.resolve_direct_ancestor_units(token, code_unit, &types)
    }

    fn resolve_direct_ancestor_units(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
        types: &ScalaProjectTypes,
    ) -> Vec<CodeUnit> {
        if !code_unit.is_class() {
            return Vec::new();
        }

        let Some(state) = self.inner.fetch_file_state(code_unit.source()) else {
            return Vec::new();
        };
        let Some(context) = hierarchy_owner_context_from_state(&state, code_unit) else {
            return Vec::new();
        };
        self.resolve_direct_ancestor_units_with_context(token, code_unit, types, &context)
    }

    fn resolve_direct_ancestor_units_with_context(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
        types: &ScalaProjectTypes,
        context: &ScalaHierarchyOwnerContext,
    ) -> Vec<CodeUnit> {
        let mut ancestors = Vec::new();
        let mut seen = HashSet::default();
        for path in &context.supertype_lookup_paths {
            let Some(fqn) =
                self.resolve_hierarchy_supertype_fqn(token, code_unit, types, context, path)
            else {
                continue;
            };
            if !seen.insert(fqn.clone()) {
                continue;
            }
            if let ScalaTypeNamespaceResolution::Resolved(definition) =
                types.exact_type_declaration_for_owner_context(&fqn, code_unit)
            {
                ancestors.push(definition);
            }
        }
        ancestors
    }

    /// The workspace type name one supertype path resolves to under its owner's
    /// package, import and lexical context.
    ///
    /// This is the tier ladder both the ancestor graph and the external-root
    /// walk read (#3454), kept as one function so a descendant edge and an
    /// external boundary cannot disagree about the same spelling.
    fn resolve_hierarchy_supertype_fqn(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
        types: &ScalaProjectTypes,
        context: &ScalaHierarchyOwnerContext,
        path: &ScalaSupertypeLookupPath,
    ) -> Option<String> {
        let package_prefixes = hierarchy_path_package_prefixes(path, code_unit);
        let resolver = ScalaNameResolver::for_file_with_package_context(
            self,
            token,
            Some(code_unit.source()),
            &package_prefixes,
            &context.imports,
            types,
        );
        let non_wildcard_imports = context
            .imports
            .iter()
            .filter(|import| !import.is_wildcard)
            .cloned()
            .collect::<Vec<_>>();
        let wildcard_baseline = (non_wildcard_imports.len() != context.imports.len()).then(|| {
            ScalaNameResolver::for_file_with_package_context(
                self,
                token,
                Some(code_unit.source()),
                &package_prefixes,
                &non_wildcard_imports,
                types,
            )
        });
        self.resolve_hierarchy_supertype_path(
            types,
            &resolver,
            wildcard_baseline.as_ref(),
            path,
            &package_prefixes,
            &context.imports,
        )
    }

    fn resolve_hierarchy_supertype_path(
        &self,
        types: &ScalaProjectTypes,
        resolver: &ScalaNameResolver,
        wildcard_baseline: Option<&ScalaNameResolver>,
        path: &ScalaSupertypeLookupPath,
        package_prefixes: &[String],
        imports: &[ImportInfo],
    ) -> Option<String> {
        let segments = path.segments();
        if let [root, _, ..] = segments
            && !hierarchy_import_claims_root(imports, root, resolver, wildcard_baseline)
        {
            match self.resolve_enclosing_package_supertype(package_prefixes, segments) {
                ScalaHierarchyPackageResolution::Resolved(fqn) => return Some(fqn),
                ScalaHierarchyPackageResolution::AuthoritativeMiss => return None,
                ScalaHierarchyPackageResolution::NoMatch => {}
            }
        }
        types.resolve_type_in_hierarchy_context(self, resolver, segments)
    }

    fn resolve_enclosing_package_supertype(
        &self,
        package_prefixes: &[String],
        segments: &[String],
    ) -> ScalaHierarchyPackageResolution {
        let Some((root, rest)) = segments.split_first() else {
            return ScalaHierarchyPackageResolution::NoMatch;
        };
        if rest.is_empty() || root == "_root_" {
            return ScalaHierarchyPackageResolution::NoMatch;
        }
        for package in scala_enclosing_package_root_candidates(package_prefixes, root) {
            if package == *root {
                continue;
            }
            if !self.inner.forward_package_exists(&package) {
                continue;
            }
            let qualified = std::iter::once(package.as_str())
                .chain(rest.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(".");
            let mut declarations = self
                .inner
                .definitions(&qualified)
                .filter(CodeUnit::is_class)
                .collect::<Vec<_>>();
            declarations.sort();
            declarations.dedup();
            let ordinary = declarations
                .iter()
                .filter(|unit| !unit.short_name().ends_with('$'))
                .cloned()
                .collect::<Vec<_>>();
            let selected = if ordinary.is_empty() {
                declarations
            } else {
                ordinary
            };
            return match selected.as_slice() {
                [definition] => ScalaHierarchyPackageResolution::Resolved(definition.fq_name()),
                [] | [_, _, ..] => ScalaHierarchyPackageResolution::AuthoritativeMiss,
            };
        }
        ScalaHierarchyPackageResolution::NoMatch
    }

    /// Enumerate every workspace template below one exact external root and the
    /// members of the queried identity those templates declare (#3454).
    ///
    /// This is Scala's half of the shared JVM external boundary. It reads the
    /// one reviewed JDK model the whole realm activates and answers the same
    /// question `JavaAnalyzer::resolve_external_member_family` answers from
    /// Java's persisted hierarchy facts, so the Scala row ships no JDK model of
    /// its own. The effect is never read from a spelling: only the members of
    /// templates this walk proves below the exact external root become
    /// candidates.
    ///
    /// The walk uses Scala's own structured hierarchy. The lazy index's
    /// parser-derived supertype lookup paths decide which templates could sit
    /// below the root, the same tier ladder the ancestor graph reads decides
    /// where each spelled supertype lands, and the closure over
    /// workspace-to-workspace edges is iterative so a deep tree cannot recurse.
    pub(crate) fn resolve_external_member_family(
        &self,
        analyzer: &dyn IAnalyzer,
        identity: &JvmExternalMemberIdentity,
        max_visits: usize,
        cancellation: Option<&crate::cancellation::CancellationToken>,
    ) -> ExternalMemberFamilyAnswer {
        if identity.language() != Language::Scala {
            return ExternalMemberFamilyAnswer::unsupported();
        }
        if cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled) {
            return ExternalMemberFamilyAnswer::stopped(ExternalMemberFamilyStatus::Cancelled, 0);
        }
        if identity.receiver() == JvmReceiverSemantics::Static {
            // A static JVM member is reached on the type itself, so no
            // workspace subtype can override it.
            return ExternalMemberFamilyAnswer {
                status: ExternalMemberFamilyStatus::Complete,
                candidates: Vec::new(),
                visited: 0,
            };
        }
        let _scope = crate::profiling::scope("ScalaAnalyzer::resolve_external_member_family");
        let index = self
            .lazy_hierarchy_index
            .get_or_init(|| self.build_lazy_hierarchy_index());
        let scan = index.class_candidate_count();
        if scan > max_visits {
            return ExternalMemberFamilyAnswer::stopped(
                ExternalMemberFamilyStatus::BudgetExhausted,
                0,
            );
        }
        let mut visited = scan;
        if index.types_by_fq_name.contains_key(identity.owner_fqn()) {
            // The workspace declares the queried external name itself, so a
            // workspace template below that name cannot be told from the
            // external root.
            return ExternalMemberFamilyAnswer::incomplete(
                ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
                visited,
            );
        }
        // A template can only sit below the root when it spells the root's
        // simple name in an extends clause.
        let owner_simple = identity
            .owner_fqn()
            .rsplit('.')
            .next()
            .expect("a canonical external FQN has a last segment");
        let Some(possible) = index
            .candidates_by_supertype_simple
            .get(owner_simple)
            .filter(|candidates| !candidates.is_empty())
        else {
            return ExternalMemberFamilyAnswer {
                status: ExternalMemberFamilyStatus::Complete,
                candidates: Vec::new(),
                visited,
            };
        };

        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        let mut direct = Vec::new();
        let mut below: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
        for candidate in possible {
            if cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled) {
                return ExternalMemberFamilyAnswer::stopped(
                    ExternalMemberFamilyStatus::Cancelled,
                    visited,
                );
            }
            let Some(context) = index.contexts.get(candidate) else {
                return ExternalMemberFamilyAnswer::incomplete(
                    ExternalMemberFamilyIncompleteReason::HierarchyFactsUnavailable,
                    visited,
                );
            };
            if context.supertype_lookup_paths.len() > max_visits.saturating_sub(visited) {
                return ExternalMemberFamilyAnswer::stopped(
                    ExternalMemberFamilyStatus::BudgetExhausted,
                    visited,
                );
            }
            visited += context.supertype_lookup_paths.len();
            for path in &context.supertype_lookup_paths {
                if let Some(fqn) = self.resolve_hierarchy_supertype_fqn(
                    token,
                    candidate,
                    &index.types,
                    context,
                    path,
                ) {
                    if let ScalaTypeNamespaceResolution::Resolved(ancestor) = index
                        .types
                        .exact_type_declaration_for_owner_context(&fqn, candidate)
                    {
                        let ancestor = index.reconcile_ancestor(&ancestor, candidate);
                        below.entry(ancestor).or_default().push(candidate.clone());
                    }
                    continue;
                }
                let package_prefixes = hierarchy_path_package_prefixes(path, candidate);
                match self.external_supertype_landing(
                    analyzer.semantic_model_overlay(),
                    candidate.package_name(),
                    &package_prefixes,
                    &context.imports,
                    path,
                    identity.owner_fqn(),
                ) {
                    ScalaExternalRootLanding::ExternalRoot => direct.push(candidate.clone()),
                    ScalaExternalRootLanding::Other => {}
                    ScalaExternalRootLanding::Ambiguous => {
                        return ExternalMemberFamilyAnswer::incomplete(
                            ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
                            visited,
                        );
                    }
                }
            }
        }

        let mut descendants = Vec::new();
        let mut seen = HashSet::default();
        let mut stack = direct;
        while let Some(unit) = stack.pop() {
            if cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled) {
                return ExternalMemberFamilyAnswer::stopped(
                    ExternalMemberFamilyStatus::Cancelled,
                    visited,
                );
            }
            if !seen.insert(unit.clone()) {
                continue;
            }
            if let Some(children) = below.get(&unit) {
                stack.extend(children.iter().cloned());
            }
            descendants.push(unit);
        }
        descendants.sort();

        let mut candidates = Vec::new();
        for descendant in &descendants {
            if cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled) {
                return ExternalMemberFamilyAnswer::stopped(
                    ExternalMemberFamilyStatus::Cancelled,
                    visited,
                );
            }
            let children = analyzer.direct_children(descendant);
            if children.len() > max_visits.saturating_sub(visited) {
                return ExternalMemberFamilyAnswer::stopped(
                    ExternalMemberFamilyStatus::BudgetExhausted,
                    visited,
                );
            }
            visited += children.len();
            let mut matching = Vec::new();
            for child in children {
                if !child.is_function() || child.identifier() != identity.member() {
                    continue;
                }
                let Some(facts) = MemberFacts::read(analyzer, &child) else {
                    return ExternalMemberFamilyAnswer::incomplete(
                        ExternalMemberFamilyIncompleteReason::MemberFactsUnavailable,
                        visited,
                    );
                };
                // `is_static` means "member of an `object`" in Scala, and an
                // `object` extending a trait implements that trait's members,
                // so only the universal exclusions apply here.
                if facts.universal_exclusion().is_some() {
                    continue;
                }
                let Some(arity) = facts.arity() else {
                    return ExternalMemberFamilyAnswer::incomplete(
                        ExternalMemberFamilyIncompleteReason::MemberFactsUnavailable,
                        visited,
                    );
                };
                if arity.accepts(identity.arity()) {
                    matching.push(child);
                }
            }
            match matching.as_slice() {
                [] => {}
                [only] => candidates.push(only.clone()),
                [_, _, ..] => {
                    return ExternalMemberFamilyAnswer::incomplete(
                        ExternalMemberFamilyIncompleteReason::OverloadIdentityUnproven,
                        visited,
                    );
                }
            }
        }
        candidates.sort();
        candidates.dedup();
        ExternalMemberFamilyAnswer {
            status: ExternalMemberFamilyStatus::Complete,
            candidates,
            visited,
        }
    }

    /// Where one spelled supertype of a possible descendant lands once the
    /// indexed workspace has declined to name it (#3454).
    ///
    /// The workspace tier ran first, so `Other` here means the spelling is
    /// external or unanswered, and only the shared external declaration ladder
    /// can say whether it names the queried root. That ladder is
    /// [`Self::external_type_spelling_in`], the same one the receiver-typing
    /// and boundary-evidence paths read, so a class extending the root and a
    /// receiver of the root's type cannot disagree about one spelling.
    ///
    /// A miss is not a proof of absence: a supertype the surface does not
    /// answer is `Other`, never an invented external root. A bare spelling a
    /// wildcard import could bind is refused when several wildcard namespaces
    /// are in scope, because a dependency the surface has not indexed could
    /// still bind the name.
    fn external_supertype_landing(
        &self,
        packs: Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
        package_name: &str,
        package_prefixes: &[String],
        imports: &[ImportInfo],
        path: &ScalaSupertypeLookupPath,
        external_root_fqn: &str,
    ) -> ScalaExternalRootLanding {
        let external = self.external_declarations(packs);
        if external.is_empty() {
            return ScalaExternalRootLanding::Other;
        }
        let segments = path.segments();
        // `_root_.a.b.C` names the root package absolutely; the shared ladder
        // reads written qualified names, so the marker itself is not a segment.
        let segments = if segments.first().is_some_and(|root| root == "_root_") {
            &segments[1..]
        } else {
            segments
        };
        if segments.is_empty() {
            return ScalaExternalRootLanding::Other;
        }
        let spelling = segments.join(".");
        // An explicit import or a written qualified name settles the spelling
        // on its own; only a bare spelling no explicit tier binds is open to
        // several wildcard namespaces at once.
        let explicitly_bound = imports
            .iter()
            .any(|import| !import.is_wildcard && import.local_name() == Some(spelling.as_str()));
        if !spelling.contains('.')
            && !explicitly_bound
            && self.wildcard_supertype_binding_is_ambiguous(
                &external,
                package_name,
                package_prefixes,
                imports,
                &spelling,
                external_root_fqn,
            )
        {
            return ScalaExternalRootLanding::Ambiguous;
        }
        match Self::external_type_spelling_in(&external, package_name, &spelling, imports) {
            Some(external_type) if external_type.fqn() == external_root_fqn => {
                ScalaExternalRootLanding::ExternalRoot
            }
            _ => ScalaExternalRootLanding::Other,
        }
    }

    /// Whether more than one wildcard import in scope could bind a bare
    /// supertype spelling (#3454).
    ///
    /// Scala refuses to pick between two wildcard imports that both bind one
    /// name. The shared surface only reports what its artifacts and activated
    /// packs declare, so a second wildcard namespace whose dependency the
    /// surface has not indexed could still bind the name: the landing is then
    /// unproven rather than settled by import order, the same refusal Java's
    /// external-root walk makes.
    fn wildcard_supertype_binding_is_ambiguous(
        &self,
        external: &JvmExternalDeclarations<'_>,
        package_name: &str,
        package_prefixes: &[String],
        imports: &[ImportInfo],
        spelling: &str,
        external_root_fqn: &str,
    ) -> bool {
        let mut namespaces: Vec<String> = Vec::new();
        for import in imports {
            if !import.is_wildcard {
                continue;
            }
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            for candidate in scala_import_path_candidates(&path, package_prefixes) {
                if !namespaces.contains(&candidate) {
                    namespaces.push(candidate);
                }
            }
        }
        if namespaces.len() <= 1 {
            return false;
        }
        namespaces.iter().any(|namespace| {
            format!("{namespace}.{spelling}") == external_root_fqn
                || external
                    .resolve_wildcard_import(namespace, spelling, package_name)
                    .is_some()
        })
    }

    fn resolve_direct_ancestor_relations(
        &self,
        token: QueryToken<'_>,
        code_unit: &CodeUnit,
        types: &ScalaProjectTypes,
        traits: &HashSet<String>,
    ) -> Vec<TypeRelation> {
        let owner_is_trait = traits.contains(&code_unit.fq_name());
        self.resolve_direct_ancestor_units(token, code_unit, types)
            .into_iter()
            .map(|ancestor| {
                let kind = self.relation_kind(owner_is_trait, &ancestor, traits);
                TypeRelation {
                    from: code_unit.clone(),
                    to: ancestor,
                    kind,
                }
            })
            .collect()
    }

    fn relation_kind(
        &self,
        owner_is_trait: bool,
        ancestor: &CodeUnit,
        traits: &HashSet<String>,
    ) -> TypeRelationKind {
        if !owner_is_trait && traits.contains(&ancestor.fq_name()) {
            TypeRelationKind::TraitImplementation
        } else {
            TypeRelationKind::NominalInheritance
        }
    }

    pub(crate) fn is_scala_trait_declaration(&self, code_unit: &CodeUnit) -> bool {
        code_unit.is_class()
            && self
                .forward_owner_facts(code_unit)
                .map(|facts| facts.is_trait)
                .unwrap_or_else(|| self.inner.is_scala_trait(code_unit))
    }

    fn scala_trait_fqns(&self) -> HashSet<String> {
        self.inner
            .scala_traits()
            .into_iter()
            .map(|unit| unit.fq_name())
            .collect()
    }
}

fn hierarchy_owner_context_from_state(
    state: &FileState,
    owner: &CodeUnit,
) -> Option<ScalaHierarchyOwnerContext> {
    let raw_supertypes = state.raw_supertypes.get(owner)?;
    let supertype_lookup_paths = state
        .supertype_lookup_paths
        .get(owner)?
        .iter()
        .map(|path| ScalaSupertypeLookupPath::decode(path))
        .collect::<Option<Vec<_>>>()?;
    if raw_supertypes.len() != supertype_lookup_paths.len() {
        return None;
    }
    let reference_byte = state
        .ranges
        .get(owner)
        .into_iter()
        .flatten()
        .map(|range| range.start_byte)
        .min()
        .unwrap_or(usize::MAX);
    let fallback_package = [owner.package_name().to_string()];
    let package_prefixes = supertype_lookup_paths
        .first()
        .map(ScalaSupertypeLookupPath::package_prefixes)
        .filter(|prefixes| !prefixes.is_empty())
        .unwrap_or(fallback_package.as_slice());
    let lexical_scopes = supertype_lookup_paths
        .first()
        .map(ScalaSupertypeLookupPath::lexical_scopes)
        .unwrap_or_default();
    let imports = state
        .imports
        .iter()
        .filter(|import| {
            scala_import_visible_at(import, package_prefixes, lexical_scopes, reference_byte)
        })
        .cloned()
        .collect();
    Some(ScalaHierarchyOwnerContext {
        supertype_lookup_paths,
        imports,
    })
}

fn hierarchy_import_claims_root(
    imports: &[ImportInfo],
    root: &str,
    resolver: &ScalaNameResolver,
    wildcard_baseline: Option<&ScalaNameResolver>,
) -> bool {
    imports.iter().any(|import| {
        !import.is_wildcard
            && import
                .identifier
                .as_deref()
                .is_some_and(|visible| visible == root)
    }) || wildcard_baseline.is_some_and(|baseline| {
        let wildcard_is_newly_ambiguous = (resolver.type_binding_is_ambiguous(root)
            && !baseline.type_binding_is_ambiguous(root))
            || (resolver.object_binding_is_ambiguous(root)
                && !baseline.object_binding_is_ambiguous(root));
        wildcard_is_newly_ambiguous
            || (resolver.resolve(root), resolver.resolve_object(root))
                != (baseline.resolve(root), baseline.resolve_object(root))
    })
}

/// The package scopes one supertype lookup path resolves its root against.
///
/// The scopes the parser established at the owner declaration travel on the
/// path; a path that carries none falls back to the owner's own package. The
/// ancestor graph and the external-root walk both read them here, so one
/// spelled supertype cannot resolve against one package set for a descendant
/// edge and another for an external boundary (#3454).
fn hierarchy_path_package_prefixes(
    path: &ScalaSupertypeLookupPath,
    owner: &CodeUnit,
) -> Vec<String> {
    if path.package_prefixes().is_empty() {
        vec![owner.package_name().to_string()]
    } else {
        path.package_prefixes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::test_support::AnalyzerFixture;

    fn analyzer_with_files(files: &[(&str, &str)]) -> (AnalyzerFixture, ScalaAnalyzer) {
        let fixture = AnalyzerFixture::new_for_language(Language::Scala, files);
        let analyzer = ScalaAnalyzer::from_project(fixture.test_project().clone());
        (fixture, analyzer)
    }

    #[test]
    fn scala_type_relations_distinguish_trait_mixins_from_nominal_inheritance() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            (
                "Types.scala",
                r#"
package app
import lib.External
class Base
trait Runnable
trait Logged
trait Derived extends Logged
class Worker extends Base with Runnable with External
object Singleton extends Runnable
"#,
            ),
            (
                "lib/Types.scala",
                r#"
package lib
trait External
"#,
            ),
        ]);

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let relations = analyzer.type_relations(token);
        assert!(relations.iter().any(|relation| {
            relation.from.fq_name() == "app.Worker"
                && relation.to.fq_name() == "app.Base"
                && relation.kind == TypeRelationKind::NominalInheritance
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.fq_name() == "app.Worker"
                && relation.to.fq_name() == "app.Runnable"
                && relation.kind == TypeRelationKind::TraitImplementation
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.fq_name() == "app.Singleton$"
                && relation.to.fq_name() == "app.Runnable"
                && relation.kind == TypeRelationKind::TraitImplementation
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.fq_name() == "app.Worker"
                && relation.to.fq_name() == "lib.External"
                && relation.kind == TypeRelationKind::TraitImplementation
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.fq_name() == "app.Derived"
                && relation.to.fq_name() == "app.Logged"
                && relation.kind == TypeRelationKind::NominalInheritance
        }));
    }

    /// Reference implementation of the pre-#908 eager whole-workspace descendant
    /// index: resolve every class's ancestors up front and materialize the full
    /// ancestor→descendant graph. Kept test-only to prove the lazy path is
    /// semantically identical.
    fn eager_reference_descendants(
        analyzer: &ScalaAnalyzer,
    ) -> crate::analyzer::DirectDescendantIndex {
        use crate::hash::{HashMap, HashSet};
        let file_states = analyzer.bulk_file_states(
            analyzer.analyzed_files(),
            crate::analyzer::BulkFileStateSource::Omit,
        );
        let mut candidates = Vec::new();
        let mut contexts: HashMap<CodeUnit, ScalaHierarchyOwnerContext> = HashMap::default();
        let mut seen = HashSet::default();
        for state in file_states.values() {
            for candidate in state
                .definition_lookup_units
                .iter()
                .chain(&state.declarations)
                .filter(|candidate| candidate.is_class())
            {
                if seen.insert(candidate.clone()) {
                    candidates.push(candidate.clone());
                }
                if let Some(context) = hierarchy_owner_context_from_state(state, candidate) {
                    contexts.insert(candidate.clone(), context);
                }
            }
        }
        let types = analyzer.project_types_from_file_states(file_states);
        let mut ancestors_by_owner: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
        for candidate in &candidates {
            let ancestors = contexts
                .get(candidate)
                .map(|context| {
                    let scope = AnalyzerQueryScope::new(analyzer);
                    let token = scope.token();
                    analyzer.resolve_direct_ancestor_units_with_context(
                        token, candidate, &types, context,
                    )
                })
                .unwrap_or_default();
            ancestors_by_owner.insert(candidate.clone(), ancestors);
        }
        crate::analyzer::capabilities::build_direct_descendant_index_from_candidates(
            candidates,
            |candidate| {
                Some(
                    ancestors_by_owner
                        .get(candidate)
                        .cloned()
                        .unwrap_or_default(),
                )
            },
            &|| true,
        )
        .expect("a reference index that cannot stop always completes")
    }

    fn sorted_fq_names(units: &crate::hash::HashSet<CodeUnit>) -> Vec<String> {
        let mut names: Vec<String> = units.iter().map(CodeUnit::fq_name).collect();
        names.sort();
        names
    }

    #[test]
    fn scala_lazy_descendants_match_eager_reference_index() {
        // Tricky shapes: cross-file inheritance, type/package aliases, wildcard
        // imports, companion objects, and a multi-level chain.
        let files: &[(&str, &str)] = &[
            (
                "lib/Types.scala",
                "package lib\nclass Base\ntrait Runnable\n",
            ),
            (
                "root/api/Types.scala",
                "package root.api\nclass PackageBase\n",
            ),
            (
                "alias/Children.scala",
                "package alias\nimport lib.Base as Parent\nimport lib.Runnable\nimport root.{api => classic}\nclass First extends Parent with Runnable\nclass Second extends Parent\nclass Third extends Parent\nclass PackageAliasChild extends classic.PackageBase\n",
            ),
            (
                "wild/Child.scala",
                "package wild\nimport lib._\nclass WildcardChild extends Base with Runnable\n",
            ),
            (
                "same/Types.scala",
                "package same\nclass Peer\nclass SamePackageChild extends Peer\n",
            ),
            (
                "companion/Types.scala",
                "package companion\nclass Foo\nobject Foo { trait Base }\nclass Child extends Foo.Base\nobject Bases { trait StableBase }\nimport Bases.*\nclass StableWildcardChild extends StableBase\n",
            ),
            (
                "chain/Chain.scala",
                "package chain\nclass A\nclass B extends A\nclass C extends B\nclass D extends C\n",
            ),
            (
                "aliastype/Alias.scala",
                "package aliastype\nimport lib.Base\ntype Renamed = Base\nclass ViaTypeAlias extends Renamed\n",
            ),
        ];

        // One analyzer so both paths key on the same declaration identities;
        // the eager reference builds its own standalone index and does not touch
        // the lazy `get_direct_descendants` path or its cache priming.
        let (_fixture, analyzer) = analyzer_with_files(files);
        let eager = eager_reference_descendants(&analyzer);

        let all_classes: Vec<CodeUnit> = analyzer
            .all_declarations()
            .filter(CodeUnit::is_class)
            .collect();
        assert!(
            all_classes.len() >= 15,
            "fixture should exercise many classes"
        );

        let mut agreements = 0usize;
        for unit in &all_classes {
            let lazy = sorted_fq_names(&analyzer.get_direct_descendants(unit));
            let reference = sorted_fq_names(&eager.descendants(unit));
            assert_eq!(
                lazy,
                reference,
                "descendant mismatch for {}",
                unit.fq_name()
            );
            if !lazy.is_empty() {
                agreements += 1;
            }
        }
        assert!(
            agreements >= 5,
            "differential must cover several non-empty descendant sets, saw {agreements}"
        );
    }
}
