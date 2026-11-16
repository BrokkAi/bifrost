use crate::analyzer::scala::*;
use brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer;

use brokk_bifrost_core::analyzer::model::ImportInfo;

use crate::analyzer::jvm::external::JvmExternalDeclarations;
use crate::analyzer::jvm::external::QueryGapRecorder;

use brokk_bifrost_core::analyzer::type_relations::TypeRelation;

use brokk_bifrost_core::analyzer::type_relations::TypeRelationKind;

use brokk_bifrost_jvm::scala::graph::inverted::NameResolver as ScalaNameResolver;

use brokk_bifrost_jvm::scala::graph::inverted::ProjectTypes as ScalaProjectTypes;

use brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyAnswer;

use brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyIncompleteReason;

use brokk_bifrost_analysis::analyzer::usages::member_family::ExternalMemberFamilyStatus;

use brokk_bifrost_jvm::realm::JvmExternalMemberIdentity;

use brokk_bifrost_jvm::realm::JvmReceiverSemantics;

use brokk_bifrost_analysis::analyzer::usages::member_family::MemberFacts;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryScope;
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

/// Where one written supertype of a Scala template lands, independent of any
/// queried external root (#3454, #11162).
///
/// The landing depends on the template's file, the snapshot, the dependency
/// artifacts and the active model set, never on the root a family query asks
/// about, so one resolution per template serves every external root.
#[derive(Debug, Clone)]
pub(crate) enum ScalaSupertypeLanding {
    /// Every workspace template the spelling can denote. More than one means
    /// the workspace tier named one type that several declarations share, and
    /// the walk keeps all of them as possible ancestors rather than dropping
    /// the edge.
    Workspace(Vec<CodeUnit>),
    /// The workspace tier named a type it cannot pin to a template: no class
    /// declaration, or a type alias, whose target this walk does not follow.
    /// A family that reads it stays open.
    Unsettled(String),
    /// The workspace declares nothing under the spelling, so only the shared
    /// external surface can name it.
    External(ScalaExternalSupertype),
}

/// A written supertype that only the shared external surface can name.
#[derive(Debug, Clone)]
pub(crate) struct ScalaExternalSupertype {
    /// The written name, without a leading `_root_`.
    spelling: String,
    /// The external type the shared declaration ladder binds, or `None` when
    /// nothing it reads declares one. Not read for an ambiguous spelling.
    identity: Option<String>,
    /// For a bare spelling that no explicit import binds, every wildcard
    /// namespace in scope when there is more than one; otherwise empty.
    open_wildcard_namespaces: Vec<String>,
    /// The external types those namespaces bind the spelling to on the surface.
    wildcard_bindings: Vec<String>,
}

impl ScalaExternalSupertype {
    /// Whether more than one visible wildcard import could bind the spelling,
    /// so which declaration it denotes cannot be told.
    ///
    /// Scala refuses to pick between two wildcard imports that both bind one
    /// name. The shared surface only reports what its artifacts and activated
    /// packs declare, so a namespace whose dependency the surface has not
    /// indexed could still bind the name: the landing is then unproven rather
    /// than settled by import order. A namespace that spells the queried root
    /// itself counts even when the surface does not index the root.
    fn ambiguous_for(&self, external_root_fqn: &str) -> bool {
        !self.open_wildcard_namespaces.is_empty()
            && (!self.wildcard_bindings.is_empty() || self.wildcard_names_root(external_root_fqn))
    }

    fn wildcard_names_root(&self, external_root_fqn: &str) -> bool {
        self.open_wildcard_namespaces
            .iter()
            .any(|namespace| format!("{namespace}.{}", self.spelling) == external_root_fqn)
    }

    fn heap_bytes(&self) -> usize {
        self.spelling.len()
            + self.identity.as_ref().map_or(0, String::len)
            + self
                .open_wildcard_namespaces
                .iter()
                .chain(&self.wildcard_bindings)
                .map(|name| std::mem::size_of::<String>() + name.len())
                .sum::<usize>()
    }
}

impl ScalaSupertypeLanding {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + match self {
                Self::Workspace(definitions) => definitions
                    .iter()
                    .map(|definition| {
                        usize::try_from(
                            brokk_bifrost_analysis::analyzer::cache_weight::estimate_code_unit(
                                definition,
                            ),
                        )
                        .unwrap_or(usize::MAX)
                    })
                    .fold(0, usize::saturating_add),
                Self::Unsettled(fqn) => fqn.len(),
                Self::External(supertype) => supertype.heap_bytes(),
            }
    }
}

/// The landings of every written supertype of one template, or `None` when its
/// hierarchy facts cannot be read.
pub(crate) type ScalaSupertypeLandings = Option<Vec<ScalaSupertypeLanding>>;

/// The model-set digest a landing is keyed by: activated packs can declare the
/// external types a spelling names.
type ScalaLandingModels = Option<brokk_bifrost_analysis::analyzer::semantic::StableDigest>;

pub(crate) type ScalaSupertypeLandingMemo = crate::analyzer::jvm::hierarchy::DerivedMemo<
    (ScalaLandingModels, CodeUnit),
    ScalaSupertypeLandings,
>;

impl ScalaAnalyzer {
    fn legacy_direct_ancestors(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        HierarchyAnswer::complete(crate::analyzer::jvm::hierarchy::memoized_ancestors(
            &self.direct_ancestors,
            self,
            code_unit,
            || self.resolve_direct_ancestors(token, code_unit),
        ))
    }
}

impl TypeHierarchyProvider for ScalaAnalyzer {
    fn with_hierarchy_query(
        &self,
        run: &mut dyn FnMut(&mut dyn brokk_bifrost_core::analyzer::capabilities::HierarchyQuery),
    ) {
        #[cfg(any(test, feature = "test-support"))]
        if std::env::var_os("BIFROST_TRIAL_NATIVE_SCALA").is_some() {
            self.native_hierarchy_query(None, run);
            return;
        }
        run(&mut brokk_bifrost_core::analyzer::capabilities::ForwardingHierarchyQuery(self));
    }

    fn with_hierarchy_query_for(
        &self,
        _root: &CodeUnit,
        run: &mut dyn FnMut(&mut dyn brokk_bifrost_core::analyzer::capabilities::HierarchyQuery),
    ) {
        #[cfg(any(test, feature = "test-support"))]
        if std::env::var_os("BIFROST_TRIAL_NATIVE_SCALA").is_some() {
            self.native_hierarchy_query(Some(_root), run);
            return;
        }
        run(&mut brokk_bifrost_core::analyzer::capabilities::ForwardingHierarchyQuery(self));
    }

    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        #[cfg(any(test, feature = "test-support"))]
        if std::env::var_os("BIFROST_TRIAL_NATIVE_SCALA").is_some() {
            let mut answer = None;
            self.with_hierarchy_query_for(code_unit, &mut |query| {
                answer = Some(query.direct_ancestors(code_unit))
            });
            return answer.expect("hierarchy query runs once");
        }
        self.legacy_direct_ancestors(code_unit)
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HierarchyAnswer {
        let uncancelled = brokk_bifrost_core::cancellation::CancellationToken::default();
        self.get_direct_descendants_within(
            code_unit,
            &brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope::whole_workspace(
                &uncancelled,
            ),
        )
        .expect("an uncancelled descendant query cannot be cancelled")
    }

    /// Scala keeps one index, not one per [`brokk_bifrost_analysis::analyzer::DescendantIndexVariant`].
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
        scope: &brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope<'_>,
    ) -> Result<HierarchyAnswer, brokk_bifrost_core::analyzer::capabilities::Cancelled> {
        #[cfg(any(test, feature = "test-support"))]
        if std::env::var_os("BIFROST_TRIAL_NATIVE_SCALA").is_some() {
            if scope.cancellation().is_cancelled() {
                return Err(brokk_bifrost_core::analyzer::capabilities::Cancelled);
            }
            let mut answer = None;
            self.with_hierarchy_query_for(code_unit, &mut |query| {
                answer = Some(query.direct_descendants_within(code_unit, scope));
            });
            return answer.expect("hierarchy query runs once");
        }

        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        if scope.cancellation().is_cancelled() {
            return Err(brokk_bifrost_core::analyzer::capabilities::Cancelled);
        }
        self.lazy_hierarchy_index.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_arc_cell(
                    self,
                    memo,
                    || self.build_lazy_hierarchy_index(),
                )
                .direct_descendants_while(token, self, code_unit, scope)
            },
            |_| {
                brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs::SourceOf(&[
                    Language::Scala,
                ])
            },
        ).ok_or(brokk_bifrost_core::analyzer::capabilities::Cancelled).map(|descendants| {
            let mut edges: Vec<_> = descendants.into_iter().collect();
            edges.sort();
            HierarchyAnswer::complete(edges)
        })
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
        scope: &brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope<'_>,
    ) -> Option<HashSet<CodeUnit>> {
        if !owner.is_class() {
            return Some(HashSet::default());
        }
        let simple = brokk_bifrost_jvm::scala::scala_simple_type_name(owner);
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
        Arc::new(crate::analyzer::jvm::hierarchy::memoized_ancestors(
            &scala.direct_ancestors,
            scala,
            candidate,
            // Read project types and this owner's context inside the retained
            // ancestor fill; the lazy candidate index may have incomplete inputs.
            || scala.resolve_direct_ancestors(token, candidate),
        ))
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
        let _scope =
            brokk_bifrost_core::profiling::scope("ScalaAnalyzer::build_lazy_hierarchy_index");
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
        // Seed the analyzer's retained project types from the states this pass
        // already read, so the ancestor resolutions that follow do not sweep
        // the workspace a second time.
        self.project_types_from_file_states(file_states);

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
            types_by_fq_name,
            candidates_by_supertype_simple,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn type_relations(&self, token: QueryToken<'_>) -> Arc<Vec<TypeRelation>> {
        self.type_relations.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_arc_cell(
                    self,
                    memo,
                    || self.collect_type_relations(token),
                )
            },
            |_| {
                brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs::SourceOf(&[
                    Language::Scala,
                ])
            },
        )
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
    /// The walk uses Scala's own structured hierarchy. Every indexed template's
    /// written supertypes land through [`Self::supertype_landings`]: the tier
    /// ladder the ancestor graph reads decides which land in the workspace, and
    /// the shared external declaration ladder names the rest. A template can
    /// sit below the root through external intermediates it never names
    /// (`class Foo extends dep.Base`, where `dep.Base` extends the root), so
    /// every external landing is followed through the shared
    /// [`brokk_bifrost_jvm::ExternalSupertypeClosure`] that the Java and Kotlin
    /// walks read (#11162). A supertype nothing resolves keeps the proven
    /// candidates and leaves the family open. The closure over
    /// workspace-to-workspace edges is iterative so a deep tree cannot recurse.
    pub(crate) fn resolve_external_member_family(
        &self,
        analyzer: &dyn IAnalyzer,
        identity: &JvmExternalMemberIdentity,
        max_visits: usize,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    ) -> ExternalMemberFamilyAnswer {
        if identity.language() != Language::Scala {
            return ExternalMemberFamilyAnswer::unsupported();
        }
        if cancellation
            .is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled)
        {
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
        let _scope =
            brokk_bifrost_core::profiling::scope("ScalaAnalyzer::resolve_external_member_family");
        let index = self.lazy_hierarchy_index.read(
            &brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(self),
            |memo| {
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_arc_cell(
                    self,
                    memo,
                    || self.build_lazy_hierarchy_index(),
                )
            },
            |_| {
                brokk_bifrost_analysis::analyzer::workspace_authority::AuthorityInputs::SourceOf(&[
                    Language::Scala,
                ])
            },
        );
        let scan = index.class_candidate_count();
        if scan > max_visits {
            return ExternalMemberFamilyAnswer::stopped(
                ExternalMemberFamilyStatus::BudgetExhausted,
                0,
            );
        }
        let mut visited = scan;
        let external_root_fqn = identity.owner_fqn();
        if index.types_by_fq_name.contains_key(external_root_fqn) {
            // The workspace declares the queried external name itself, so a
            // workspace template below that name cannot be told from the
            // external root.
            return ExternalMemberFamilyAnswer::incomplete(
                ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
                visited,
            );
        }

        let packs = analyzer.semantic_model_overlay();
        let models = packs.as_ref().map(|overlay| {
            brokk_bifrost_analysis::analyzer::semantic::StableDigest::sha256(
                overlay.active_model_set_hash(),
            )
        });
        let external = self.external_declarations(packs.clone());
        let recorder = QueryGapRecorder::new(self);
        let query_scope = AnalyzerQueryScope::new(self);
        let token = query_scope.token();
        let mut templates = index.contexts.iter().collect::<Vec<_>>();
        templates.sort_by_key(|(template, _)| *template);
        let positions = templates
            .iter()
            .enumerate()
            .map(|(position, (template, _))| (*template, position))
            .collect::<HashMap<_, _>>();
        let mut workspace_edges = vec![Vec::new(); templates.len()];
        let mut external_descendants = Vec::new();
        // Set by a supertype nothing resolves, which may hide another
        // overrider; the walk keeps the descendants it proves around it.
        let mut open = false;
        let mut closure = brokk_bifrost_jvm::ExternalSupertypeClosure::default();
        for (position, (template, context)) in templates.iter().enumerate() {
            if cancellation
                .is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled)
            {
                return ExternalMemberFamilyAnswer::stopped(
                    ExternalMemberFamilyStatus::Cancelled,
                    visited,
                );
            }
            if context.supertype_lookup_paths.len() > max_visits.saturating_sub(visited) {
                return ExternalMemberFamilyAnswer::stopped(
                    ExternalMemberFamilyStatus::BudgetExhausted,
                    visited,
                );
            }
            visited += context.supertype_lookup_paths.len();
            let landings = self.supertype_landings(token, &packs, models, template);
            let Some(landings) = landings.as_ref() else {
                return ExternalMemberFamilyAnswer::incomplete(
                    ExternalMemberFamilyIncompleteReason::HierarchyFactsUnavailable,
                    visited,
                );
            };
            for landing in landings {
                match landing {
                    ScalaSupertypeLanding::Workspace(ancestors) => {
                        for ancestor in ancestors {
                            let ancestor = index.reconcile_ancestor(ancestor, template);
                            if let Some(&ancestor) = positions.get(&ancestor) {
                                workspace_edges[ancestor].push(position);
                            }
                        }
                    }
                    ScalaSupertypeLanding::Unsettled(_) => open = true,
                    ScalaSupertypeLanding::External(supertype)
                        if supertype.ambiguous_for(external_root_fqn) =>
                    {
                        // Which type the spelling denotes cannot be told. When
                        // the root or a type below it is one of the possible
                        // bindings, the template may sit below the root and
                        // the family is refused; otherwise an unindexed
                        // namespace could still bind the name, so the family
                        // stays open.
                        if supertype.wildcard_names_root(external_root_fqn) {
                            return ExternalMemberFamilyAnswer::incomplete(
                                ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
                                visited,
                            );
                        }
                        for binding in &supertype.wildcard_bindings {
                            match closure.reaches_root(
                                binding,
                                external_root_fqn,
                                &mut visited,
                                max_visits,
                                cancellation,
                                |binding| Some(binding.to_owned()),
                                |identity| external.hierarchy_supertypes(&recorder, identity),
                            ) {
                                Ok(answer) if answer.reaches_root => {
                                    return ExternalMemberFamilyAnswer::incomplete(
                                        ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
                                        visited,
                                    );
                                }
                                Ok(_) => {}
                                Err(stop) => return external_closure_stopped(stop, visited),
                            }
                        }
                        open = true;
                    }
                    ScalaSupertypeLanding::External(supertype) => {
                        match closure.reaches_root(
                            &supertype.spelling,
                            external_root_fqn,
                            &mut visited,
                            max_visits,
                            cancellation,
                            |_| supertype.identity.clone(),
                            |identity| external.hierarchy_supertypes(&recorder, identity),
                        ) {
                            Ok(answer) => {
                                if answer.reaches_root {
                                    external_descendants.push(position);
                                }
                                open |= answer.unresolved_supertype.is_some();
                            }
                            Err(stop) => return external_closure_stopped(stop, visited),
                        }
                    }
                }
            }
        }

        let Some(descendants) = brokk_bifrost_jvm::hierarchy_descendants_from_edges(
            &templates,
            &workspace_edges,
            external_descendants,
            cancellation,
            |(template, _)| *template,
        ) else {
            return ExternalMemberFamilyAnswer::stopped(
                ExternalMemberFamilyStatus::Cancelled,
                visited,
            );
        };

        let mut candidates = Vec::new();
        for descendant in &descendants {
            if cancellation
                .is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled)
            {
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
            // A supertype nothing resolves may hide another overrider: keep the
            // proven candidates as targets, but never claim the family
            // complete, as the Java and Kotlin walks do (#10497).
            status: if open {
                ExternalMemberFamilyStatus::Incomplete(
                    ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
                )
            } else {
                ExternalMemberFamilyStatus::Complete
            },
            candidates,
            visited,
        }
    }

    /// Where every written supertype of `template` lands (#11162).
    ///
    /// The answer depends on the template's file, the snapshot, the
    /// dependency artifacts and the active model set, never on the root a
    /// family query asks about. It is memoized per analyzer generation under
    /// the model-set digest, and every hit replays the reads of its
    /// resolution. Following external intermediates needs every template's
    /// landings, and one resolution builds name bindings over the template's
    /// packages, so resolving them again in every family query would cost
    /// calls times workspace templates, the cost Java's #11517 removed.
    fn supertype_landings(
        &self,
        token: QueryToken<'_>,
        packs: &Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        models: ScalaLandingModels,
        template: &CodeUnit,
    ) -> Arc<ScalaSupertypeLandings> {
        crate::analyzer::jvm::hierarchy::derived_read(
            &self.supertype_landings,
            self,
            &(models, template.clone()),
            || {
                let landings = self.resolve_supertype_landings(token, packs.clone(), template);
                let bytes = std::mem::size_of::<(ScalaLandingModels, CodeUnit)>()
                    + usize::try_from(
                        brokk_bifrost_analysis::analyzer::cache_weight::estimate_code_unit(
                            template,
                        ),
                    )
                    .unwrap_or(usize::MAX)
                    + landings
                        .iter()
                        .flatten()
                        .map(ScalaSupertypeLanding::retained_bytes)
                        .sum::<usize>();
                (Arc::new(landings), bytes)
            },
        )
    }

    fn resolve_supertype_landings(
        &self,
        token: QueryToken<'_>,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        template: &CodeUnit,
    ) -> ScalaSupertypeLandings {
        // Read the template's own context and the project types inside the
        // retained fill, as the ancestor memo does, so the entry's receipt
        // names every input of its landings.
        let state = self.inner.fetch_file_state(template.source())?;
        let context = hierarchy_owner_context_from_state(&state, template)?;
        let types = self.project_types();
        let external = self.external_declarations(packs);
        Some(
            context
                .supertype_lookup_paths
                .iter()
                .map(|path| {
                    let Some(fqn) = self
                        .resolve_hierarchy_supertype_fqn(token, template, &types, &context, path)
                    else {
                        return ScalaSupertypeLanding::External(self.external_supertype(
                            &external,
                            template,
                            &context.imports,
                            path,
                        ));
                    };
                    let definitions =
                        match types.exact_type_declaration_for_owner_context(&fqn, template) {
                            ScalaTypeNamespaceResolution::Resolved(definition) => vec![definition],
                            ScalaTypeNamespaceResolution::Ambiguous(definitions) => definitions,
                            ScalaTypeNamespaceResolution::NoMatch
                            | ScalaTypeNamespaceResolution::AuthoritativeMiss => Vec::new(),
                        };
                    // This walk does not follow a type alias to its target.
                    if definitions.is_empty()
                        || definitions
                            .iter()
                            .any(|definition| self.is_type_alias(definition))
                    {
                        ScalaSupertypeLanding::Unsettled(fqn)
                    } else {
                        ScalaSupertypeLanding::Workspace(definitions)
                    }
                })
                .collect(),
        )
    }

    /// The external type one written supertype of `template` names once the
    /// indexed workspace has declined to name it (#3454).
    ///
    /// The workspace tier ran first, so only the shared external declaration
    /// ladder can name the spelling. That ladder is
    /// [`Self::external_type_spelling_in`], the same one the receiver-typing
    /// and boundary-evidence paths read, so a class extending a type and a
    /// receiver of that type cannot disagree about one spelling.
    ///
    /// A miss is not a proof of absence: a supertype the surface does not
    /// answer has no identity, never an invented one, and a family that reads
    /// it stays open. A bare spelling a wildcard import could bind is recorded
    /// with the wildcard namespaces in scope, and what they bind, when there
    /// are several, because a dependency the surface has not indexed could
    /// still bind the name. The family query refuses such a spelling when one
    /// possible binding is the root or sits below it, the refusal Java's
    /// external-root walk makes for an ambiguous supertype.
    fn external_supertype(
        &self,
        external: &JvmExternalDeclarations<'_>,
        template: &CodeUnit,
        imports: &[ImportInfo],
        path: &ScalaSupertypeLookupPath,
    ) -> ScalaExternalSupertype {
        let segments = path.segments();
        // `_root_.a.b.C` names the root package absolutely; the shared ladder
        // reads written qualified names, so the marker itself is not a segment.
        let segments = if segments.first().is_some_and(|root| root == "_root_") {
            &segments[1..]
        } else {
            segments
        };
        let mut supertype = ScalaExternalSupertype {
            spelling: segments.join("."),
            identity: None,
            open_wildcard_namespaces: Vec::new(),
            wildcard_bindings: Vec::new(),
        };
        let recorder = QueryGapRecorder::new(self);
        if segments.is_empty() || external.empty_surface(&recorder) {
            return supertype;
        }
        let spelling = supertype.spelling.as_str();
        let package_name = template.package_name();
        // An explicit import or a written qualified name settles the spelling
        // on its own; only a bare spelling no explicit tier binds is open to
        // several wildcard namespaces at once.
        let explicitly_bound = imports
            .iter()
            .any(|import| !import.is_wildcard && import.local_name() == Some(spelling));
        if !spelling.contains('.') && !explicitly_bound {
            supertype.open_wildcard_namespaces =
                open_wildcard_namespaces(&hierarchy_path_package_prefixes(path, template), imports);
        }
        supertype.wildcard_bindings = supertype
            .open_wildcard_namespaces
            .iter()
            .filter_map(|namespace| {
                external
                    .resolve_wildcard_import(&recorder, namespace, spelling, package_name)
                    .map(|external_type| external_type.fqn().to_owned())
            })
            .collect();
        if supertype.wildcard_bindings.is_empty() {
            supertype.identity = self
                .external_type_spelling_in(external, package_name, spelling, imports)
                .map(|external_type| external_type.fqn().to_owned());
        }
        supertype
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

fn external_closure_stopped(
    stop: brokk_bifrost_jvm::ExternalSupertypeClosureStop,
    visited: usize,
) -> ExternalMemberFamilyAnswer {
    ExternalMemberFamilyAnswer::stopped(
        match stop {
            brokk_bifrost_jvm::ExternalSupertypeClosureStop::Cancelled => {
                ExternalMemberFamilyStatus::Cancelled
            }
            brokk_bifrost_jvm::ExternalSupertypeClosureStop::BudgetExhausted => {
                ExternalMemberFamilyStatus::BudgetExhausted
            }
        },
        visited,
    )
}

/// The wildcard namespaces in scope at a declaration when more than one could
/// bind a bare supertype spelling; empty when at most one is in scope.
fn open_wildcard_namespaces(package_prefixes: &[String], imports: &[ImportInfo]) -> Vec<String> {
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
        namespaces.clear();
    }
    namespaces
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

impl ScalaAnalyzer {
    #[cfg(any(test, feature = "test-support"))]
    fn native_hierarchy_query(
        &self,
        root: Option<&CodeUnit>,
        run: &mut dyn FnMut(&mut dyn brokk_bifrost_core::analyzer::capabilities::HierarchyQuery),
    ) {
        use brokk_bifrost_core::analyzer::capabilities::UnreadMemberFamilyAncestor;
        use brokk_bifrost_jvm::intrinsics::overridable_method_inventory;
        let _scope = AnalyzerQueryScope::new(self);
        crate::analyzer::jvm::native_hierarchy::with_native_query(
            self.tree_sitter_analyzer(),
            root,
            &mut |owner, parents| self.normalize_native_parents(owner, parents),
            &mut |owner, parents| {
                self.normalize_native_parents(owner, parents);
                for parent in parents {
                    if let Some(root) = &parent.intrinsic_root
                        && root.owner_fqn.as_ref() == "scala.AnyRef"
                    {
                        // The scala package declares `type AnyRef = java.lang.Object`,
                        // so AnyRef contributes exactly Object's overridable methods.
                        parent.unread.push(UnreadMemberFamilyAncestor {
                            name: root.owner_fqn.to_string(),
                            inventory: overridable_method_inventory("java.lang.Object"),
                        });
                    }
                }
            },
            run,
        );
    }
    #[cfg(any(test, feature = "test-support"))]
    fn normalize_native_parents(
        &self,
        owner: &CodeUnit,
        parents: &mut Vec<crate::analyzer::jvm::native_hierarchy::MappedParent>,
    ) {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSupertypeKind;
        let no_written_parent = parents
            .iter()
            .all(|parent| parent.kind == Some(ResolutionSupertypeKind::ImplicitSuperclass));
        let first = parents
            .iter_mut()
            .filter(|parent| parent.kind == Some(ResolutionSupertypeKind::Superclass))
            .min_by_key(|parent| parent.ordinal);
        let trait_first = if !self.is_scala_trait_declaration(owner)
            && let Some(first) = first
            && first.complete
            && first.alternatives == 1
            && let [target] = first.targets.as_slice()
            && self.is_scala_trait_declaration(target)
        {
            true
        } else {
            false
        };
        if trait_first {
            parents
                .iter_mut()
                .filter(|parent| parent.kind == Some(ResolutionSupertypeKind::Superclass))
                .min_by_key(|parent| parent.ordinal)
                .expect("trait first parent exists")
                .kind = Some(ResolutionSupertypeKind::Interface);
        }
        if (trait_first || no_written_parent)
            && !parents.iter().any(|parent| {
                parent
                    .intrinsic_root
                    .as_ref()
                    .is_some_and(|owner| owner.owner_fqn.as_ref() == "scala.AnyRef")
            })
        {
            parents.push(crate::analyzer::jvm::native_hierarchy::MappedParent {
                kind: Some(ResolutionSupertypeKind::ImplicitSuperclass),
                ordinal: 0,
                targets: Vec::new(),
                // Like the native Java implicit Object root, this intrinsic
                // superclass has no source edge and does not open the answer.
                unread: Vec::new(),
                intrinsic_root: Some(
                    brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_direct_supertypes::jvm_intrinsic_parent(
                        brokk_bifrost_core::analyzer::model::Language::Scala,
                        Some(ResolutionSupertypeKind::ImplicitSuperclass),
                    ).expect("Scala's language-defined implicit superclass is intrinsic"),
                ),
                alternatives: 1,
                complete: true,
            });
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::analyzer::scala::hierarchy::*;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    use brokk_bifrost_test_macros::hardwon;

    fn analyzer_with_files(files: &[(&str, &str)]) -> (AnalyzerFixture, ScalaAnalyzer) {
        let fixture = AnalyzerFixture::new_for_language(Language::Scala, files);
        let analyzer = ScalaAnalyzer::from_project(fixture.test_project().clone());
        (fixture, analyzer)
    }

    /// Templates below `java.io.InputStream` through external intermediates:
    /// one hop, two hops, an `object` and a workspace subtype. `Elsewhere`
    /// reaches another root, and `Shadow` extends a workspace type that only
    /// shares the root's simple name.
    const BELOW_EXTERNAL_INTERMEDIATES: &str = r#"package app
class Foo extends org.example.Base { override def close(): Unit = () }
class Child extends Foo { override def close(): Unit = () }
class Two extends org.example.Deeper { override def close(): Unit = () }
object Single extends org.example.Base { override def close(): Unit = () }
class Elsewhere extends org.example.Other { override def close(): Unit = () }
class InputStream { def close(): Unit = () }
class Shadow extends InputStream { override def close(): Unit = () }
"#;

    #[test]
    #[hardwon(
        "#11162: Scala external families claimed Complete while missing overrides below external intermediates"
    )]
    fn scala_external_intermediate_jar_closure() {
        use crate::analyzer::jvm::external::{TestClassFile, write_test_class_jar};
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_core::analyzer::config::{
            AnalyzerConfig, JvmAnalyzerConfig, JvmExternalArtifact, JvmExternalDependencies,
        };

        let class = |internal_name, super_internal_name| TestClassFile {
            internal_name,
            super_internal_name,
            methods: &[],
            private_nested: false,
        };
        let imported = (
            "app/Imported.scala",
            "package app\nimport org.example.Base\nclass Imported extends Base { override def close(): Unit = () }\n",
        );
        let direct = (
            "app/Direct.scala",
            "package app\nclass Direct extends java.io.InputStream { override def read(): Int = -1; override def close(): Unit = () }\n",
        );
        let lost = (
            "app/Lost.scala",
            "package app\nclass Lost extends missing.Gone { def close(): Unit = () }\n",
        );
        let root_declared = (
            "java/io/InputStream.scala",
            "package java.io\nclass InputStream\n",
        );
        // One wildcard import from a named package opens two namespaces
        // (`app.org.example` and `org.example`), so a bare spelling it binds
        // is ambiguous.
        let ambiguous_below = (
            "app/AmbiguousBelow.scala",
            "package app\nimport org.example._\nclass AmbiguousBelow extends Deeper { override def close(): Unit = () }\n",
        );
        let ambiguous_elsewhere = (
            "app/AmbiguousElsewhere.scala",
            "package app\nimport org.example._\nclass AmbiguousElsewhere extends Other { override def close(): Unit = () }\n",
        );
        // The walk does not follow a type alias, so a template that extends
        // one leaves the family open instead of dropping the edge.
        let aliased = (
            "app/Aliased.scala",
            "package app\ntype AliasBase = org.example.Base\nclass ViaAlias extends AliasBase { override def close(): Unit = () }\n",
        );
        let ambiguous_root = (
            "wild/Wild.scala",
            "package wild\nimport java.io._\nclass Wild extends InputStream { override def close(): Unit = () }\n",
        );
        // Two workspace files declare `app.Shared`; the walk keeps both
        // declarations as possible ancestors of `Dup`, so `Dup` stays a
        // candidate in a Complete family even though one declaration is not
        // below the root.
        let shared_below = (
            "app/SharedBelow.scala",
            "package app\nclass Shared extends org.example.Base\n",
        );
        let shared_plain = ("app/SharedPlain.scala", "package app\nclass Shared\n");
        let duplicate_child = (
            "app/Dup.scala",
            "package app\nclass Dup extends Shared { override def close(): Unit = () }\n",
        );
        let below = [
            "app.Child.close",
            "app.Foo.close",
            "app.Imported.close",
            "app.Single$.close",
            "app.Two.close",
        ];
        let with_direct = || {
            let mut names = below.to_vec();
            names.push("app.Direct.close");
            names.sort();
            names
        };
        let with_duplicate = || {
            let mut names = below.to_vec();
            names.push("app.Dup.close");
            names.sort();
            names
        };
        let complete = ExternalMemberFamilyStatus::Complete;
        let open = ExternalMemberFamilyStatus::Incomplete(
            ExternalMemberFamilyIncompleteReason::ExternalRootUnresolved,
        );
        /// How a case treats the dependency artifact.
        enum Jar {
            /// No artifact is configured.
            Absent,
            /// The artifact is configured but the file is never written.
            Missing,
            /// The jar holds every class, plus the root when `root_indexed`.
            Full { root_indexed: bool },
            /// The jar holds the root and `Other` chains but not
            /// `org/example/Base` or `org/example/Deeper`.
            WithoutBase,
        }
        // (case, extra files, jar, status, candidates)
        let cases = vec![
            (
                "indexed root",
                vec![imported, direct],
                Jar::Full { root_indexed: true },
                complete,
                with_direct(),
            ),
            (
                "intermediate whose root is outside the jar",
                vec![imported],
                Jar::Full {
                    root_indexed: false,
                },
                complete,
                below.to_vec(),
            ),
            (
                "direct spelling of a root outside the jar",
                vec![imported, direct],
                Jar::Full {
                    root_indexed: false,
                },
                open,
                below.to_vec(),
            ),
            (
                "supertype nothing resolves",
                vec![imported, direct, lost],
                Jar::Full { root_indexed: true },
                open,
                with_direct(),
            ),
            ("no jar", vec![imported], Jar::Absent, open, Vec::new()),
            (
                "configured jar does not exist",
                vec![imported],
                Jar::Missing,
                open,
                Vec::new(),
            ),
            (
                "jar without the intermediate",
                vec![imported, direct],
                Jar::WithoutBase,
                open,
                vec!["app.Direct.close"],
            ),
            (
                "workspace declares the root",
                vec![imported, root_declared],
                Jar::Full { root_indexed: true },
                open,
                Vec::new(),
            ),
            (
                "ambiguous wildcard below the root",
                vec![imported, ambiguous_below],
                Jar::Full { root_indexed: true },
                open,
                Vec::new(),
            ),
            (
                "ambiguous wildcard naming the root",
                vec![imported, ambiguous_root],
                Jar::Full { root_indexed: true },
                open,
                Vec::new(),
            ),
            (
                "type alias",
                vec![imported, aliased],
                Jar::Full { root_indexed: true },
                open,
                below.to_vec(),
            ),
            (
                "duplicate workspace declarations of a supertype",
                vec![imported, shared_below, shared_plain, duplicate_child],
                Jar::Full { root_indexed: true },
                complete,
                with_duplicate(),
            ),
            (
                "ambiguous wildcard elsewhere",
                vec![imported, ambiguous_elsewhere],
                Jar::Full { root_indexed: true },
                open,
                below.to_vec(),
            ),
        ];
        let input_stream_close = JvmExternalMemberIdentity::new(
            Language::Scala,
            "java.io.InputStream",
            "close",
            0,
            JvmReceiverSemantics::Instance,
        );
        let reader_close = JvmExternalMemberIdentity::new(
            Language::Scala,
            "java.io.Reader",
            "close",
            0,
            JvmReceiverSemantics::Instance,
        );
        for (case, files, jar_mode, status, candidates) in cases {
            let mut project = InlineTestProject::with_language(Language::Scala)
                .file("app/Below.scala", BELOW_EXTERNAL_INTERMEDIATES);
            for (path, source) in files {
                project = project.file(path, source);
            }
            let project = project.build();
            let dir = tempfile::tempdir().unwrap();
            let jar = dir.path().join("dependency.jar");
            let mut artifact_paths = Vec::new();
            let classes = |root_indexed| {
                let mut classes = vec![
                    class("org/example/Base", "java/io/InputStream"),
                    class("org/example/Deeper", "org/example/Base"),
                    class("org/example/Other", "java/io/Reader"),
                    class("java/io/Reader", "java/lang/Object"),
                    class("java/lang/Object", "java/lang/Object"),
                ];
                if root_indexed {
                    classes.push(class("java/io/InputStream", "java/lang/Object"));
                }
                classes
            };
            match jar_mode {
                Jar::Absent => {}
                Jar::Missing => {
                    artifact_paths.push(JvmExternalArtifact {
                        artifact_path: jar.clone(),
                        ..Default::default()
                    });
                }
                Jar::Full { root_indexed } => {
                    write_test_class_jar(&jar, &classes(root_indexed));
                    artifact_paths.push(JvmExternalArtifact {
                        artifact_path: jar.clone(),
                        ..Default::default()
                    });
                }
                Jar::WithoutBase => {
                    write_test_class_jar(
                        &jar,
                        &[
                            class("org/example/Other", "java/io/Reader"),
                            class("java/io/Reader", "java/lang/Object"),
                            class("java/lang/Object", "java/lang/Object"),
                            class("java/io/InputStream", "java/lang/Object"),
                        ],
                    );
                    artifact_paths.push(JvmExternalArtifact {
                        artifact_path: jar.clone(),
                        ..Default::default()
                    });
                }
            }
            let scala = ScalaAnalyzer::new_with_config(
                project.project_dyn(),
                AnalyzerConfig {
                    jvm: JvmAnalyzerConfig {
                        external_dependencies: JvmExternalDependencies {
                            artifact_paths,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
            let family = |identity: &JvmExternalMemberIdentity| {
                let answer =
                    scala.resolve_external_member_family(&scala, identity, usize::MAX, None);
                let mut names = answer
                    .candidates
                    .iter()
                    .map(CodeUnit::fq_name)
                    .collect::<Vec<_>>();
                names.sort();
                (answer.status, names)
            };
            let owned = |names: Vec<&str>| names.into_iter().map(str::to_owned).collect::<Vec<_>>();
            let expected = (status, owned(candidates));
            assert_eq!(family(&input_stream_close), expected, "{case}");
            if case == "type alias" {
                // The alias landing itself is Unsettled: the walk does not
                // follow `type AliasBase = org.example.Base` to its target,
                // which is what leaves the family open.
                let scope = AnalyzerQueryScope::new(&scala);
                let via_alias = scala
                    .declarations(&ProjectFile::new(project.root(), "app/Aliased.scala"))
                    .into_iter()
                    .find(|unit| unit.identifier() == "ViaAlias")
                    .expect("ViaAlias is declared");
                let landings = scala.supertype_landings(scope.token(), &None, None, &via_alias);
                let landings = landings.as_ref().as_ref().expect("landings available");
                assert!(
                    landings.iter().any(
                        |landing| matches!(landing, ScalaSupertypeLanding::Unsettled(fqn) if fqn == "app.AliasBase")
                    ),
                    "{case}: {landings:?}"
                );
            }
            // The memoized landings serve a second root and a warm repeat of
            // the first one. `Elsewhere` is the only template below
            // `java.io.Reader`, and an ambiguous binding below it refuses.
            let reader = match case {
                "indexed root" => (complete, vec!["app.Elsewhere.close"]),
                "supertype nothing resolves" => (open, vec!["app.Elsewhere.close"]),
                "ambiguous wildcard elsewhere" => (open, Vec::new()),
                _ => continue,
            };
            assert_eq!(
                family(&reader_close),
                (reader.0, owned(reader.1)),
                "{case}: java.io.Reader"
            );
            assert_eq!(family(&input_stream_close), expected, "{case}: warm");
        }
    }

    #[test]
    fn scala_external_intermediate_budget_and_cancellation() {
        use crate::analyzer::jvm::external::{TestClassFile, write_test_class_jar};
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_core::analyzer::config::{
            AnalyzerConfig, JvmAnalyzerConfig, JvmExternalArtifact, JvmExternalDependencies,
        };

        let project = InlineTestProject::with_language(Language::Scala)
            .file("app/Below.scala", BELOW_EXTERNAL_INTERMEDIATES)
            .file(
                "app/Direct.scala",
                "package app\nclass Direct extends java.io.InputStream { override def read(): Int = -1; override def close(): Unit = () }\n",
            )
            .build();
        let dir = tempfile::tempdir().unwrap();
        let jar = dir.path().join("dependency.jar");
        let class = |internal_name, super_internal_name| TestClassFile {
            internal_name,
            super_internal_name,
            methods: &[],
            private_nested: false,
        };
        write_test_class_jar(
            &jar,
            &[
                class("org/example/Base", "java/io/InputStream"),
                class("org/example/Deeper", "org/example/Base"),
                class("org/example/Other", "java/io/Reader"),
                class("java/io/Reader", "java/lang/Object"),
                class("java/lang/Object", "java/lang/Object"),
                class("java/io/InputStream", "java/lang/Object"),
            ],
        );
        let scala = ScalaAnalyzer::new_with_config(
            project.project_dyn(),
            AnalyzerConfig {
                jvm: JvmAnalyzerConfig {
                    external_dependencies: JvmExternalDependencies {
                        artifact_paths: vec![JvmExternalArtifact {
                            artifact_path: jar,
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let identity = JvmExternalMemberIdentity::new(
            Language::Scala,
            "java.io.InputStream",
            "close",
            0,
            JvmReceiverSemantics::Instance,
        );
        let full = scala.resolve_external_member_family(&scala, &identity, usize::MAX, None);
        assert_eq!(full.status, ExternalMemberFamilyStatus::Complete);
        assert!(!full.candidates.is_empty());
        // Every budget short of the full walk stops with no candidates: at
        // the template scan when the budget is below it (visited == 0),
        // inside the walk and its external closures otherwise.
        let mut past_scan = false;
        for budget in 0..full.visited {
            let answer = scala.resolve_external_member_family(&scala, &identity, budget, None);
            assert_eq!(
                answer.status,
                ExternalMemberFamilyStatus::BudgetExhausted,
                "budget {budget}"
            );
            assert!(answer.candidates.is_empty(), "budget {budget}");
            past_scan |= answer.visited > 0;
        }
        assert!(
            past_scan,
            "a budget past the template scan stops inside the walk"
        );
        let token = brokk_bifrost_core::cancellation::CancellationToken::new();
        token.cancel();
        let cancelled =
            scala.resolve_external_member_family(&scala, &identity, usize::MAX, Some(&token));
        assert_eq!(cancelled.status, ExternalMemberFamilyStatus::Cancelled);
        assert!(cancelled.candidates.is_empty());
    }

    #[test]
    fn retained_ancestors_read_inputs_instead_of_partial_lazy_contexts() {
        let (fixture, scala) = analyzer_with_files(&[
            ("Base.scala", "class Base"),
            ("Child.scala", "class Child extends Base"),
        ]);
        let child = scala
            .declarations(&ProjectFile::new(
                fixture.test_project().root(),
                "Child.scala",
            ))
            .into_iter()
            .find(|unit| unit.is_class())
            .unwrap();
        let mut index = scala.build_lazy_hierarchy_index();
        // A partial bulk pass may lack an owner's context. That caller-local
        // candidate filter must not become a retained complete ancestor answer.
        assert!(index.contexts.remove(&child).is_some());
        let scope = AnalyzerQueryScope::new(&scala);
        let ancestors = index.ancestors_of(scope.token(), &scala, &child);
        assert!(
            ancestors.iter().any(|unit| unit.identifier() == "Base"),
            "{ancestors:?}"
        );
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
    ) -> brokk_bifrost_core::analyzer::capabilities::DirectDescendantIndex {
        use brokk_bifrost_core::hash::HashMap;

        use brokk_bifrost_core::hash::HashSet;
        let file_states = analyzer.bulk_file_states(
            analyzer.analyzed_files(),
            brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BulkFileStateSource::Omit,
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
        brokk_bifrost_core::analyzer::capabilities::build_direct_descendant_index_from_candidates(
            candidates,
            |candidate| {
                Some(
                    brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer::complete(
                        ancestors_by_owner
                            .get(candidate)
                            .cloned()
                            .unwrap_or_default(),
                    ),
                )
            },
            &|| true,
        )
        .expect("a reference index that cannot stop always completes")
    }

    fn sorted_fq_names(units: &[CodeUnit]) -> Vec<String> {
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
            let index = analyzer.build_lazy_hierarchy_index();
            let token = brokk_bifrost_core::cancellation::CancellationToken::default();
            let scope =
                brokk_bifrost_core::analyzer::capabilities::DescendantIndexScope::whole_workspace(
                    &token,
                );
            let query = AnalyzerQueryScope::new(&analyzer);
            let lazy = sorted_fq_names(
                &index
                    .direct_descendants_while(query.token(), &analyzer, unit, &scope)
                    .unwrap()
                    .into_iter()
                    .collect::<Vec<_>>(),
            );
            let reference =
                sorted_fq_names(&eager.descendants(unit).into_iter().collect::<Vec<_>>());
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
