//! Python workspace and member lookup helpers shared by native and legacy requests.

use crate::analyzer::PythonAnalyzer;
use brokk_bifrost_analysis::analyzer::common::language_for_file;
use brokk_bifrost_analysis::analyzer::usages::get_definition::{self as definition, *};
use brokk_bifrost_analysis::analyzer::{CodeUnit, IAnalyzer, Language, resolve_analyzer};
use brokk_bifrost_core::analyzer::BoundedDefinitionLookup;
use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::definition_lookup::sort_units;
use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::path_utils::rel_path_string;
use brokk_bifrost_python::declarations::python_module_name;
use brokk_bifrost_python::source_support::PythonSource;
use definition::trace;

pub(crate) fn python_member_outcome(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    receiver_type: CodeUnit,
    member: &str,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    // A receiver typed cross-language (#1174) owns members in *its* language's
    // index, not Python's, so the exact-fq member lookup has to follow it there.
    let receiver_language = language_for_file(receiver_type.source());
    let cross_language_owner = receiver_language != Language::Python;
    let mut candidates = support.members_for_owner(&receiver_type, member);
    // The member attribution this seam can name: every candidate was found by
    // asking the index for `<owner fq>.<member>`, so the owner is exactly the
    // type the lookup asked about, and the hop distance is that type's distance
    // from the receiver. Built only while a trace records (#1477).
    let mut attribution = PythonMemberAttribution::default();
    attribution.record_direct(&receiver_type, &candidates);
    if candidates.is_empty()
        && let Some(provider) = analyzer.type_hierarchy_provider()
    {
        // The routes are the walk `get_ancestors` performs, retaining the hop
        // distance and the first-discovery parent it discards.
        let routes = if trace::recording() {
            PythonAncestorRoutes::build(provider, &receiver_type)
        } else {
            PythonAncestorRoutes::default()
        };
        for ancestor in provider.get_ancestors(&receiver_type).definite().to_vec() {
            let found = support.members_for_owner(&ancestor, member);
            attribution.record_inherited(&receiver_type, &ancestor, &found, &routes);
            candidates.extend(found);
        }
        sort_units(&mut candidates);
        candidates.dedup();
    }
    if candidates.is_empty()
        && !cross_language_owner
        && let Some(python) = resolve_analyzer::<PythonAnalyzer>(analyzer)
        && let Some(overlay) = analyzer.semantic_model_overlay()
        && let Some(symbol) =
            crate::analyzer::python::python_external_value_member_on_workspace_class(
                python,
                &receiver_type,
                member,
                &overlay,
            )
    {
        let mut reference = site.clone();
        reference.text = symbol.qualified_name.clone();
        let outcome = DefinitionLookupOutcome {
            modeled_definitions: vec![symbol],
            status: DefinitionLookupStatus::Resolved,
            reference: Some(reference),
            definitions: Vec::new(),
            lexical_definition: None,
            diagnostics: Vec::new(),
        };
        trace::record_selected_modeled(&outcome);
        return outcome;
    }
    if candidates.is_empty() {
        let owner = receiver_type.fq_name();
        let message = if cross_language_owner {
            format!(
                "`{owner}.{member}` is not indexed; `{owner}` is a {} declaration, not a Python one",
                receiver_language.config_label()
            )
        } else {
            format!("`{owner}.{member}` is not indexed as a Python definition")
        };
        no_definition("no_indexed_definition", message)
    } else {
        attribution.stage();
        candidates_outcome(candidates)
    }
}

/// How many ancestor types the recording-only route walk may visit. Mirrors the
/// bound the Java member-family walk applies to the same kind of closure: a
/// diamond or a deep framework hierarchy stays bounded, and a hierarchy that
/// exceeds the bound loses attribution rather than gaining a wrong one.
const MAX_ANCESTOR_FRONTIER: usize = 512;

/// The hop distance and first-discovery parent of every ancestor the Python
/// member walk can reach (#1477).
///
/// `TypeHierarchyProvider::get_ancestors` flattens its breadth-first walk to a
/// list, discarding both facts. This repeats that walk over the same
/// direct-ancestor edges, in the same order and with the same
/// fully-qualified-name deduplication, and retains them. It decides nothing:
/// the production loop still consumes `get_ancestors` unchanged.
///
/// The walk is bounded by [`MAX_ANCESTOR_FRONTIER`]. Truncation removes
/// attribution, never distorts it: breadth-first order fixes every depth at
/// the level it was recorded, so an ancestor the bound cut off simply has no
/// depth and [`PythonAncestorRoutes::route`] returns `None` for it, leaving
/// that candidate unattributed.
#[derive(Default)]
struct PythonAncestorRoutes {
    /// First-discovery parent of each ancestor the walk expanded.
    parents: HashMap<CodeUnit, CodeUnit>,
    /// Breadth-first hop distance from the receiver.
    depths: HashMap<CodeUnit, usize>,
}

impl PythonAncestorRoutes {
    fn build(
        provider: &dyn brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider,
        receiver: &CodeUnit,
    ) -> Self {
        let mut routes = Self::default();
        let mut seen: HashSet<String> = HashSet::default();
        seen.insert(receiver.fq_name());
        let mut level = provider.get_direct_ancestors(receiver).definite().to_vec();
        for ancestor in &level {
            routes
                .parents
                .entry(ancestor.clone())
                .or_insert_with(|| receiver.clone());
        }
        let mut depth = 0usize;
        let mut visited = 0usize;
        'walk: while !level.is_empty() {
            depth += 1;
            let mut next_level = Vec::new();
            for ancestor in level {
                if !seen.insert(ancestor.fq_name()) {
                    continue;
                }
                visited += 1;
                if visited > MAX_ANCESTOR_FRONTIER {
                    // Stop before recording anything about this ancestor. Every
                    // depth already recorded is the breadth-first minimum and
                    // stays correct; the rest of the closure is simply absent,
                    // so its candidates stay unattributed.
                    break 'walk;
                }
                routes.depths.insert(ancestor.clone(), depth);
                let expanded = provider.get_direct_ancestors(&ancestor).definite().to_vec();
                for next in &expanded {
                    routes
                        .parents
                        .entry(next.clone())
                        .or_insert_with(|| ancestor.clone());
                }
                next_level.extend(expanded);
            }
            level = next_level;
        }
        routes
    }

    /// The exact route from `receiver` to `owner`, as first-discovery hops.
    /// Every Python direct-ancestor edge is a base-class edge, so each hop is
    /// [`HierarchyRelation::Extends`]. Returns `None` when the walk never
    /// reached `owner`, which leaves the candidate unattributed rather than
    /// attributed to a route this seam cannot name.
    fn route(
        &self,
        receiver: &CodeUnit,
        owner: &CodeUnit,
    ) -> Option<(usize, Vec<trace::HierarchyHopRecord>)> {
        use brokk_bifrost_core::analyzer::structural::resolution::HierarchyRelation;

        let depth = *self.depths.get(owner)?;
        let (route, reached_receiver) = trace::hierarchy_route_from_predecessors(
            owner,
            depth,
            |current, _| current == receiver,
            |current| {
                self.parents
                    .get(current)
                    .cloned()
                    .map(|parent| (parent, HierarchyRelation::Extends))
            },
            |unit| Some(unit.clone()),
        )?;
        if !reached_receiver {
            return None;
        }
        debug_assert_eq!(
            route.len(),
            depth,
            "the first-discovery chain must be exactly the walk's hop distance"
        );
        Some((depth, route))
    }
}

/// The member attribution the Python member seams accumulate before they hand
/// their candidates to the shared outcome constructor (#1477).
///
/// Applicability stays `Unknown`: these seams select by owner and name and
/// never inspect the call shape, so claiming anything else would be inventing
/// a check the resolver did not perform.
#[derive(Default)]
struct PythonMemberAttribution {
    by_fq_name: Vec<(String, trace::MemberEnrichment)>,
}

impl PythonMemberAttribution {
    /// Candidates found on the receiver's own type: depth zero, no route.
    fn record_direct(&mut self, receiver: &CodeUnit, found: &[CodeUnit]) {
        if !trace::recording() {
            return;
        }
        for candidate in found {
            self.by_fq_name.push((
                candidate.fq_name(),
                trace::member_enrichment_with_tier(
                    receiver.clone(),
                    0,
                    brokk_bifrost_core::analyzer::structural::resolution::MemberDispatchTier::InherentOrDirect,
                    brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict::Unknown,
                    Vec::new(),
                ),
            ));
        }
    }

    /// Candidates found on an ancestor of the receiver. A candidate whose owner
    /// the route walk cannot place stays unattributed.
    fn record_inherited(
        &mut self,
        receiver: &CodeUnit,
        owner: &CodeUnit,
        found: &[CodeUnit],
        routes: &PythonAncestorRoutes,
    ) {
        if !trace::recording() || found.is_empty() {
            return;
        }
        let Some((depth, route)) = routes.route(receiver, owner) else {
            return;
        };
        for candidate in found {
            self.by_fq_name.push((
                candidate.fq_name(),
                trace::member_enrichment_with_tier(
                    owner.clone(),
                    depth,
                    brokk_bifrost_core::analyzer::structural::resolution::MemberDispatchTier::InheritedOrPromoted,
                    brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict::Unknown,
                    route.clone(),
                ),
            ));
        }
    }

    /// Stage the attribution for the outcome constructor the caller is about to
    /// reach. Staging nothing leaves the rows unattributed, which is what an
    /// unrecorded trace and an unplaceable owner must both look like.
    fn stage(self) {
        if self.by_fq_name.is_empty() {
            return;
        }
        trace::stage_member_context(self.by_fq_name);
    }
}

/// Whether the workspace declares `module` as a package/namespace or as a
/// declaration.
///
/// Deliberately language-blind: this is the honesty gate behind every confident
/// Python boundary claim, and a namespace that only C#/Java/Scala declares (a
/// pythonnet CLR namespace, say) is still *inside* the workspace. Answering it
/// Python-only made the claim wrong about workspace-internal targets (#1174).
pub(crate) fn python_workspace_module_exists(
    py: &PythonAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    module: &str,
) -> bool {
    if module.is_empty() {
        return false;
    }
    python_workspace_declares_module(support, module)
        || !python_source_root_spellings(py, module).is_empty()
}

pub(crate) fn python_workspace_declares_module(
    support: &dyn BoundedDefinitionLookup,
    module: &str,
) -> bool {
    !module.is_empty()
        && (support.package_exists_in_any_language(module)
            || !support.fqn_in_any_language(module).is_empty())
}

/// The names and paths this workspace indexes `module` under when `module` is
/// written against a source root below the project root.
///
/// This is diagnostic evidence, not a binding decision. A tail match says the
/// file would be the module *if* its implied root were on the importing
/// program's path, and only the workspace's own structure -- a packaging
/// manifest declaring that root, or a complete package chain from it -- makes
/// that true; a candidate that fails that test is still the spelling the
/// workspace indexes the file under, which the gap has to name (#3506).
///
/// Empty for every module the index spells exactly and for every genuinely
/// external one, so it is only ever consulted after the exact lookups fail.
fn python_source_root_spellings(py: &PythonAnalyzer, module: &str) -> Vec<String> {
    python_source_root_spellings_excluding_installed_roots(py, module, &[])
}

pub(crate) fn python_source_root_spellings_excluding_installed_roots(
    py: &PythonAnalyzer,
    module: &str,
    installed_roots: &[std::path::PathBuf],
) -> Vec<String> {
    let mut names = py
        .module_spellings()
        .suffix_candidates(module)
        .into_iter()
        .filter(|candidate| {
            !installed_roots
                .iter()
                .any(|root| candidate.file.abs_path().starts_with(root))
        })
        .map(|candidate| {
            format!(
                "{} ({})",
                python_module_name(py.project(), &candidate.file),
                rel_path_string(&candidate.file)
            )
        })
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}
