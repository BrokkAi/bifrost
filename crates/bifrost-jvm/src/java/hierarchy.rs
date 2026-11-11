//! Java's type hierarchy: which written supertype name each declaration
//! resolves to, and the workspace-wide ancestor-to-descendant index built from
//! the answers.
//!
//! The persisted hierarchy facts themselves stay in `brokk-bifrost-analysis`:
//! [`JavaHierarchyFact`] is the accessor surface the walk below needs, and the
//! analyzer implements it for its own row type so a hydration batch can be
//! handed across without the store's key material crossing with it.

use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::capabilities::{
    DescendantIndexScope, DirectDescendantIndex, TypeHierarchyProvider,
};
use brokk_bifrost_core::analyzer::fq_name::{SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::{
    CodeUnit, ImportInfo, Language, Range, SignatureMetadata,
};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};

use crate::java::graph_support::{JavaSource, resolve_java_lexical_type_name};
use crate::java::imports::non_static_import_path;

const HIERARCHY_FACT_BATCH_SIZE: usize = 4_096;

/// Why a bounded external-root hierarchy walk could not prove its descendant
/// set complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JavaExternalRootHierarchyIncompleteReason {
    HierarchyFactsUnavailable,
    AmbiguousSupertype,
    UnresolvedSupertype(String),
}

/// Completion status of a workspace hierarchy walk rooted at one exact
/// external JVM type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JavaExternalRootHierarchyStatus {
    Complete,
    Incomplete(JavaExternalRootHierarchyIncompleteReason),
    Cancelled,
    BudgetExhausted,
}

/// Exact workspace descendants of one external Java root.
#[derive(Debug, Clone)]
pub struct JavaExternalRootHierarchyAnswer {
    pub status: JavaExternalRootHierarchyStatus,
    pub descendants: Vec<CodeUnit>,
    pub visited: usize,
    /// Every written supertype of a workspace type that resolved to neither a
    /// workspace type nor the root: the declaration and the name as written.
    /// Such a supertype may be another external type (a JDK class) or a type no
    /// surface can name; the walk cannot tell which, because it reads the
    /// workspace only. A caller that can ask the external surface decides
    /// whether one of them might be an intermediate that overrides a member of
    /// the root. Empty unless the status is `Complete`.
    pub unmatched_supertypes: Vec<(CodeUnit, String)>,
}

impl JavaExternalRootHierarchyAnswer {
    fn stopped(status: JavaExternalRootHierarchyStatus, visited: usize) -> Self {
        debug_assert!(status != JavaExternalRootHierarchyStatus::Complete);
        Self {
            status,
            descendants: Vec::new(),
            visited,
            unmatched_supertypes: Vec::new(),
        }
    }
}

struct JavaHierarchyTypeBucket {
    winner: usize,
    declarations: Vec<usize>,
}

/// One persisted class-like declaration together with the file facts a
/// supertype name resolves against.
///
/// The analyzer's own row carries store key material that cannot cross the
/// crate line, so the walk reads it through these four accessors and hands the
/// unmodified rows back for hydration.
pub trait JavaHierarchyFact: Clone {
    fn declaration(&self) -> &CodeUnit;
    fn primary_range(&self) -> Option<&Range>;
    fn imports(&self) -> &[ImportInfo];
    fn raw_supertypes(&self) -> &[String];
}

/// Why a hierarchy member-selection fact could not be established from the
/// canonical Java declaration metadata.
///
/// The hierarchy walk deliberately keeps this separate from a missing member:
/// an absent or disagreeing type property must not let the walk continue and
/// manufacture a lower-confidence owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaHierarchyFactError {
    MetadataUnavailable,
}

/// Whether `code_unit` is declared as an interface rather than a class.
///
/// The answer is a canonical declaration property, so a missing metadata row
/// or disagreeing alternatives is deliberately unavailable instead of being
/// interpreted as an ordinary class.
pub fn java_is_interface(
    source: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
) -> Result<bool, JavaHierarchyFactError> {
    if !code_unit.is_class() {
        return Ok(false);
    }
    java_interface_metadata_value(&source.signature_metadata(code_unit))
}

fn java_interface_metadata_value(
    alternatives: &[SignatureMetadata],
) -> Result<bool, JavaHierarchyFactError> {
    let first = alternatives
        .first()
        .ok_or(JavaHierarchyFactError::MetadataUnavailable)?;
    let is_interface = first.class_like_is_interface();
    alternatives
        .iter()
        .all(|alternative| alternative.class_like_is_interface() == is_interface)
        .then_some(is_interface)
        .ok_or(JavaHierarchyFactError::MetadataUnavailable)
}

/// Prefer class owners over interface owners at one Java hierarchy
/// level. When no class declares the applicable member, every interface owner
/// remains a peer so callers can preserve honest ambiguity. A single owner is
/// already unambiguous and does not require the interface marker.
pub fn java_preferred_declaring_owners(
    source: &dyn CodeUnitIndex,
    owners: &[CodeUnit],
) -> Result<Vec<CodeUnit>, JavaHierarchyFactError> {
    if owners.len() <= 1 {
        return Ok(owners.to_vec());
    }
    let mut class_owners = Vec::new();
    for owner in owners {
        if !java_is_interface(source, owner)? {
            class_owners.push(owner.clone());
        }
    }
    Ok(if class_owners.is_empty() {
        owners.to_vec()
    } else {
        class_owners
    })
}

/// The owners on the *nearest* supertype level of `owner` that declare the
/// member `declares` tests for, reduced by [`java_preferred_declaring_owners`].
///
/// Java binds an inherited member to the declaration the receiver's static type
/// provides, searching one level at a time and stopping at the first level that
/// declares the name. A level that declares it answers outright, so a deeper
/// declaration of the same name is the one that level's declaration overrides,
/// never a competing candidate.
///
/// `Ok(None)` means no ancestor level declares the member at all -- either the
/// hierarchy is exhausted or the declaring supertype is outside the workspace.
/// A returned vector holding more than one owner is honest ambiguity: two
/// unrelated interfaces at the same distance both declare the name, and no
/// caller may choose between them. `Err` means the caller's canonical fact
/// predicate could not answer, so the walk must remain unproven.
pub fn java_nearest_declaring_ancestors(
    source: &dyn CodeUnitIndex,
    provider: &dyn TypeHierarchyProvider,
    owner: &CodeUnit,
    mut declares: impl FnMut(&CodeUnit) -> Result<bool, JavaHierarchyFactError>,
) -> Result<Option<Vec<CodeUnit>>, JavaHierarchyFactError> {
    let mut seen = HashSet::from_iter([owner.clone()]);
    let answer = provider.get_direct_ancestors(owner);
    if !answer.is_complete() {
        return Err(JavaHierarchyFactError::MetadataUnavailable);
    }
    let mut level = answer.edges;
    while !level.is_empty() {
        let mut declaring_owners = Vec::new();
        let mut next_level = Vec::new();
        for ancestor in level {
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            if declares(&ancestor)? {
                declaring_owners.push(ancestor.clone());
            }
            let answer = provider.get_direct_ancestors(&ancestor);
            if !answer.is_complete() {
                return Err(JavaHierarchyFactError::MetadataUnavailable);
            }
            next_level.extend(answer.edges);
        }
        if !declaring_owners.is_empty() {
            return java_preferred_declaring_owners(source, &declaring_owners).map(Some);
        }
        level = next_level;
    }
    Ok(None)
}

/// The uncached half of the analyzer's `get_direct_ancestors`.
pub fn java_direct_ancestors(
    source: &dyn JavaSource,
    token: QueryToken<'_>,
    code_unit: &CodeUnit,
) -> Vec<CodeUnit> {
    source
        .raw_supertypes_of(code_unit)
        .iter()
        .filter_map(|raw_name| {
            resolve_java_lexical_type_name(source, code_unit, raw_name)
                .or_else(|| source.resolve_imported_type_name(token, code_unit.source(), raw_name))
        })
        .collect()
}

/// The uncached half of the analyzer's `get_direct_descendants` cell: every
/// class-like declaration in the workspace, with an edge from each resolved
/// supertype to the declaration that names it.
///
/// `hydrate` fills the supertype and import facts of one batch in place and
/// reports whether it could; a batch it cannot fill contributes no edges, as
/// before the move.
///
/// `scope` drops out-of-slice declarations before they are hydrated at all, and
/// bounds the hydration pass: `None` means the build stopped short and must not
/// be published (issue #1748).
pub fn build_java_direct_descendant_index<F, H>(
    mut candidates: Vec<F>,
    hydrate: H,
    scope: &DescendantIndexScope<'_>,
) -> Option<DirectDescendantIndex>
where
    F: JavaHierarchyFact,
    H: Fn(&mut Vec<F>) -> bool,
{
    candidates.retain(|facts| scope.admits(facts.declaration()));
    candidates.sort_by(|left, right| {
        left.declaration()
            .source()
            .cmp(right.declaration().source())
            .then_with(|| left.declaration().cmp(right.declaration()))
    });
    let mut types_by_fq_name: HashMap<String, JavaHierarchyTypeBucket> = HashMap::default();
    for (index, facts) in candidates.iter().enumerate() {
        let candidate = facts.declaration();
        let fq_name = candidate.fq_name();
        if let Some(bucket) = types_by_fq_name.get_mut(&fq_name) {
            let winner = &candidates[bucket.winner];
            if java_definition_sort_key(candidate, facts.primary_range())
                < java_definition_sort_key(winner.declaration(), winner.primary_range())
            {
                bucket.winner = index;
            }
            bucket.declarations.push(index);
        } else {
            types_by_fq_name.insert(
                fq_name,
                JavaHierarchyTypeBucket {
                    winner: index,
                    declarations: vec![index],
                },
            );
        }
    }
    let mut index_by_node = HashMap::default();
    for (index, facts) in candidates.iter().enumerate() {
        index_by_node.insert(
            facts.declaration().clone(),
            u32::try_from(index).expect("Java hierarchy declarations must fit in a u32"),
        );
    }

    let mut edges = Vec::new();
    for batch_start in (0..candidates.len()).step_by(HIERARCHY_FACT_BATCH_SIZE) {
        if scope.cancellation().is_cancelled() {
            return None;
        }
        let batch_end = (batch_start + HIERARCHY_FACT_BATCH_SIZE).min(candidates.len());
        let mut batch = candidates[batch_start..batch_end].to_vec();
        if !hydrate(&mut batch) {
            continue;
        }
        for (offset, facts) in batch.iter().enumerate() {
            let candidate_index = batch_start + offset;
            let candidate = facts.declaration();
            let descendant = u32::try_from(candidate_index)
                .expect("Java hierarchy declarations must fit in a u32");
            for raw in facts.raw_supertypes().iter() {
                let resolved = resolve_hierarchy_type_index(
                    raw,
                    candidate,
                    facts.imports(),
                    &types_by_fq_name,
                );
                let Some(resolved) = resolved else {
                    continue;
                };
                let ancestor = same_source_hierarchy_identity(
                    resolved,
                    candidate,
                    &candidates,
                    &types_by_fq_name,
                );
                edges.push((
                    u32::try_from(ancestor).expect("Java hierarchy declarations must fit in a u32"),
                    descendant,
                ));
            }
        }
    }

    let nodes = candidates
        .into_iter()
        .map(|facts| facts.declaration().clone())
        .collect();
    Some(DirectDescendantIndex::from_indexed_nodes(
        nodes,
        index_by_node,
        edges,
    ))
}

/// Every admitted workspace Java type, hydrated with the facts its supertype
/// spellings resolve against, ready to answer which types lie below one exact
/// external root.
///
/// This is the external-root counterpart to
/// [`build_java_direct_descendant_index`]. It consumes the same persisted,
/// AST-derived hierarchy facts. Nothing in it depends on the root, so one
/// index answers every root of a snapshot: preparing it reads every class's
/// hierarchy facts once, and [`Self::descendants_of`] is an in-memory pass.
pub struct JavaExternalRootHierarchyIndex<F> {
    candidates: Vec<F>,
    types_by_fq_name: HashMap<String, JavaHierarchyTypeBucket>,
}

impl<F: JavaHierarchyFact> JavaExternalRootHierarchyIndex<F> {
    /// Sort and hydrate `candidates`. `hydrate` fills one batch in place and
    /// reports whether it could; a batch it cannot fill refuses the index,
    /// because a missing supertype edge would silently shrink a family.
    pub fn prepare<H>(
        mut candidates: Vec<F>,
        hydrate: H,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, JavaExternalRootHierarchyStatus>
    where
        H: Fn(&mut Vec<F>) -> bool,
    {
        candidates.sort_by(|left, right| {
            left.declaration()
                .source()
                .cmp(right.declaration().source())
                .then_with(|| left.declaration().cmp(right.declaration()))
        });
        let mut types_by_fq_name: HashMap<String, JavaHierarchyTypeBucket> = HashMap::default();
        for (index, facts) in candidates.iter().enumerate() {
            let candidate = facts.declaration();
            let fq_name = candidate.fq_name();
            if let Some(bucket) = types_by_fq_name.get_mut(&fq_name) {
                let winner = &candidates[bucket.winner];
                if java_definition_sort_key(candidate, facts.primary_range())
                    < java_definition_sort_key(winner.declaration(), winner.primary_range())
                {
                    bucket.winner = index;
                }
                bucket.declarations.push(index);
            } else {
                types_by_fq_name.insert(
                    fq_name,
                    JavaHierarchyTypeBucket {
                        winner: index,
                        declarations: vec![index],
                    },
                );
            }
        }
        for batch_start in (0..candidates.len()).step_by(HIERARCHY_FACT_BATCH_SIZE) {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(JavaExternalRootHierarchyStatus::Cancelled);
            }
            let batch_end = (batch_start + HIERARCHY_FACT_BATCH_SIZE).min(candidates.len());
            let mut batch = candidates[batch_start..batch_end].to_vec();
            if !hydrate(&mut batch) {
                return Err(JavaExternalRootHierarchyStatus::Incomplete(
                    JavaExternalRootHierarchyIncompleteReason::HierarchyFactsUnavailable,
                ));
            }
            assert_eq!(
                batch.len(),
                batch_end - batch_start,
                "hydration keeps its batch"
            );
            for (slot, facts) in candidates[batch_start..batch_end].iter_mut().zip(batch) {
                *slot = facts;
            }
        }
        Ok(Self {
            candidates,
            types_by_fq_name,
        })
    }

    /// The hydrated declarations, for callers that weigh a retained index.
    pub fn candidates(&self) -> &[F] {
        &self.candidates
    }

    /// Enumerate every workspace Java type below one exact external root.
    ///
    /// An edge is retained when Java's type-name tiers resolve a raw supertype
    /// to `external_root_fqn`. The root itself is not represented by a
    /// fabricated [`CodeUnit`]. Instead, direct external edges seed an
    /// iterative walk over the ordinary workspace-to-workspace edges. Those
    /// edges are recomputed for each root: a tier that names the root before a
    /// workspace type binds the root, so the workspace edges depend on it.
    ///
    /// `external_root_fqn` is the resolver-owned canonical identity at the
    /// dispatch boundary. A complete answer, even an empty one, covers every
    /// admitted declaration, so `max_visits` must admit all of them.
    pub fn descendants_of(
        &self,
        external_root_fqn: &str,
        max_visits: usize,
        cancellation: Option<&CancellationToken>,
    ) -> JavaExternalRootHierarchyAnswer {
        self.descendants_of_with_external(external_root_fqn, max_visits, cancellation, |_, _, _| {
            Ok(crate::ExternalSupertypeClosureAnswer::default())
        })
    }

    /// Resolve unmatched workspace edges against a query-local external closure.
    pub fn descendants_of_with_external(
        &self,
        external_root_fqn: &str,
        max_visits: usize,
        cancellation: Option<&CancellationToken>,
        mut external_reaches_root: impl FnMut(
            &CodeUnit,
            &str,
            &mut usize,
        ) -> Result<
            crate::ExternalSupertypeClosureAnswer,
            crate::ExternalSupertypeClosureStop,
        >,
    ) -> JavaExternalRootHierarchyAnswer {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return JavaExternalRootHierarchyAnswer::stopped(
                JavaExternalRootHierarchyStatus::Cancelled,
                0,
            );
        }
        let candidates = &self.candidates;
        if candidates.len() > max_visits {
            return JavaExternalRootHierarchyAnswer::stopped(
                JavaExternalRootHierarchyStatus::BudgetExhausted,
                0,
            );
        }
        let mut visited = candidates.len();
        let types_by_fq_name = &self.types_by_fq_name;
        if types_by_fq_name.contains_key(external_root_fqn) {
            return JavaExternalRootHierarchyAnswer::stopped(
                JavaExternalRootHierarchyStatus::Incomplete(
                    JavaExternalRootHierarchyIncompleteReason::AmbiguousSupertype,
                ),
                visited,
            );
        }

        let mut workspace_edges = vec![Vec::new(); candidates.len()];
        let mut external_descendants = Vec::new();
        let mut unmatched_supertypes = Vec::new();
        // The first external closure that could not be completed. The scan
        // goes on so every unmatched workspace supertype is still collected
        // for the independent unresolved-supertype report. Later external closures
        // may still prove more descendants.
        let mut incomplete = None;
        for (descendant_index, facts) in candidates.iter().enumerate() {
            if descendant_index % HIERARCHY_FACT_BATCH_SIZE == 0
                && cancellation.is_some_and(CancellationToken::is_cancelled)
            {
                return JavaExternalRootHierarchyAnswer::stopped(
                    JavaExternalRootHierarchyStatus::Cancelled,
                    visited,
                );
            }
            let descendant = facts.declaration();
            for raw in facts.raw_supertypes() {
                let resolved = resolve_external_root_hierarchy_type(
                    raw,
                    descendant,
                    facts.imports(),
                    types_by_fq_name,
                    external_root_fqn,
                );
                match resolved {
                    ExternalRootHierarchyResolution::Workspace(ancestor) => {
                        let ancestor = same_source_hierarchy_identity(
                            ancestor,
                            descendant,
                            candidates,
                            types_by_fq_name,
                        );
                        workspace_edges[ancestor].push(descendant_index);
                    }
                    ExternalRootHierarchyResolution::ExternalRoot => {
                        external_descendants.push(descendant_index);
                    }
                    ExternalRootHierarchyResolution::NoMatch => {
                        unmatched_supertypes.push((descendant.clone(), raw.clone()));
                        match external_reaches_root(descendant, raw, &mut visited) {
                            Ok(answer) => {
                                if answer.reaches_root {
                                    external_descendants.push(descendant_index);
                                }
                                if let Some(identity) = answer.unresolved_supertype {
                                    incomplete.get_or_insert(JavaExternalRootHierarchyStatus::Incomplete(
                                        JavaExternalRootHierarchyIncompleteReason::UnresolvedSupertype(identity),
                                    ));
                                }
                            }
                            Err(stop) => {
                                let status = match stop {
                                    crate::ExternalSupertypeClosureStop::Cancelled => {
                                        JavaExternalRootHierarchyStatus::Cancelled
                                    }
                                    crate::ExternalSupertypeClosureStop::BudgetExhausted => {
                                        JavaExternalRootHierarchyStatus::BudgetExhausted
                                    }
                                };
                                let mut answer =
                                    JavaExternalRootHierarchyAnswer::stopped(status, visited);
                                answer.unmatched_supertypes = unmatched_supertypes;
                                return answer;
                            }
                        }
                    }
                    ExternalRootHierarchyResolution::Ambiguous => {
                        return JavaExternalRootHierarchyAnswer::stopped(
                            JavaExternalRootHierarchyStatus::Incomplete(
                                JavaExternalRootHierarchyIncompleteReason::AmbiguousSupertype,
                            ),
                            visited,
                        );
                    }
                }
            }
        }

        let Some(descendants) = crate::hierarchy_descendants_from_edges(
            candidates,
            &workspace_edges,
            external_descendants,
            cancellation,
            JavaHierarchyFact::declaration,
        ) else {
            return JavaExternalRootHierarchyAnswer::stopped(
                JavaExternalRootHierarchyStatus::Cancelled,
                visited,
            );
        };
        // An unresolved supertype leaves the answer incomplete, but the
        // descendants already proven are still descendants: a consumer keeps
        // them as targets while the family stays open.
        JavaExternalRootHierarchyAnswer {
            status: incomplete.unwrap_or(JavaExternalRootHierarchyStatus::Complete),
            descendants,
            visited,
            unmatched_supertypes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalRootHierarchyResolution {
    Workspace(usize),
    ExternalRoot,
    NoMatch,
    Ambiguous,
}

fn resolve_external_root_hierarchy_type(
    raw_name: &str,
    candidate: &CodeUnit,
    imports: &[ImportInfo],
    types_by_fq_name: &HashMap<String, JavaHierarchyTypeBucket>,
    external_root_fqn: &str,
) -> ExternalRootHierarchyResolution {
    match resolve_hierarchy_type_with(raw_name, candidate, imports, |fq_name| {
        hierarchy_type_index(types_by_fq_name, fq_name)
            .map(HierarchyTypeTarget::Workspace)
            .or_else(|| (fq_name == external_root_fqn).then_some(HierarchyTypeTarget::ExternalRoot))
    }) {
        HierarchyTypeResolution::Resolved(HierarchyTypeTarget::Workspace(index)) => {
            ExternalRootHierarchyResolution::Workspace(index)
        }
        HierarchyTypeResolution::Resolved(HierarchyTypeTarget::ExternalRoot) => {
            ExternalRootHierarchyResolution::ExternalRoot
        }
        HierarchyTypeResolution::NoMatch => ExternalRootHierarchyResolution::NoMatch,
        HierarchyTypeResolution::AmbiguousWildcard(_) => ExternalRootHierarchyResolution::Ambiguous,
    }
}

fn java_definition_sort_key(
    candidate: &CodeUnit,
    range: Option<&Range>,
) -> (usize, String, String, String, String) {
    let (source, fq_name, signature, kind) =
        brokk_bifrost_core::analyzer::code_unit_index::definition_tie_break_key(candidate);
    (
        range.map_or(usize::MAX, |range| range.start_byte),
        source,
        fq_name,
        signature,
        kind,
    )
}

fn resolve_hierarchy_type_index(
    raw_name: &str,
    candidate: &CodeUnit,
    imports: &[ImportInfo],
    types_by_fq_name: &HashMap<String, JavaHierarchyTypeBucket>,
) -> Option<usize> {
    match resolve_hierarchy_type_with(raw_name, candidate, imports, |fq_name| {
        hierarchy_type_index(types_by_fq_name, fq_name)
    }) {
        HierarchyTypeResolution::Resolved(index)
        | HierarchyTypeResolution::AmbiguousWildcard(index) => Some(index),
        HierarchyTypeResolution::NoMatch => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HierarchyTypeTarget {
    Workspace(usize),
    ExternalRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HierarchyTypeResolution<T> {
    Resolved(T),
    /// More than one wildcard import could bind the spelling. The ordinary
    /// workspace index preserves its historical first-known-target behavior;
    /// an external-root proof must refuse because dependency types in the
    /// other imported packages are not indexed.
    AmbiguousWildcard(T),
    NoMatch,
}

/// Resolve one persisted Java supertype spelling through Java's hierarchy
/// tiers. Both the ordinary workspace index and the external-root query use
/// this function; only `target_by_fqn` differs, so import and lexical
/// precedence cannot drift between the two paths.
fn resolve_hierarchy_type_with<T: Copy>(
    raw_name: &str,
    candidate: &CodeUnit,
    imports: &[ImportInfo],
    mut target_by_fqn: impl FnMut(&str) -> Option<T>,
) -> HierarchyTypeResolution<T> {
    let normalized = raw_name.trim();
    if normalized.is_empty() {
        return HierarchyTypeResolution::NoMatch;
    }

    if normalized.contains('.')
        && let Some(target) = target_by_fqn(normalized)
    {
        return HierarchyTypeResolution::Resolved(target);
    }

    for fq_name in lexical_hierarchy_type_names(normalized, candidate) {
        if let Some(target) = target_by_fqn(&fq_name) {
            return HierarchyTypeResolution::Resolved(target);
        }
    }

    let package_name = candidate.package_name();

    for import in imports {
        let Some(import_path) = non_static_import_path(import) else {
            continue;
        };
        if import.is_wildcard {
            continue;
        }
        let Some(imported_name) = import.identifier.as_deref() else {
            continue;
        };
        if normalized == imported_name {
            return target_by_fqn(&import_path.render_segments(".")).map_or(
                HierarchyTypeResolution::NoMatch,
                HierarchyTypeResolution::Resolved,
            );
        }
        if let Some(rest) = normalized
            .strip_prefix(imported_name)
            .and_then(|rest| rest.strip_prefix('.'))
        {
            let nested_fqn = format!("{}.{rest}", import_path.render_segments("."));
            return target_by_fqn(&nested_fqn).map_or(
                HierarchyTypeResolution::NoMatch,
                HierarchyTypeResolution::Resolved,
            );
        }
    }

    let mut wildcard_names = Vec::new();
    let mut first_wildcard_target = None;
    for import in imports {
        let Some(import_path) = non_static_import_path(import) else {
            continue;
        };
        if !import.is_wildcard {
            continue;
        }
        let fqn = format!("{}.{normalized}", import_path.render_segments("."));
        if !wildcard_names.contains(&fqn) {
            wildcard_names.push(fqn.clone());
        }
        if first_wildcard_target.is_none() {
            first_wildcard_target = target_by_fqn(&fqn);
        }
    }
    if let Some(target) = first_wildcard_target {
        return if wildcard_names.len() == 1 {
            HierarchyTypeResolution::Resolved(target)
        } else {
            HierarchyTypeResolution::AmbiguousWildcard(target)
        };
    }

    let same_package_fqn = if package_name.is_empty() {
        normalized.to_string()
    } else {
        format!("{package_name}.{normalized}")
    };
    if let Some(target) = target_by_fqn(&same_package_fqn) {
        return HierarchyTypeResolution::Resolved(target);
    }
    if package_name.is_empty()
        && let Some(target) = target_by_fqn(normalized)
    {
        return HierarchyTypeResolution::Resolved(target);
    }
    target_by_fqn(&format!("java.lang.{normalized}")).map_or(
        HierarchyTypeResolution::NoMatch,
        HierarchyTypeResolution::Resolved,
    )
}

fn lexical_hierarchy_type_names(normalized: &str, candidate: &CodeUnit) -> Vec<String> {
    if normalized.contains('.') {
        return Vec::new();
    }
    let mut names = Vec::new();
    let package_end = candidate.package_segment_count();
    let type_end = candidate.fq().len().saturating_sub(1);
    let interner = segment_interner();
    for owner_end in (package_end.saturating_add(1)..=type_end).rev() {
        let owner = candidate.fq().prefix(owner_end);
        let target = owner.with_pushed(interner.intern(normalized, SegmentKind::Type));
        names.push(target.display_native(Language::Java, interner));
    }
    names
}

fn hierarchy_type_index(
    types_by_fq_name: &HashMap<String, JavaHierarchyTypeBucket>,
    fq_name: &str,
) -> Option<usize> {
    types_by_fq_name.get(fq_name).map(|bucket| bucket.winner)
}

fn same_source_hierarchy_identity<F: JavaHierarchyFact>(
    resolved: usize,
    descendant: &CodeUnit,
    candidates: &[F],
    types_by_fq_name: &HashMap<String, JavaHierarchyTypeBucket>,
) -> usize {
    let bucket = &types_by_fq_name[&candidates[resolved].declaration().fq_name()];
    crate::same_source_hierarchy_declaration(
        resolved,
        &bucket.declarations,
        descendant,
        candidates,
        JavaHierarchyFact::declaration,
    )
}

#[cfg(test)]
mod metadata_tests {
    use super::*;

    #[test]
    fn interface_fact_requires_complete_agreement() {
        let interface =
            SignatureMetadata::new("interface I {}", Vec::new()).with_class_like_interface(true);
        let class = SignatureMetadata::new("class I {}", Vec::new());
        assert_eq!(
            java_interface_metadata_value(std::slice::from_ref(&interface)),
            Ok(true)
        );
        assert_eq!(
            java_interface_metadata_value(&[interface.clone(), interface.clone()]),
            Ok(true)
        );
        assert_eq!(
            java_interface_metadata_value(&[interface, class]),
            Err(JavaHierarchyFactError::MetadataUnavailable)
        );
        assert_eq!(
            java_interface_metadata_value(&[]),
            Err(JavaHierarchyFactError::MetadataUnavailable)
        );
    }
}
