//! Kotlin type hierarchy (#1237).
//!
//! Ancestors come from the dotted supertype paths recorded at index time,
//! resolved through Kotlin's name-resolution ladder. Descendants are the
//! inverse, built once per analyzer generation over the shared batched
//! declaration-facts path that Java's hierarchy already uses — the facts carry
//! each candidate's supertype paths and imports together, so inverting the
//! whole workspace costs one hydration pass rather than one per class.
//!
//! The persisted hierarchy facts themselves stay in `brokk-bifrost-analysis`:
//! [`KotlinHierarchyFact`] is the accessor surface the walk below needs, and
//! the analyzer implements it for its own row type so a hydration batch can be
//! handed across without the store's key material crossing with it. Java's
//! hierarchy draws the same line.

use brokk_bifrost_core::analyzer::capabilities::{
    DescendantIndexScope, DirectDescendantIndex, build_direct_descendant_index_from_candidates,
};
use brokk_bifrost_core::analyzer::model::{CodeUnit, ImportInfo, Range};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};

use crate::kotlin::graph_support::KotlinSource;
use crate::kotlin::types::{
    KotlinNameScope, KotlinTypeName, kotlin_realm_type_by_fqn, kotlin_scope_owners_for_with,
    resolve_kotlin_type_name,
};
use crate::realm::JvmSourceRealm;

/// How many declarations are hydrated per store round-trip while inverting the
/// hierarchy. Matches the Java hierarchy's batch size for the same reason:
/// large enough to amortize the query, small enough to bound peak memory.
const HIERARCHY_FACT_BATCH_SIZE: usize = 4_096;

/// One persisted class-like declaration together with the file facts a
/// supertype name resolves against.
///
/// The analyzer's own row carries store key material that cannot cross the
/// crate line, so the walk reads it through these three accessors and hands the
/// unmodified rows back for hydration.
pub trait KotlinHierarchyFact: Clone {
    fn declaration(&self) -> &CodeUnit;
    fn primary_range(&self) -> Option<Range>;
    fn imports(&self) -> &[ImportInfo];
    fn raw_supertypes(&self) -> &[String];
}

/// The uncached half of the analyzer's realm-keyed ancestor cache.
pub fn kotlin_resolve_direct_ancestors(
    source: &dyn KotlinSource,
    token: QueryToken<'_>,
    code_unit: &CodeUnit,
    realm: Option<&JvmSourceRealm<'_>>,
) -> Vec<CodeUnit> {
    if !code_unit.is_class() {
        return Vec::new();
    }
    let raw_supertypes = source.raw_supertypes_of(code_unit);
    if raw_supertypes.is_empty() {
        // Most classes declare nothing, and the scope below is the expensive
        // part — it walks the owner chain and every inherited nested scope — so
        // it is never built for them.
        return Vec::new();
    }
    let imports = source.import_info_of(token, code_unit.source());
    kotlin_resolve_ancestors_from_facts(
        source,
        token,
        code_unit,
        &raw_supertypes,
        &imports,
        realm,
        &mut |fqn| kotlin_realm_type_by_fqn(source, token, fqn, realm),
    )
}

/// The uncached half of the analyzer's realm-keyed descendant-index cell: every
/// class-like declaration in the workspace, with an edge from each resolved
/// supertype to the declaration that names it.
///
/// `candidates` are the persisted class rows; `hydrate` fills one batch of them
/// with the imports and raw supertypes the resolution needs, answering `false`
/// when the batch could not be hydrated.
///
/// `scope` drops out-of-slice declarations before they are hydrated at all, and
/// bounds the pass: `None` means it stopped short and must not be published
/// (issue #1748).
pub fn build_kotlin_direct_descendant_index<Fact>(
    mut candidates: Vec<Fact>,
    mut hydrate: impl FnMut(&mut [Fact]) -> bool,
    source: &dyn KotlinSource,
    realm: Option<&JvmSourceRealm<'_>>,
    scope: &DescendantIndexScope<'_>,
    token: QueryToken<'_>,
) -> Option<DirectDescendantIndex>
where
    Fact: KotlinHierarchyFact,
{
    candidates.sort_by(|left, right| left.declaration().cmp(right.declaration()));

    // The candidate pass above is already the authoritative Kotlin class
    // universe for this analyzer generation. Supertype resolution
    // used to ignore it and issue one bounded point-definition query for every
    // candidate name it tried. Common member queries therefore turned one
    // descendant-index build into tens of thousands of repeated store reads.
    // Keep the same source-position-first representative that an exact
    // definition lookup returns; duplicate FQNs remain one JVM identity. Build
    // this lookup before filtering traversal candidates so an excluded test
    // declaration can still be the structurally real ancestor of an admitted
    // production declaration without itself entering the published index.
    let mut kotlin_types_by_fqn: HashMap<String, (CodeUnit, Option<Range>)> = HashMap::default();
    for facts in &candidates {
        let declaration = facts.declaration();
        if declaration.is_synthetic() || !declaration.is_class() {
            continue;
        }
        kotlin_types_by_fqn
            .entry(declaration.fq_name())
            .and_modify(|current| {
                if hierarchy_definition_key(declaration, facts.primary_range())
                    < hierarchy_definition_key(&current.0, current.1)
                {
                    *current = (declaration.clone(), facts.primary_range());
                }
            })
            .or_insert_with(|| (declaration.clone(), facts.primary_range()));
    }
    candidates.retain(|facts| scope.admits(facts.declaration()));

    // Hydration is batched because each candidate needs two facts that are not
    // in the candidate row itself — the supertypes it spells and the file's
    // imports — and fetching those one declaration at a time would be a store
    // round-trip per class.
    let mut ancestors_by_owner: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
    for batch_start in (0..candidates.len()).step_by(HIERARCHY_FACT_BATCH_SIZE) {
        if scope.cancellation().is_cancelled() {
            return None;
        }
        let batch_end = (batch_start + HIERARCHY_FACT_BATCH_SIZE).min(candidates.len());
        let mut batch = candidates[batch_start..batch_end].to_vec();
        if !hydrate(&mut batch) {
            continue;
        }
        for facts in &batch {
            let resolved = source.resolved_ancestors_from_hydrated_facts(
                token,
                facts.declaration(),
                facts.raw_supertypes(),
                facts.imports(),
                realm,
                &mut |fqn| {
                    kotlin_types_by_fqn
                        .get(fqn)
                        .map(|(unit, _)| unit.clone())
                        .or_else(|| {
                            realm?
                                .peer_types_by_fqn(
                                    fqn,
                                    brokk_bifrost_core::analyzer::Language::Kotlin,
                                )
                                .into_iter()
                                .next()
                        })
                },
            );
            if !resolved.is_empty() {
                ancestors_by_owner.insert(facts.declaration().clone(), resolved);
            }
        }
    }

    build_direct_descendant_index_from_candidates(
        candidates
            .into_iter()
            .map(|facts| facts.declaration().clone())
            .collect(),
        |candidate| {
            Some(
                ancestors_by_owner
                    .get(candidate)
                    .cloned()
                    .unwrap_or_default(),
            )
        },
        &scope.keep_going(),
    )
}

fn hierarchy_definition_key(
    unit: &CodeUnit,
    primary_range: Option<Range>,
) -> (usize, String, String, String, String) {
    (
        primary_range.map_or(usize::MAX, |range| range.start_byte),
        unit.source().to_string().to_ascii_lowercase(),
        unit.fq_name().to_ascii_lowercase(),
        unit.signature().unwrap_or("").to_ascii_lowercase(),
        format!("{:?}", unit.kind()),
    )
}

/// Why a bounded external-root hierarchy walk could not prove its descendant
/// set complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KotlinExternalRootHierarchyIncompleteReason {
    HierarchyFactsUnavailable,
    AmbiguousSupertype,
}

/// Completion status of a workspace hierarchy walk rooted at one exact
/// external JVM type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KotlinExternalRootHierarchyStatus {
    Complete,
    Incomplete(KotlinExternalRootHierarchyIncompleteReason),
    Cancelled,
    BudgetExhausted,
}

/// Exact workspace descendants of one external Kotlin-visible JVM root.
#[derive(Debug, Clone)]
pub struct KotlinExternalRootHierarchyAnswer {
    pub status: KotlinExternalRootHierarchyStatus,
    pub descendants: Vec<CodeUnit>,
    pub visited: usize,
}

impl KotlinExternalRootHierarchyAnswer {
    fn stopped(status: KotlinExternalRootHierarchyStatus, visited: usize) -> Self {
        debug_assert!(status != KotlinExternalRootHierarchyStatus::Complete);
        Self {
            status,
            descendants: Vec::new(),
            visited,
        }
    }
}

struct KotlinHierarchyTypeBucket {
    winner: usize,
    declarations: Vec<usize>,
}

/// Enumerate every workspace Kotlin type below one exact external root.
///
/// This is the external-root counterpart to
/// [`build_kotlin_direct_descendant_index`]. It consumes the same persisted,
/// AST-derived hierarchy facts, but retains an edge when Kotlin's type-name
/// ladder resolves a raw supertype to `external_root_fqn`. The root itself is
/// not represented by a fabricated [`CodeUnit`]. Instead, direct external edges
/// seed an iterative walk over the ordinary workspace-to-workspace edges.
///
/// `external_root_fqn` is the resolver-owned canonical identity at the
/// dispatch boundary. Scanning every admitted declaration is required even for
/// a complete-empty answer, so `max_visits` is checked before the candidate
/// index is built.
pub fn build_kotlin_external_root_hierarchy<Fact>(
    mut candidates: Vec<Fact>,
    mut hydrate: impl FnMut(&mut [Fact]) -> bool,
    source: &(impl KotlinSource + ?Sized),
    token: QueryToken<'_>,
    external_root_fqn: &str,
    max_visits: usize,
    cancellation: Option<&CancellationToken>,
) -> KotlinExternalRootHierarchyAnswer
where
    Fact: KotlinHierarchyFact,
{
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return KotlinExternalRootHierarchyAnswer::stopped(
            KotlinExternalRootHierarchyStatus::Cancelled,
            0,
        );
    }
    if candidates.len() > max_visits {
        return KotlinExternalRootHierarchyAnswer::stopped(
            KotlinExternalRootHierarchyStatus::BudgetExhausted,
            0,
        );
    }
    let visited = candidates.len();
    candidates.sort_by(|left, right| left.declaration().cmp(right.declaration()));
    let mut types_by_fq_name: HashMap<String, KotlinHierarchyTypeBucket> = HashMap::default();
    for (index, facts) in candidates.iter().enumerate() {
        let candidate = facts.declaration();
        if candidate.is_synthetic() || !candidate.is_class() {
            continue;
        }
        let fq_name = candidate.fq_name();
        if let Some(bucket) = types_by_fq_name.get_mut(&fq_name) {
            let winner = &candidates[bucket.winner];
            if hierarchy_definition_key(candidate, facts.primary_range())
                < hierarchy_definition_key(winner.declaration(), winner.primary_range())
            {
                bucket.winner = index;
            }
            bucket.declarations.push(index);
        } else {
            types_by_fq_name.insert(
                fq_name,
                KotlinHierarchyTypeBucket {
                    winner: index,
                    declarations: vec![index],
                },
            );
        }
    }
    if types_by_fq_name.contains_key(external_root_fqn) {
        return KotlinExternalRootHierarchyAnswer::stopped(
            KotlinExternalRootHierarchyStatus::Incomplete(
                KotlinExternalRootHierarchyIncompleteReason::AmbiguousSupertype,
            ),
            visited,
        );
    }

    let mut workspace_edges = vec![Vec::new(); candidates.len()];
    let mut external_descendants = Vec::new();
    for batch_start in (0..candidates.len()).step_by(HIERARCHY_FACT_BATCH_SIZE) {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return KotlinExternalRootHierarchyAnswer::stopped(
                KotlinExternalRootHierarchyStatus::Cancelled,
                visited,
            );
        }
        let batch_end = (batch_start + HIERARCHY_FACT_BATCH_SIZE).min(candidates.len());
        let mut batch = candidates[batch_start..batch_end].to_vec();
        if !hydrate(&mut batch) {
            return KotlinExternalRootHierarchyAnswer::stopped(
                KotlinExternalRootHierarchyStatus::Incomplete(
                    KotlinExternalRootHierarchyIncompleteReason::HierarchyFactsUnavailable,
                ),
                visited,
            );
        }
        for (offset, facts) in batch.iter().enumerate() {
            let descendant_index = batch_start + offset;
            let descendant = facts.declaration();
            let mut type_by_fqn = |fqn: &str| {
                types_by_fq_name
                    .get(fqn)
                    .map(|bucket| candidates[bucket.winner].declaration().clone())
            };
            let scope = KotlinNameScope {
                package_name: descendant.package_name(),
                imports: facts.imports(),
                scope_owners: kotlin_scope_owners_for_with(
                    source,
                    token,
                    descendant,
                    None,
                    &mut type_by_fqn,
                ),
            };
            for raw in facts.raw_supertypes() {
                let resolved = resolve_kotlin_type_name(raw, &scope, |candidate| {
                    types_by_fq_name.contains_key(candidate) || candidate == external_root_fqn
                });
                match resolved {
                    KotlinTypeName::Resolved(fqn) if fqn == external_root_fqn => {
                        external_descendants.push(descendant_index);
                    }
                    KotlinTypeName::Resolved(fqn) => {
                        let ancestor = same_source_hierarchy_identity(
                            &fqn,
                            descendant,
                            &candidates,
                            &types_by_fq_name,
                        );
                        workspace_edges[ancestor].push(descendant_index);
                    }
                    KotlinTypeName::Unresolved => {}
                    KotlinTypeName::Ambiguous => {
                        return KotlinExternalRootHierarchyAnswer::stopped(
                            KotlinExternalRootHierarchyStatus::Incomplete(
                                KotlinExternalRootHierarchyIncompleteReason::AmbiguousSupertype,
                            ),
                            visited,
                        );
                    }
                }
            }
        }
    }

    let mut seen = vec![false; candidates.len()];
    let mut stack = external_descendants;
    while let Some(index) = stack.pop() {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return KotlinExternalRootHierarchyAnswer::stopped(
                KotlinExternalRootHierarchyStatus::Cancelled,
                visited,
            );
        }
        if std::mem::replace(&mut seen[index], true) {
            continue;
        }
        stack.extend(workspace_edges[index].iter().copied());
    }
    let mut descendants = seen
        .into_iter()
        .enumerate()
        .filter(|(_, seen)| *seen)
        .map(|(index, _)| candidates[index].declaration().clone())
        .collect::<Vec<_>>();
    descendants.sort();
    KotlinExternalRootHierarchyAnswer {
        status: KotlinExternalRootHierarchyStatus::Complete,
        descendants,
        visited,
    }
}

/// The candidate index the walk uses for a supertype that resolved by fully
/// qualified name.
///
/// A duplicate FQN is one JVM identity declared in more than one source. When
/// exactly one of those declarations sits in the descendant's own source, that
/// declaration is the one the descendant's own file sees; otherwise the
/// source-position winner stands. Java's external-root walk makes the same
/// choice for the same reason.
fn same_source_hierarchy_identity<Fact: KotlinHierarchyFact>(
    fqn: &str,
    descendant: &CodeUnit,
    candidates: &[Fact],
    types_by_fq_name: &HashMap<String, KotlinHierarchyTypeBucket>,
) -> usize {
    let bucket = &types_by_fq_name[fqn];
    let mut same_source = bucket
        .declarations
        .iter()
        .copied()
        .filter(|index| candidates[*index].declaration().source() == descendant.source());
    let Some(exact) = same_source.next() else {
        return bucket.winner;
    };
    if same_source.next().is_none() {
        exact
    } else {
        bucket.winner
    }
}

/// Resolve one declaration's ancestors from facts already in hand.
///
/// A supertype that does not resolve yields no ancestor. Kotlin code routinely
/// extends types from dependencies that are not on the configured classpath,
/// and inventing a declaration for one would put a name in the hierarchy that
/// no query can open.
pub fn kotlin_resolve_ancestors_from_facts<S: KotlinSource + ?Sized>(
    source: &S,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    raw_supertypes: &[String],
    imports: &[ImportInfo],
    realm: Option<&JvmSourceRealm<'_>>,
    type_by_fqn: &mut dyn FnMut(&str) -> Option<CodeUnit>,
) -> Vec<CodeUnit> {
    if raw_supertypes.is_empty() {
        return Vec::new();
    }
    let scope = KotlinNameScope {
        package_name: owner.package_name(),
        imports,
        scope_owners: kotlin_scope_owners_for_with(source, token, owner, realm, type_by_fqn),
    };
    let mut ancestors = Vec::new();
    let mut seen = HashSet::default();
    for spelled in raw_supertypes {
        let KotlinTypeName::Resolved(fqn) =
            resolve_kotlin_type_name(spelled, &scope, |candidate| {
                type_by_fqn(candidate).is_some()
            })
        else {
            continue;
        };
        if let Some(unit) = type_by_fqn(&fqn)
            && seen.insert(unit.fq_name())
        {
            ancestors.push(unit);
        }
    }
    ancestors
}
