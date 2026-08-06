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
    DirectDescendantIndex, build_direct_descendant_index_from_candidates,
};
use brokk_bifrost_core::analyzer::model::{CodeUnit, ImportInfo};
use brokk_bifrost_core::hash::{HashMap, HashSet};

use crate::kotlin::graph_support::KotlinSource;
use crate::kotlin::types::{
    KotlinNameScope, KotlinTypeName, kotlin_realm_type_by_fqn, kotlin_realm_type_exists,
    kotlin_scope_owners_for, resolve_kotlin_type_name,
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
    fn imports(&self) -> &[ImportInfo];
    fn raw_supertypes(&self) -> &[String];
}

/// The uncached half of the analyzer's realm-keyed ancestor cache.
pub fn kotlin_resolve_direct_ancestors(
    source: &dyn KotlinSource,
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
    let imports = source.import_info_of(code_unit.source());
    kotlin_resolve_ancestors_from_facts(source, code_unit, &raw_supertypes, &imports, realm)
}

/// The uncached half of the analyzer's realm-keyed descendant-index cell: every
/// class-like declaration in the workspace, with an edge from each resolved
/// supertype to the declaration that names it.
///
/// `candidates` are the persisted class rows; `hydrate` fills one batch of them
/// with the imports and raw supertypes the resolution needs, answering `false`
/// when the batch could not be hydrated.
pub fn build_kotlin_direct_descendant_index<Fact>(
    mut candidates: Vec<Fact>,
    mut hydrate: impl FnMut(&mut [Fact]) -> bool,
    source: &dyn KotlinSource,
    realm: Option<&JvmSourceRealm<'_>>,
) -> DirectDescendantIndex
where
    Fact: KotlinHierarchyFact,
{
    candidates.sort_by(|left, right| left.declaration().cmp(right.declaration()));

    // Hydration is batched because each candidate needs two facts that are not
    // in the candidate row itself — the supertypes it spells and the file's
    // imports — and fetching those one declaration at a time would be a store
    // round-trip per class.
    let mut ancestors_by_owner: HashMap<CodeUnit, Vec<CodeUnit>> = HashMap::default();
    for batch_start in (0..candidates.len()).step_by(HIERARCHY_FACT_BATCH_SIZE) {
        let batch_end = (batch_start + HIERARCHY_FACT_BATCH_SIZE).min(candidates.len());
        let mut batch = candidates[batch_start..batch_end].to_vec();
        if !hydrate(&mut batch) {
            continue;
        }
        for facts in &batch {
            let resolved = kotlin_resolve_ancestors_from_facts(
                source,
                facts.declaration(),
                facts.raw_supertypes(),
                facts.imports(),
                realm,
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
            ancestors_by_owner
                .get(candidate)
                .cloned()
                .unwrap_or_default()
        },
    )
}

/// Resolve one declaration's ancestors from facts already in hand.
///
/// A supertype that does not resolve yields no ancestor. Kotlin code routinely
/// extends types from dependencies that are not on the configured classpath,
/// and inventing a declaration for one would put a name in the hierarchy that
/// no query can open.
fn kotlin_resolve_ancestors_from_facts(
    source: &dyn KotlinSource,
    owner: &CodeUnit,
    raw_supertypes: &[String],
    imports: &[ImportInfo],
    realm: Option<&JvmSourceRealm<'_>>,
) -> Vec<CodeUnit> {
    if raw_supertypes.is_empty() {
        return Vec::new();
    }
    let scope = KotlinNameScope {
        package_name: owner.package_name(),
        imports,
        scope_owners: kotlin_scope_owners_for(source, owner),
    };
    let mut ancestors = Vec::new();
    let mut seen = HashSet::default();
    for spelled in raw_supertypes {
        let KotlinTypeName::Resolved(fqn) =
            resolve_kotlin_type_name(spelled, &scope, |candidate| {
                kotlin_realm_type_exists(source, candidate, realm)
            })
        else {
            continue;
        };
        if let Some(unit) = kotlin_realm_type_by_fqn(source, &fqn, realm)
            && seen.insert(unit.fq_name())
        {
            ancestors.push(unit);
        }
    }
    ancestors
}
