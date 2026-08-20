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
use brokk_bifrost_core::analyzer::model::{CodeUnit, ImportInfo, Language, Range};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};

use crate::java::graph_support::{
    JavaSource, resolve_java_forward_type_name, resolve_java_lexical_type_name,
};
use crate::java::imports::non_static_import_path;

const HIERARCHY_FACT_BATCH_SIZE: usize = 4_096;

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

/// Whether `code_unit` is declared as an interface rather than a class.
pub fn java_is_interface(source: &dyn CodeUnitIndex, code_unit: &CodeUnit) -> bool {
    code_unit.is_class()
        && source.signatures(code_unit).iter().any(|signature| {
            signature
                .split_whitespace()
                .any(|token| token == "interface")
        })
}

/// Prefer class owners over interface owners at one Java hierarchy
/// level. When no class declares the applicable member, every interface owner
/// remains a peer so callers can preserve honest ambiguity.
pub fn java_preferred_declaring_owners(
    source: &dyn CodeUnitIndex,
    owners: &[CodeUnit],
) -> Vec<CodeUnit> {
    let class_owners = owners
        .iter()
        .filter(|owner| !java_is_interface(source, owner))
        .cloned()
        .collect::<Vec<_>>();
    if class_owners.is_empty() {
        owners.to_vec()
    } else {
        class_owners
    }
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
/// `None` means no ancestor level declares the member at all -- either the
/// hierarchy is exhausted or the declaring supertype is outside the workspace.
/// A returned vector holding more than one owner is honest ambiguity: two
/// unrelated interfaces at the same distance both declare the name, and no
/// caller may choose between them.
pub fn java_nearest_declaring_ancestors(
    source: &dyn CodeUnitIndex,
    provider: &dyn TypeHierarchyProvider,
    owner: &CodeUnit,
    mut declares: impl FnMut(&CodeUnit) -> bool,
) -> Option<Vec<CodeUnit>> {
    let mut seen = HashSet::from_iter([owner.clone()]);
    let mut level = provider.get_direct_ancestors(owner);
    while !level.is_empty() {
        let mut declaring_owners = Vec::new();
        let mut next_level = Vec::new();
        for ancestor in level {
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            if declares(&ancestor) {
                declaring_owners.push(ancestor.clone());
            }
            next_level.extend(provider.get_direct_ancestors(&ancestor));
        }
        if !declaring_owners.is_empty() {
            return Some(java_preferred_declaring_owners(source, &declaring_owners));
        }
        level = next_level;
    }
    None
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
            resolve_java_lexical_type_name(source, code_unit, raw_name).or_else(|| {
                resolve_java_forward_type_name(source, token, code_unit.source(), raw_name)
            })
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

fn java_definition_sort_key(
    candidate: &CodeUnit,
    range: Option<&Range>,
) -> (usize, String, String, String, String) {
    (
        range.map_or(usize::MAX, |range| range.start_byte),
        candidate.source().to_string().to_ascii_lowercase(),
        candidate.fq_name().to_ascii_lowercase(),
        candidate.signature().unwrap_or("").to_ascii_lowercase(),
        format!("{:?}", candidate.kind()),
    )
}

fn resolve_hierarchy_type_index(
    raw_name: &str,
    candidate: &CodeUnit,
    imports: &[ImportInfo],
    types_by_fq_name: &HashMap<String, JavaHierarchyTypeBucket>,
) -> Option<usize> {
    let normalized = raw_name.trim();
    if normalized.is_empty() {
        return None;
    }

    if normalized.contains('.')
        && let Some(index) = hierarchy_type_index(types_by_fq_name, normalized)
    {
        return Some(index);
    }

    if let Some(index) =
        resolve_lexical_hierarchy_type_index(normalized, candidate, types_by_fq_name)
    {
        return Some(index);
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
        if normalized == imported_name
            && let Some(index) =
                hierarchy_type_index(types_by_fq_name, &import_path.render_segments("."))
        {
            return Some(index);
        }
        if let Some(rest) = normalized
            .strip_prefix(imported_name)
            .and_then(|rest| rest.strip_prefix('.'))
        {
            let nested_fqn = format!("{}.{rest}", import_path.render_segments("."));
            if let Some(index) = hierarchy_type_index(types_by_fq_name, &nested_fqn) {
                return Some(index);
            }
        }
    }

    for import in imports {
        let Some(import_path) = non_static_import_path(import) else {
            continue;
        };
        if !import.is_wildcard {
            continue;
        }
        let fqn = format!("{}.{normalized}", import_path.render_segments("."));
        if let Some(index) = hierarchy_type_index(types_by_fq_name, &fqn) {
            return Some(index);
        }
    }

    let same_package_fqn = if package_name.is_empty() {
        normalized.to_string()
    } else {
        format!("{package_name}.{normalized}")
    };
    hierarchy_type_index(types_by_fq_name, &same_package_fqn)
        .or_else(|| hierarchy_type_index(types_by_fq_name, normalized))
}

fn resolve_lexical_hierarchy_type_index(
    normalized: &str,
    candidate: &CodeUnit,
    types_by_fq_name: &HashMap<String, JavaHierarchyTypeBucket>,
) -> Option<usize> {
    if normalized.contains('.') {
        return None;
    }
    let package_end = candidate.package_segment_count();
    let type_end = candidate.fq().len().saturating_sub(1);
    let interner = segment_interner();
    for owner_end in (package_end.saturating_add(1)..=type_end).rev() {
        let owner = candidate.fq().prefix(owner_end);
        let target = owner.with_pushed(interner.intern(normalized, SegmentKind::Type));
        let target_fqn = target.display_native(Language::Java, interner);
        if let Some(index) = hierarchy_type_index(types_by_fq_name, &target_fqn) {
            return Some(index);
        }
    }
    None
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
    let mut same_source = bucket
        .declarations
        .iter()
        .copied()
        .filter(|index| candidates[*index].declaration().source() == descendant.source());
    let Some(exact) = same_source.next() else {
        return resolved;
    };
    if same_source.next().is_none() {
        exact
    } else {
        resolved
    }
}
