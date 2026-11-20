//! Operation-owned evaluation of one immutable C# set publication.
use super::*;
use brokk_bifrost_core::retention_budget::{
    BudgetRegion, BudgetedValue, RetainedBytes, RetentionBudget,
};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

pub(in crate::analyzer::store) const RULE_GAPS_SQL: &str =
    "SELECT output_digest,json(gaps) FROM csharp_compilation_sets WHERE set_id=?1";
pub(in crate::analyzer::store) const RULE_COMPILATIONS_SQL: &str = "SELECT compilation_id,project_path,inventory_open,json(inventory_gap_indices) FROM csharp_compilations WHERE set_id=?1";
pub(in crate::analyzer::store) const RULE_ITEMS_SQL: &str = "SELECT compilation_id,ordinal,kind,rel_path,json(excluded_trees),json(gap_indices) FROM csharp_compilation_items WHERE set_id=?1";

/// Clones share initialization, including an admission-refused request-only value.
#[derive(Debug, Default)]
pub struct CSharpRuleIndexHandle(OnceLock<Result<Option<Arc<CSharpRuleIndex>>>>);
impl CSharpRuleIndexHandle {
    #[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
    pub fn get(
        &self,
        store: &AnalyzerStore,
        set: i64,
        digest: [u8; 32],
    ) -> Result<Option<Arc<CSharpRuleIndex>>> {
        let index = self
            .0
            .get_or_init(|| {
                let conn = store.read_conn()?;
                if conn
                    .query_row(
                        SET_MEMBERSHIP_SQL,
                        params![set, derivation_identity()],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                    .is_none()
                {
                    return Ok(None);
                }
                CSharpRuleIndex::load(&conn, store.retention_budget(), set, digest).map(Some)
            })
            .clone()?;
        if let Some(index) = &index {
            index.validate(set, digest);
        }
        Ok(index)
    }
}

/// A private region and its pinned answer; no registry outlives the operation.
pub struct CSharpRuleIndex {
    data: BudgetedValue<RuleData>,
    region: BudgetRegion<i64, RuleData>,
}
impl std::fmt::Debug for CSharpRuleIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CSharpRuleIndex")
            .field("set", &self.data.set)
            .field("digest", &self.data.digest)
            .finish()
    }
}
impl Drop for CSharpRuleIndex {
    fn drop(&mut self) {
        self.region.invalidate_all();
    }
}

#[derive(Debug)]
struct Rule {
    compilation: i64,
    ordinal: i64,
    kind: String,
    path: String,
    excluded: Vec<String>,
}
#[derive(Default)]
struct Bucket {
    rules: Vec<Rule>,
    // Open tree rules have no hidden-directory rule. Equal exclusions can be
    // tested once, before sharing the whole pre-expanded group with a path.
    open: BTreeMap<Vec<String>, BTreeMap<i64, Arc<[usize]>>>,
}
struct RuleData {
    set: i64,
    digest: [u8; 32],
    gaps: Vec<CSharpCompilationGap>,
    capped: bool,
    implicit: Option<i64>,
    exact: BTreeMap<String, Bucket>,
    trees: BTreeMap<String, Bucket>,
    regions: Vec<(i64, CSharpOpenRegion)>,
    compilations: BTreeMap<i64, (Option<String>, bool, Vec<usize>)>,
}

fn decode_indices(encoded: &str) -> Result<Vec<usize>> {
    serde_json::from_str(encoded)
        .map_err(|error| StoreError::corrupt(format!("invalid C# gap indices: {error}")))
}
impl RuleData {
    fn resolve_gaps(&self, indices: &[usize]) -> Result<Vec<CSharpCompilationGap>> {
        indices
            .iter()
            .map(|&index| {
                self.gaps
                    .get(index)
                    .cloned()
                    .ok_or_else(|| StoreError::corrupt(format!("invalid C# gap index {index}")))
            })
            .collect()
    }
}
impl RetainedBytes for RuleData {
    fn retained_bytes(&self) -> usize {
        #[allow(clippy::ptr_arg)] // The owning vector's spare capacity is retained.
        fn gaps_bytes(gaps: &Vec<CSharpCompilationGap>) -> usize {
            use brokk_bifrost_core::allocation_size::allocation_size;
            allocation_size(gaps.capacity() * std::mem::size_of::<CSharpCompilationGap>())
                + gaps
                    .iter()
                    .map(|gap| {
                        allocation_size(gap.code.capacity())
                            + allocation_size(gap.path.capacity())
                            + allocation_size(gap.evidence.capacity())
                    })
                    .sum::<usize>()
        }
        fn buckets_bytes(buckets: &BTreeMap<String, Bucket>) -> usize {
            use brokk_bifrost_core::allocation_size::allocation_size;
            buckets
                .iter()
                .map(|(path, bucket)| {
                    // Preserve the existing conservative per-node allowance; each
                    // separately owned buffer is sized at its own boundary.
                    allocation_size(
                        std::mem::size_of::<(String, Bucket)>() + 6 * std::mem::size_of::<usize>(),
                    ) + allocation_size(path.capacity())
                        + allocation_size(bucket.rules.capacity() * std::mem::size_of::<Rule>())
                        + bucket
                            .rules
                            .iter()
                            .map(|rule| {
                                allocation_size(rule.kind.capacity())
                                    + allocation_size(rule.path.capacity())
                                    + allocation_size(
                                        rule.excluded.capacity() * std::mem::size_of::<String>(),
                                    )
                                    + rule
                                        .excluded
                                        .iter()
                                        .map(|value| allocation_size(value.capacity()))
                                        .sum::<usize>()
                            })
                            .sum::<usize>()
                        + bucket
                            .open
                            .iter()
                            .map(|(excluded, owners)| {
                                allocation_size(
                                    std::mem::size_of::<(Vec<String>, BTreeMap<i64, Arc<[usize]>>)>(
                                    ) + 6 * std::mem::size_of::<usize>(),
                                ) + allocation_size(
                                    excluded.capacity() * std::mem::size_of::<String>(),
                                ) + excluded
                                    .iter()
                                    .map(|value| allocation_size(value.capacity()))
                                    .sum::<usize>()
                                    + owners
                                        .values()
                                        .map(|indices| {
                                            allocation_size(
                                                std::mem::size_of::<(i64, Arc<[usize]>)>()
                                                    + 6 * std::mem::size_of::<usize>(),
                                            ) + allocation_size(
                                                (indices.len() + 2) * std::mem::size_of::<usize>(),
                                            )
                                        })
                                        .sum::<usize>()
                            })
                            .sum::<usize>()
                })
                .sum::<usize>()
        }
        std::mem::size_of::<Self>()
            + gaps_bytes(&self.gaps)
            + brokk_bifrost_core::allocation_size::allocation_size(
                self.regions.capacity() * std::mem::size_of::<(i64, CSharpOpenRegion)>(),
            )
            + self
                .regions
                .iter()
                .map(|(_, region)| {
                    brokk_bifrost_core::allocation_size::allocation_size(region.kind.capacity())
                        + brokk_bifrost_core::allocation_size::allocation_size(
                            region.rel_path.capacity(),
                        )
                        + gaps_bytes(&region.gaps)
                })
                .sum::<usize>()
            + buckets_bytes(&self.exact)
            + buckets_bytes(&self.trees)
            + self
                .compilations
                .values()
                .map(|(path, _, indices)| {
                    std::mem::size_of::<(i64, (Option<String>, bool, Vec<usize>))>()
                        + 6 * std::mem::size_of::<usize>()
                        + path.as_ref().map_or(0, |value| {
                            brokk_bifrost_core::allocation_size::allocation_size(value.capacity())
                        })
                        + brokk_bifrost_core::allocation_size::allocation_size(
                            indices.capacity() * std::mem::size_of::<usize>(),
                        )
                })
                .sum::<usize>()
    }
}

#[cfg(test)]
thread_local! {
    static WORK: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

impl CSharpRuleIndex {
    pub(super) fn load(
        conn: &Connection,
        budget: &RetentionBudget,
        set: i64,
        digest: [u8; 32],
    ) -> Result<Arc<Self>> {
        // Only this statement touches the large document. All subsequent reads
        // select narrow columns and resolve indices in this decoded table.
        let (actual, encoded): ([u8; 32], String) =
            conn.query_row(RULE_GAPS_SQL, [set], |row| Ok((row.get(0)?, row.get(1)?)))?;
        debug_assert_eq!(digest, actual);
        let gaps = decode_gaps(&encoded)?;
        #[cfg(test)]
        WORK.with(|work| {
            let (decodes, roots) = work.get();
            work.set((decodes + 1, roots));
        });
        let mut data = RuleData {
            set,
            digest,
            capped: gaps.iter().any(|gap| is_membership_cap(&gap.code)),
            gaps,
            implicit: None,
            exact: BTreeMap::new(),
            trees: BTreeMap::new(),
            regions: Vec::new(),
            compilations: BTreeMap::new(),
        };
        let mut statement = conn.prepare_cached(RULE_COMPILATIONS_SQL)?;
        let mut rows = statement.query([set])?;
        while let Some(row) = rows.next()? {
            let id = row.get(0)?;
            let path: Option<String> = row.get(1)?;
            if path.is_none() {
                data.implicit = Some(id);
            }
            data.compilations.insert(
                id,
                (
                    path,
                    row.get(2)?,
                    decode_indices(&row.get::<_, String>(3)?)?,
                ),
            );
        }
        let mut statement = conn.prepare_cached(RULE_ITEMS_SQL)?;
        let mut rows = statement.query([set])?;
        // Build with vectors, then freeze each owner's region list once.
        type Pending = BTreeMap<(bool, String, Vec<String>, i64), Vec<usize>>;
        let mut pending: Pending = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let kind: String = row.get(2)?;
            let tree = matches!(kind.as_str(), "include_tree" | "default_tree" | "open_tree");
            let rule = Rule {
                compilation: row.get(0)?,
                ordinal: row.get(1)?,
                kind,
                path: row.get(3)?,
                excluded: if tree {
                    serde_json::from_str(&row.get::<_, String>(4)?).map_err(|error| {
                        StoreError::corrupt(format!("invalid C# excluded trees: {error}"))
                    })?
                } else {
                    Vec::new()
                },
            };
            if matches!(rule.kind.as_str(), "open" | "open_tree") {
                let gaps = data.resolve_gaps(&decode_indices(&row.get::<_, String>(5)?)?)?;
                if gaps.is_empty() {
                    return Err(StoreError::corrupt("open C# item lacks gap evidence"));
                }
                let index = data.regions.len();
                #[cfg(test)]
                if tree && rule.path.is_empty() {
                    WORK.with(|work| {
                        let (decodes, roots) = work.get();
                        work.set((decodes, roots + 1));
                    });
                }
                data.regions.push((
                    rule.ordinal,
                    CSharpOpenRegion {
                        kind: rule.kind,
                        rel_path: rule.path.clone(),
                        gaps,
                    },
                ));
                pending
                    .entry((tree, rule.path, rule.excluded, rule.compilation))
                    .or_default()
                    .push(index);
            } else {
                let buckets = if tree {
                    &mut data.trees
                } else {
                    &mut data.exact
                };
                buckets
                    .entry(rule.path.clone())
                    .or_default()
                    .rules
                    .push(rule);
            }
        }
        for ((tree, path, excluded, owner), mut indices) in pending {
            indices.sort_by_key(|&index| data.regions[index].0);
            let buckets = if tree {
                &mut data.trees
            } else {
                &mut data.exact
            };
            buckets
                .entry(path)
                .or_default()
                .open
                .entry(excluded)
                .or_default()
                .insert(owner, indices.into());
        }
        let region = budget.region("store.csharp-request-rules", None);
        let data = region.insert(set, data);
        Ok(Arc::new(Self { data, region }))
    }
    pub fn validate(&self, set: i64, digest: [u8; 32]) {
        debug_assert_eq!((self.data.set, self.data.digest), (set, digest));
    }
    pub fn membership_capped(&self) -> bool {
        self.data.capped
    }
    pub(super) fn gaps(&self) -> Vec<CSharpCompilationGap> {
        self.data.gaps.clone()
    }
    pub(super) fn inventory_gaps(&self, compilation: i64) -> Result<Vec<CSharpCompilationGap>> {
        let (_, open, indices) = self
            .data
            .compilations
            .get(&compilation)
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        let gaps = self.data.resolve_gaps(indices)?;
        if *open && gaps.is_empty() {
            return Err(StoreError::corrupt("open C# inventory has no gap evidence"));
        }
        Ok(gaps)
    }
    pub(super) fn indexed_gaps(&self, encoded: &str) -> Result<Vec<CSharpCompilationGap>> {
        self.data.resolve_gaps(&decode_indices(encoded)?)
    }
    fn buckets<'a>(&'a self, path: &'a str) -> impl Iterator<Item = &'a Bucket> {
        let trees = path
            .rsplit_once('.')
            .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("cs"))
            .then_some(&self.data.trees);
        self.data
            .exact
            .get(path)
            .into_iter()
            .chain(trees.into_iter().flat_map(move |trees| {
                trees
                    .get("")
                    .into_iter()
                    .chain(path.bytes().enumerate().filter_map(move |(index, byte)| {
                        if byte == b'/' {
                            trees.get(&path[..index])
                        } else {
                            None
                        }
                    }))
            }))
    }

    /// Parse preparation needs closed ownership only. An applicable open group
    /// proves it unknown without visiting any owner or expanding any causes.
    pub fn closed_owners(&self, path: &str) -> Option<Vec<i64>> {
        if self.membership_capped()
            || self.buckets(path).any(|bucket| {
                bucket
                    .open
                    .keys()
                    .any(|exclusions| !excluded(path, exclusions))
            })
        {
            return None;
        }
        Some(self.membership(path).proven)
    }

    pub fn membership(&self, path: &str) -> CSharpMembership {
        let mut rules = Vec::new();
        let mut open: BTreeMap<i64, Vec<Arc<[usize]>>> = BTreeMap::new();
        for bucket in self.buckets(path) {
            rules.extend(bucket.rules.iter().filter(|rule| {
                let hidden = rule.kind == "default_tree" && {
                    let relative = if rule.path.is_empty() {
                        path
                    } else {
                        path.strip_prefix(&rule.path)
                            .and_then(|suffix| suffix.strip_prefix('/'))
                            .expect("tree rule root is an ancestor")
                    };
                    relative
                        .split('/')
                        .rev()
                        .skip(1)
                        .any(|directory| directory.starts_with('.'))
                };
                !hidden && !excluded(path, &rule.excluded)
            }));
            for (exclusions, owners) in &bucket.open {
                if !excluded(path, exclusions) {
                    for (&owner, regions) in owners {
                        open.entry(owner).or_default().push(regions.clone());
                    }
                }
            }
        }
        rules.sort_by_key(|rule| (rule.compilation, rule.ordinal));
        let mut members = BTreeMap::new();
        if let Some(id) = self.data.implicit {
            members.insert(id, true);
        }
        for rule in rules {
            members.insert(rule.compilation, rule.kind != "remove");
        }
        let proven = members
            .into_iter()
            .filter_map(|(id, member)| (member && !open.contains_key(&id)).then_some(id))
            .collect();
        let open = open
            .into_iter()
            .map(|(id, chunks)| CSharpOpenPlacement {
                compilation_id: id,
                project_path: self.data.compilations[&id].0.clone(),
                regions: CSharpOpenRegions {
                    data: self.data.clone(),
                    chunks,
                },
            })
            .collect();
        CSharpMembership { proven, open }
    }
}
fn excluded(path: &str, exclusions: &[String]) -> bool {
    exclusions.iter().any(|directory| {
        directory.is_empty()
            || path
                .strip_prefix(directory)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// An ordinal-ordered view of pre-expanded groups. Looking up a path clones
/// group handles, never the root's region list or its diagnostic causes.
pub struct CSharpOpenRegions {
    data: BudgetedValue<RuleData>,
    chunks: Vec<Arc<[usize]>>,
}
impl CSharpOpenRegions {
    pub fn iter(&self) -> CSharpOpenRegionsIter<'_> {
        CSharpOpenRegionsIter {
            regions: self,
            positions: vec![0; self.chunks.len()],
        }
    }
    pub fn len(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.chunks.iter().all(|chunk| chunk.is_empty())
    }
}
pub struct CSharpOpenRegionsIter<'a> {
    regions: &'a CSharpOpenRegions,
    positions: Vec<usize>,
}
impl<'a> Iterator for CSharpOpenRegionsIter<'a> {
    type Item = &'a CSharpOpenRegion;
    fn next(&mut self) -> Option<Self::Item> {
        let (chunk, index) = self
            .regions
            .chunks
            .iter()
            .enumerate()
            .filter_map(|(chunk, indices)| {
                indices
                    .get(self.positions[chunk])
                    .map(|&index| (chunk, index))
            })
            .min_by_key(|&(_, index)| self.regions.data.regions[index].0)?;
        self.positions[chunk] += 1;
        Some(&self.regions.data.regions[index].1)
    }
}
impl std::ops::Index<usize> for CSharpOpenRegions {
    type Output = CSharpOpenRegion;
    fn index(&self, index: usize) -> &Self::Output {
        self.iter().nth(index).expect("open region index in bounds")
    }
}
impl std::fmt::Debug for CSharpOpenRegions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#12290: C# compilation membership re-read the whole gaps value per item and expanded every root cause per path"
    )]
    fn compilation_rule_work_is_shared_and_admission_preserves_answers() {
        for gap_count in [1, 4, 16] {
            let mut admitted_answers = Vec::new();
            for capacity in [16 * 1024 * 1024, 0] {
                let budget = RetentionBudget::for_test_capacity(capacity);
                let store =
                    AnalyzerStore::open_ephemeral_temp_file(&Default::default(), &budget).unwrap();
                let generation = store
                    .ensure_language_epoch_value("csharp", "12290-fixture")
                    .unwrap();
                let set = {
                    let mut conn = store.conn.lock().unwrap();
                    let tx = conn.transaction().unwrap();
                    let facts = CSharpCompilationFacts {
                        gaps: (0..gap_count)
                            .map(|index| CSharpCompilationGap {
                                code: "unsupported_project_items".into(),
                                path: "Directory.Build.props".into(),
                                evidence: format!(
                                    "shared import item {index}: {}",
                                    "evidence".repeat(index + 1)
                                ),
                            })
                            .collect(),
                        compilations: ["App/App.csproj", "Peer/Peer.csproj"]
                            .into_iter()
                            .map(|path| CSharpCompilationFact {
                                project_path: Some(path.into()),
                                inventory_gap_indices: (0..gap_count).collect(),
                                items: (0..gap_count)
                                    .map(|index| CSharpCompileItem {
                                        kind: CSharpCompileItemKind::OpenTree,
                                        rel_path: String::new(),
                                        excluded_trees: vec!["Excluded".into()],
                                        gap_indices: vec![index],
                                    })
                                    .chain([
                                        CSharpCompileItem {
                                            kind: CSharpCompileItemKind::DefaultTree,
                                            rel_path: "App".into(),
                                            excluded_trees: vec!["App/obj".into()],
                                            gap_indices: vec![],
                                        },
                                        CSharpCompileItem {
                                            kind: CSharpCompileItemKind::Remove,
                                            rel_path: "App/Removed.cs".into(),
                                            excluded_trees: vec![],
                                            gap_indices: vec![],
                                        },
                                        CSharpCompileItem {
                                            kind: CSharpCompileItemKind::Include,
                                            rel_path: "Linked.cs".into(),
                                            excluded_trees: vec![],
                                            gap_indices: vec![],
                                        },
                                        CSharpCompileItem {
                                            kind: CSharpCompileItemKind::Open,
                                            rel_path: "App/Source0.cs".into(),
                                            excluded_trees: vec![],
                                            gap_indices: vec![0],
                                        },
                                    ])
                                    .collect(),
                                ..Default::default()
                            })
                            .collect(),
                        ..Default::default()
                    };
                    let set = insert_set(
                        &tx,
                        &WorkspaceId("a".repeat(64)),
                        generation,
                        &[1; 32],
                        &facts,
                    )
                    .unwrap();
                    tx.commit().unwrap();
                    set
                };
                for source_count in [8, 16] {
                    WORK.with(|work| work.set((0, 0)));
                    let handle = Arc::new(CSharpRuleIndexHandle::default());
                    let mut answers = Vec::new();
                    for source in 0..source_count {
                        let clone = handle.clone();
                        let index = clone
                            .get(&store, set.id, set.output_digest)
                            .unwrap()
                            .unwrap();
                        assert_eq!(
                            matches!(index.data, BudgetedValue::Retained(_)),
                            capacity != 0
                        );
                        let membership = index.membership(&format!("App/Source{source}.cs"));
                        assert!(
                            index
                                .closed_owners(&format!("App/Source{source}.cs"))
                                .is_none()
                        );
                        assert_eq!(membership.open.len(), 2);
                        assert_eq!(
                            membership.open[0].regions.len(),
                            gap_count + usize::from(source == 0)
                        );
                        assert!(membership.proven.is_empty());
                        answers.push(format!("{membership:?}"));
                    }
                    assert_eq!(
                        WORK.with(std::cell::Cell::get),
                        (1, 2 * gap_count),
                        "{source_count} paths, {gap_count} gaps, capacity {capacity}"
                    );
                    let index = handle
                        .get(&store, set.id, set.output_digest)
                        .unwrap()
                        .unwrap();
                    assert!(index.membership("Excluded/Other.cs").open.is_empty());
                    assert!(index.membership("Other.txt").open.is_empty());
                    assert_eq!(
                        index
                            .inventory_gaps(index.data.compilations.keys().next().copied().unwrap())
                            .unwrap(),
                        index.gaps()
                    );
                    // An answer keeps the backing and its admission charge after
                    // both the configuration and its private region are gone.
                    let membership = index.membership("App/Source0.cs");
                    let expected = format!("{membership:?}");
                    let backing_bytes = index.data.retained_bytes() as u64;
                    drop(index);
                    drop(handle);
                    budget.run_pending_tasks();
                    assert_eq!(format!("{membership:?}"), expected);
                    if capacity != 0 {
                        assert!(budget.accounted_bytes() >= backing_bytes);
                        let with_answer = budget.accounted_bytes();
                        drop(membership);
                        budget.run_pending_tasks();
                        assert!(with_answer - budget.accounted_bytes() >= backing_bytes);
                    }
                    if capacity != 0 {
                        admitted_answers.push(answers);
                    } else {
                        assert_eq!(answers, admitted_answers[usize::from(source_count == 16)]);
                    }
                }
            }
        }
    }

    #[test]
    #[ignore = "operator: requires BIFROST_12290_STORE_PATH naming a read-only corpus snapshot"]
    fn measure_csharp_rule_index_read_only() {
        use brokk_bifrost_core::profiling::thread_cpu_time;
        let path = std::env::var_os("BIFROST_12290_STORE_PATH").expect("corpus snapshot path");
        let conn = Connection::open_with_flags(
            std::path::Path::new(&path),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let (set, digest): (i64, [u8; 32]) = conn
            .query_row(
                "SELECT set_id,output_digest FROM csharp_compilation_sets ORDER BY set_id LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let paths = conn.prepare("SELECT DISTINCT rel_path FROM csharp_compilation_items WHERE set_id=?1 AND kind='include' ORDER BY rel_path").unwrap().query_map([set], |row| row.get::<_,String>(0)).unwrap().map(|row| row.unwrap()).filter(|path| std::path::Path::new(path).extension().and_then(|extension| extension.to_str()).is_some_and(|extension| extension.eq_ignore_ascii_case("cs"))).collect::<Vec<_>>();
        assert!(
            paths.len() >= 50,
            "corpus must have at least 50 explicit C# paths"
        );
        let budget = RetentionBudget::new(1024 * 1024 * 1024);
        WORK.with(|work| work.set((0, 0)));
        let start = thread_cpu_time();
        let index = CSharpRuleIndex::load(&conn, &budget, set, digest).unwrap();
        let load_cpu = thread_cpu_time() - start;
        let start = thread_cpu_time();
        let mut placements = 0;
        let mut regions = 0;
        for sample in 0..50 {
            let membership = index.membership(&paths[sample * paths.len() / 50]);
            placements += membership.open.len();
            regions += membership
                .open
                .iter()
                .map(|open| open.regions.len())
                .sum::<usize>();
            std::hint::black_box(membership);
        }
        let lookup_cpu = thread_cpu_time() - start;
        eprintln!(
            "#12290 read-only corpus: paths=50 load_cpu={load_cpu:?} lookup_cpu={lookup_cpu:?} admitted={} work={:?} placements={placements} region_handles={regions} owner_accounted_bytes={}",
            matches!(index.data, BudgetedValue::Retained(_)),
            WORK.with(std::cell::Cell::get),
            budget.accounted_bytes()
        );
    }
}
