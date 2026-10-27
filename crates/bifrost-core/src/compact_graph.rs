//! Compact immutable row and directed-graph storage for read-heavy snapshots.

use crate::hash::HashMap;
use std::hash::Hash;

pub(crate) fn normalize_indexed_edges<K: Eq + Hash>(
    nodes: &[K],
    index_by_node: &HashMap<K, u32>,
    edges: &mut Vec<(u32, u32)>,
) {
    assert_eq!(nodes.len(), index_by_node.len());
    assert!(nodes.iter().enumerate().all(|(index, node)| {
        index_by_node.get(node).copied()
            == Some(u32::try_from(index).expect("indexed graph nodes must fit in a u32"))
    }));
    assert!(edges.iter().all(|(source, target)| {
        (*source as usize) < nodes.len() && (*target as usize) < nodes.len()
    }));
    edges.sort_unstable();
    edges.dedup();
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactRows<T> {
    offsets: Box<[u32]>,
    values: Box<[T]>,
}

impl<T> CompactRows<T> {
    pub fn from_parts(offsets: Vec<u32>, values: Vec<T>) -> Self {
        Self::try_from_parts(offsets, values).expect("invalid compact row parts")
    }

    /// Construct compact rows from an untrusted persisted representation.
    ///
    /// Builders enforce these invariants by construction, while snapshot
    /// decoding must reject corrupt boundaries instead of panicking.
    pub fn try_from_parts(offsets: Vec<u32>, values: Vec<T>) -> Result<Self, &'static str> {
        if offsets.is_empty() {
            return Err("compact rows require the zero boundary");
        }
        if offsets[0] != 0 {
            return Err("compact row offsets must start at zero");
        }
        if offsets.last().copied().map(|value| value as usize) != Some(values.len()) {
            return Err("compact row offsets must end at the value count");
        }
        if !offsets.windows(2).all(|pair| pair[0] <= pair[1]) {
            return Err("compact row offsets must be monotonic");
        }
        Ok(Self {
            offsets: offsets.into_boxed_slice(),
            values: values.into_boxed_slice(),
        })
    }

    pub fn rows(&self) -> usize {
        self.offsets.len() - 1
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn offsets(&self) -> &[u32] {
        &self.offsets
    }

    pub fn values(&self) -> &[T] {
        &self.values
    }

    pub fn row(&self, row: usize) -> &[T] {
        let start = self.offsets[row] as usize;
        let end = self.offsets[row + 1] as usize;
        &self.values[start..end]
    }

    pub fn estimated_bytes(&self) -> u64 {
        (self.offsets.len() as u64)
            .saturating_mul(std::mem::size_of::<u32>() as u64)
            .saturating_add(
                (self.values.len() as u64).saturating_mul(std::mem::size_of::<T>() as u64),
            )
    }
}

pub struct CompactRowsBuilder<T> {
    offsets: Vec<u32>,
    values: Vec<T>,
}

impl<T> CompactRowsBuilder<T> {
    pub fn with_capacity(rows: usize, values: usize) -> Self {
        let mut offsets = Vec::with_capacity(rows.saturating_add(1));
        offsets.push(0);
        Self {
            offsets,
            values: Vec::with_capacity(values),
        }
    }

    pub fn values_mut(&mut self) -> &mut Vec<T> {
        &mut self.values
    }

    pub fn rows(&self) -> usize {
        self.offsets.len() - 1
    }

    pub fn finish_row(&mut self) {
        self.offsets
            .push(u32::try_from(self.values.len()).expect("compact row values must fit in a u32"));
    }

    pub fn push_row(&mut self, values: impl IntoIterator<Item = T>) {
        self.values.extend(values);
        self.finish_row();
    }

    pub fn finish(self) -> CompactRows<T> {
        CompactRows::from_parts(self.offsets, self.values)
    }
}

/// Snapshot-local dense identity plus outgoing CSR and incoming CSC rows.
#[derive(Debug)]
pub struct CompactDirectedGraph<K> {
    nodes: Box<[K]>,
    index_by_node: HashMap<K, u32>,
    outgoing: CompactRows<u32>,
    incoming: CompactRows<u32>,
}

impl<K> CompactDirectedGraph<K>
where
    K: Clone + Eq + Hash,
{
    pub fn new(nodes: Vec<K>, edges: Vec<(u32, u32)>) -> Self {
        let node_count = nodes.len();
        assert!(
            u32::try_from(node_count).is_ok(),
            "compact graph nodes must fit in a u32"
        );
        let mut index_by_node = HashMap::default();
        for (index, node) in nodes.iter().enumerate() {
            assert!(
                index_by_node.insert(node.clone(), index as u32).is_none(),
                "compact graph nodes must be unique"
            );
        }
        Self::from_indexed_nodes(nodes, index_by_node, edges)
    }

    pub fn from_indexed_nodes(
        nodes: Vec<K>,
        index_by_node: HashMap<K, u32>,
        mut edges: Vec<(u32, u32)>,
    ) -> Self {
        let node_count = nodes.len();
        assert!(
            u32::try_from(node_count).is_ok(),
            "compact graph nodes must fit in a u32"
        );
        normalize_indexed_edges(&nodes, &index_by_node, &mut edges);

        let mut outgoing = CompactRowsBuilder::with_capacity(node_count, edges.len());
        let mut cursor = 0usize;
        for source in 0..node_count as u32 {
            let start = cursor;
            while cursor < edges.len() && edges[cursor].0 == source {
                cursor += 1;
            }
            outgoing.push_row(edges[start..cursor].iter().map(|(_, target)| *target));
        }

        edges.sort_unstable_by_key(|(source, target)| (*target, *source));
        let mut incoming = CompactRowsBuilder::with_capacity(node_count, edges.len());
        cursor = 0;
        for target in 0..node_count as u32 {
            let start = cursor;
            while cursor < edges.len() && edges[cursor].1 == target {
                cursor += 1;
            }
            incoming.push_row(edges[start..cursor].iter().map(|(source, _)| *source));
        }

        Self {
            nodes: nodes.into_boxed_slice(),
            index_by_node,
            outgoing: outgoing.finish(),
            incoming: incoming.finish(),
        }
    }

    pub fn nodes(&self) -> &[K] {
        &self.nodes
    }

    pub fn node_id(&self, node: &K) -> Option<u32> {
        self.index_by_node.get(node).copied()
    }

    pub fn outgoing(&self, node: u32) -> &[u32] {
        self.outgoing.row(node as usize)
    }

    pub fn incoming(&self, node: u32) -> &[u32] {
        self.incoming.row(node as usize)
    }

    pub fn edge_count(&self) -> usize {
        self.outgoing.len()
    }

    pub fn estimated_bytes(&self) -> u64 {
        Self::estimated_bytes_for_parts(
            self.nodes.len(),
            self.index_by_node.capacity(),
            self.edge_count(),
        )
    }

    pub fn estimated_bytes_for_parts(
        node_count: usize,
        index_capacity: usize,
        edge_count: usize,
    ) -> u64 {
        let rows_bytes = ((node_count.saturating_add(1)) as u64)
            .saturating_mul(std::mem::size_of::<u32>() as u64)
            .saturating_add((edge_count as u64).saturating_mul(std::mem::size_of::<u32>() as u64));
        (std::mem::size_of::<Self>() as u64)
            .saturating_add((node_count as u64).saturating_mul(std::mem::size_of::<K>() as u64))
            .saturating_add(
                (index_capacity as u64)
                    .saturating_mul((std::mem::size_of::<(K, u32)>() + 1) as u64),
            )
            .saturating_add(rows_bytes.saturating_mul(2))
    }
}

#[cfg(test)]
mod tests {
    use super::{CompactRows, CompactRowsBuilder};

    #[test]
    fn checked_compact_rows_reject_corrupt_boundaries() {
        assert!(CompactRows::<u32>::try_from_parts(Vec::new(), vec![]).is_err());
        assert!(CompactRows::try_from_parts(vec![1], vec![7_u32]).is_err());
        assert!(CompactRows::try_from_parts(vec![0, 2], vec![7_u32]).is_err());
        assert!(CompactRows::try_from_parts(vec![0, 2, 1], vec![7_u32]).is_err());

        let rows = CompactRows::try_from_parts(vec![0, 0, 2], vec![7_u32, 8])
            .expect("valid decoded compact rows");
        assert!(rows.row(0).is_empty());
        assert_eq!(rows.row(1), &[7, 8]);
    }

    #[test]
    fn compact_rows_preserve_empty_rows_and_value_order() {
        let mut rows = CompactRowsBuilder::with_capacity(3, 3);
        rows.push_row([1, 2]);
        rows.push_row([]);
        rows.push_row([3]);
        let rows = rows.finish();

        assert_eq!(rows.rows(), 3);
        assert_eq!(rows.row(0), [1, 2]);
        assert!(rows.row(1).is_empty());
        assert_eq!(rows.row(2), [3]);
    }
}

#[cfg(test)]
mod compact_graph_properties {
    use super::{CompactDirectedGraph, CompactRows, CompactRowsBuilder, normalize_indexed_edges};
    use crate::hash::HashMap;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    /// A node count and an edge list over it. The list may contain duplicates,
    /// self loops and any ordering; it is empty when there are no nodes.
    fn graph_input() -> impl Strategy<Value = (usize, Vec<(u32, u32)>)> {
        (0usize..9).prop_flat_map(|count| {
            let edges = if count == 0 {
                Just(Vec::new()).boxed()
            } else {
                let node = 0..count as u32;
                prop::collection::vec((node.clone(), node), 0..40).boxed()
            };
            (Just(count), edges)
        })
    }

    fn node_names(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("node-{index}")).collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Normalization yields the sorted, deduplicated edge set.
        #[test]
        fn normalize_indexed_edges_is_sorted_set((count, edges) in graph_input()) {
            let nodes = node_names(count);
            let index_by_node: HashMap<String, u32> = nodes
                .iter()
                .enumerate()
                .map(|(index, node)| (node.clone(), index as u32))
                .collect();
            let expected: Vec<(u32, u32)> =
                edges.iter().copied().collect::<BTreeSet<_>>().into_iter().collect();

            let mut actual = edges;
            normalize_indexed_edges(&nodes, &index_by_node, &mut actual);
            prop_assert_eq!(actual, expected);
        }

        /// Adjacency, edge count and node identity match a set-of-pairs
        /// reference, through both constructors.
        #[test]
        fn directed_graph_matches_edge_set_reference((count, edges) in graph_input()) {
            let nodes = node_names(count);
            let reference: BTreeSet<(u32, u32)> = edges.iter().copied().collect();

            let from_new = CompactDirectedGraph::new(nodes.clone(), edges.clone());
            let index_by_node: HashMap<String, u32> = nodes
                .iter()
                .enumerate()
                .map(|(index, node)| (node.clone(), index as u32))
                .collect();
            let from_indexed =
                CompactDirectedGraph::from_indexed_nodes(nodes.clone(), index_by_node, edges);

            for graph in [&from_new, &from_indexed] {
                prop_assert_eq!(graph.nodes(), nodes.as_slice());
                prop_assert_eq!(graph.edge_count(), reference.len());
                for (index, node) in nodes.iter().enumerate() {
                    prop_assert_eq!(graph.node_id(node), Some(index as u32));
                }
                prop_assert_eq!(graph.node_id(&"absent".to_string()), None);

                for node in 0..count as u32 {
                    let outgoing: Vec<u32> = reference
                        .iter()
                        .filter(|(source, _)| *source == node)
                        .map(|(_, target)| *target)
                        .collect();
                    let mut incoming: Vec<u32> = reference
                        .iter()
                        .filter(|(_, target)| *target == node)
                        .map(|(source, _)| *source)
                        .collect();
                    incoming.sort_unstable();
                    prop_assert_eq!(graph.outgoing(node), outgoing.as_slice());
                    prop_assert_eq!(graph.incoming(node), incoming.as_slice());
                }
            }
        }

        /// Rows built with `push_row` and with `values_mut` plus `finish_row`
        /// read back as the source rows, and the flat accessors agree with
        /// their concatenation and running lengths.
        #[test]
        fn rows_builder_round_trips_nested_vectors(
            source in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..6), 0..8),
            use_push_row in prop::collection::vec(any::<bool>(), 8),
        ) {
            let flat: Vec<u8> = source.iter().flatten().copied().collect();
            let mut offsets = vec![0u32];
            for row in &source {
                offsets.push(offsets.last().unwrap() + row.len() as u32);
            }

            let mut builder = CompactRowsBuilder::with_capacity(source.len(), flat.len());
            for (row, push) in source.iter().zip(use_push_row.iter().cycle()) {
                if *push {
                    builder.push_row(row.iter().copied());
                } else {
                    builder.values_mut().extend_from_slice(row);
                    builder.finish_row();
                }
            }
            prop_assert_eq!(builder.rows(), source.len());
            let rows = builder.finish();

            prop_assert_eq!(rows.rows(), source.len());
            prop_assert_eq!(rows.len(), flat.len());
            prop_assert_eq!(rows.is_empty(), flat.is_empty());
            prop_assert_eq!(rows.offsets(), offsets.as_slice());
            prop_assert_eq!(rows.values(), flat.as_slice());
            for (index, row) in source.iter().enumerate() {
                prop_assert_eq!(rows.row(index), row.as_slice());
            }
            prop_assert_eq!(
                CompactRows::try_from_parts(offsets, flat).expect("builder parts are valid"),
                rows
            );
        }
    }

    #[test]
    #[should_panic(expected = "compact graph nodes must be unique")]
    fn new_rejects_duplicate_nodes() {
        CompactDirectedGraph::new(vec!["a", "b", "a"], Vec::new());
    }

    #[test]
    #[should_panic]
    fn new_rejects_out_of_range_edge() {
        CompactDirectedGraph::new(vec!["a", "b"], vec![(0, 2)]);
    }
}
