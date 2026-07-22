//! Compact immutable row and directed-graph storage for read-heavy snapshots.

use crate::hash::HashMap;
use std::hash::Hash;

#[derive(Debug, Clone)]
pub(crate) struct CompactRows<T> {
    offsets: Box<[u32]>,
    values: Box<[T]>,
}

impl<T> CompactRows<T> {
    pub(crate) fn from_parts(offsets: Vec<u32>, values: Vec<T>) -> Self {
        Self::try_from_parts(offsets, values).expect("invalid compact row parts")
    }

    /// Construct compact rows from an untrusted persisted representation.
    ///
    /// Builders enforce these invariants by construction, while snapshot
    /// decoding must reject corrupt boundaries instead of panicking.
    pub(crate) fn try_from_parts(offsets: Vec<u32>, values: Vec<T>) -> Result<Self, &'static str> {
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

    pub(crate) fn rows(&self) -> usize {
        self.offsets.len() - 1
    }

    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }

    pub(crate) fn offsets(&self) -> &[u32] {
        &self.offsets
    }

    pub(crate) fn values(&self) -> &[T] {
        &self.values
    }

    pub(crate) fn row(&self, row: usize) -> &[T] {
        let start = self.offsets[row] as usize;
        let end = self.offsets[row + 1] as usize;
        &self.values[start..end]
    }

    pub(crate) fn estimated_bytes(&self) -> u64 {
        (self.offsets.len() as u64)
            .saturating_mul(std::mem::size_of::<u32>() as u64)
            .saturating_add(
                (self.values.len() as u64).saturating_mul(std::mem::size_of::<T>() as u64),
            )
    }
}

pub(crate) struct CompactRowsBuilder<T> {
    offsets: Vec<u32>,
    values: Vec<T>,
}

impl<T> CompactRowsBuilder<T> {
    pub(crate) fn with_capacity(rows: usize, values: usize) -> Self {
        let mut offsets = Vec::with_capacity(rows.saturating_add(1));
        offsets.push(0);
        Self {
            offsets,
            values: Vec::with_capacity(values),
        }
    }

    pub(crate) fn values_mut(&mut self) -> &mut Vec<T> {
        &mut self.values
    }

    pub(crate) fn rows(&self) -> usize {
        self.offsets.len() - 1
    }

    pub(crate) fn finish_row(&mut self) {
        self.offsets
            .push(u32::try_from(self.values.len()).expect("compact row values must fit in a u32"));
    }

    pub(crate) fn push_row(&mut self, values: impl IntoIterator<Item = T>) {
        self.values.extend(values);
        self.finish_row();
    }

    pub(crate) fn finish(self) -> CompactRows<T> {
        CompactRows::from_parts(self.offsets, self.values)
    }
}

/// Snapshot-local dense identity plus outgoing CSR and incoming CSC rows.
#[derive(Debug)]
pub(crate) struct CompactDirectedGraph<K> {
    nodes: Box<[K]>,
    index_by_node: HashMap<K, u32>,
    outgoing: CompactRows<u32>,
    incoming: CompactRows<u32>,
}

impl<K> CompactDirectedGraph<K>
where
    K: Clone + Eq + Hash,
{
    pub(crate) fn new(nodes: Vec<K>, edges: Vec<(u32, u32)>) -> Self {
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

    pub(crate) fn from_indexed_nodes(
        nodes: Vec<K>,
        index_by_node: HashMap<K, u32>,
        mut edges: Vec<(u32, u32)>,
    ) -> Self {
        let node_count = nodes.len();
        assert!(
            u32::try_from(node_count).is_ok(),
            "compact graph nodes must fit in a u32"
        );
        assert_eq!(index_by_node.len(), node_count);
        assert!(
            nodes
                .iter()
                .enumerate()
                .all(|(index, node)| index_by_node.get(node).copied() == Some(index as u32)),
            "compact graph index must match node order"
        );
        assert!(
            edges
                .iter()
                .all(|(source, target)| (*source as usize) < node_count
                    && (*target as usize) < node_count),
            "compact graph edge endpoint is out of bounds"
        );
        edges.sort_unstable();
        edges.dedup();

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

    pub(crate) fn nodes(&self) -> &[K] {
        &self.nodes
    }

    pub(crate) fn node_id(&self, node: &K) -> Option<u32> {
        self.index_by_node.get(node).copied()
    }

    pub(crate) fn outgoing(&self, node: u32) -> &[u32] {
        self.outgoing.row(node as usize)
    }

    pub(crate) fn incoming(&self, node: u32) -> &[u32] {
        self.incoming.row(node as usize)
    }

    pub(crate) fn edge_count(&self) -> usize {
        self.outgoing.len()
    }

    pub(crate) fn estimated_bytes(&self) -> u64 {
        (std::mem::size_of::<Self>() as u64)
            .saturating_add(
                (self.nodes.len() as u64).saturating_mul(std::mem::size_of::<K>() as u64),
            )
            .saturating_add(
                (self.index_by_node.capacity() as u64)
                    .saturating_mul((std::mem::size_of::<(K, u32)>() + 1) as u64),
            )
            .saturating_add(self.outgoing.estimated_bytes())
            .saturating_add(self.incoming.estimated_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::{CompactDirectedGraph, CompactRows, CompactRowsBuilder};

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
    fn directed_graph_deduplicates_and_builds_sorted_reverse_rows() {
        let graph =
            CompactDirectedGraph::new(vec!["a", "b", "c"], vec![(0, 2), (0, 1), (0, 1), (2, 1)]);

        assert_eq!(graph.edge_count(), 3);
        assert_eq!(graph.outgoing(0), [1, 2]);
        assert_eq!(graph.incoming(1), [0, 2]);
        assert_eq!(graph.node_id(&"c"), Some(2));
        assert!(graph.estimated_bytes() > 0);
    }
}
