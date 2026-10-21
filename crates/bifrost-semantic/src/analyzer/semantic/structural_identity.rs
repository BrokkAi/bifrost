//! Exact joins from a prepared syntax tree to the normalized structural facts
//! extracted from that same tree.
//!
//! A value mapping that carries its source occurrence's structural identity is
//! what lets a query anchored on an ordinary structural row reach the
//! executable value at that occurrence. The map is built once per prepared
//! source, and each mapping then performs only a tree-node-id lookup.
