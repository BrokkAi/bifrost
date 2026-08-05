//! The analysis-side half of Rust's usage-graph resolver.
//!
//! The resolver itself is [`brokk_bifrost_rust::graph::resolver`]; it resolves
//! through `RustUsageSource` and a `RustDefinitionProvider` and names no
//! analyzer type. What stays here is the two `RustDefinitionProvider` impls
//! for analysis-owned declaration indexes -- the whole-workspace
//! [`GlobalUsageDefinitionIndex`] the graph builds against, and the bounded
//! [`DefinitionIndexHandle`] the point-lookup route hands in.

//! The scan bodies still reach the resolver through `super::resolver::`, so the
//! crate's surface is re-exported here rather than requoted at every call site.

pub(crate) use brokk_bifrost_rust::graph::resolver::*;

use crate::analyzer::{CodeUnit, DefinitionIndexHandle, GlobalUsageDefinitionIndex, ProjectFile};

impl RustDefinitionProvider for GlobalUsageDefinitionIndex {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        GlobalUsageDefinitionIndex::fqn(self, fqn)
    }

    fn file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        GlobalUsageDefinitionIndex::file_identifier(self, file, identifier)
    }
}

impl RustDefinitionProvider for DefinitionIndexHandle<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        DefinitionIndexHandle::fqn(self, fqn)
    }

    fn file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        DefinitionIndexHandle::file_identifier(self, file, identifier)
    }
}
