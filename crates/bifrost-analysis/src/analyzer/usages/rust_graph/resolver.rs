//! The analysis-side half of Rust's usage-graph resolver.
//!
//! The resolver itself is [`brokk_bifrost_rust::graph::resolver`]; it resolves
//! through `RustFactSource` and a `RustDefinitionProvider` and names no
//! analyzer type. What stays here is the three `RustDefinitionProvider` impls
//! for analysis-owned declaration providers: the retained whole-workspace
//! [`GlobalUsageDefinitionIndex`], the request-scoped [`AnalyzerDefinitionLookup`],
//! and the bounded [`DefinitionIndexHandle`] used by point lookup.

//! The scan bodies still reach the resolver through `super::resolver::`, so the
//! crate's surface is re-exported here rather than requoted at every call site.

pub(crate) use brokk_bifrost_rust::graph::resolver::*;

use crate::analyzer::{
    AnalyzerDefinitionLookup, CodeUnit, DefinitionIndexHandle, GlobalUsageDefinitionIndex,
    ProjectFile,
};

impl RustDefinitionProvider for AnalyzerDefinitionLookup<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        AnalyzerDefinitionLookup::fqn(self, fqn)
    }

    fn file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        AnalyzerDefinitionLookup::file_identifier(self, file, identifier)
    }
}

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
