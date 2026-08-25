//! The analysis-side half of Rust's usage-graph resolver.
//!
//! The resolver itself is [`brokk_bifrost_rust::graph::resolver`]; it resolves
//! through `RustFactSource` and a `RustDefinitionProvider` and names no
//! analyzer type. What stays here is the `RustDefinitionProvider` impl for the
//! request-scoped [`AnalyzerDefinitionLookup`].

//! The scan bodies still reach the resolver through `super::resolver::`, so the
//! crate's surface is re-exported here rather than requoted at every call site.

pub(crate) use brokk_bifrost_rust::graph::resolver::*;

use crate::analyzer::{AnalyzerDefinitionLookup, CodeUnit, ProjectFile};

impl RustDefinitionProvider for AnalyzerDefinitionLookup<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        AnalyzerDefinitionLookup::fqn(self, fqn)
    }

    fn file_identifier(&self, file: &ProjectFile, identifier: &str) -> Vec<CodeUnit> {
        AnalyzerDefinitionLookup::file_identifier(self, file, identifier)
    }
}
