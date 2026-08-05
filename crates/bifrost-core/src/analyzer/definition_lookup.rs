//! Bounded lookup of declarations by name.
//!
//! [`CodeUnitIndex`] answers from one analyzer's own declarations.  A resolver
//! or a language scan usually needs a wider view than that -- "does the
//! workspace define this fq name at all" -- and the implementations that can
//! answer it differ in how much they are allowed to touch: a whole-workspace
//! index answers from memory, while a persisted analyzer must route the same
//! question through bounded store queries instead of materializing every
//! declaration.  [`BoundedDefinitionLookup`] is the contract both satisfy, so a
//! caller taking `&dyn BoundedDefinitionLookup` cannot accidentally opt into
//! the unbounded one.
//!
//! The trait lives here, below the usages framework that owns its
//! implementations, so a language crate can ask the question without naming
//! `brokk-bifrost-analysis`'s resolution model.
//!
//! [`CodeUnitIndex`]: crate::analyzer::code_unit_index::CodeUnitIndex

use crate::analyzer::model::{CodeUnit, Language, ProjectFile};
use crate::path_utils::rel_path_string;

pub trait BoundedDefinitionLookup {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit>;
    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit>;

    /// Exact-fq lookup across *every* language the workspace indexes.
    ///
    /// A language-scoped resolver cannot tell "this fq is not in the workspace"
    /// apart from "this fq belongs to another language's declarations", so a
    /// confident cross-workspace boundary claim must consult this before it
    /// fires (#1174).  The default is the implementation's own scope: bounded
    /// single-language providers genuinely have no view of other languages, and
    /// answering same-language keeps them conservative (they can only *fail* to
    /// suppress a boundary claim, never invent a cross-language hit).
    fn fqn_in_any_language(&self, fqn: &str) -> Vec<CodeUnit> {
        self.fqn(fqn)
    }

    /// Language-blind counterpart of [`Self::package_exists`]; see
    /// [`Self::fqn_in_any_language`] for why the default is same-language.
    fn package_exists_in_any_language(&self, package: &str) -> bool {
        self.package_exists(package)
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit>;
    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit>;
    fn fqn_exists(&self, fqn: &str) -> bool;
    fn package_exists(&self, package: &str) -> bool;
    fn package_exists_in_language(&self, package: &str, language: Language) -> bool;
    fn fqn_prefix_exists(&self, prefix: &str) -> bool;

    fn fqn_candidates(&self, fqns: Vec<String>) -> Vec<CodeUnit> {
        let mut candidates = fqns
            .into_iter()
            .flat_map(|fqn| self.fqn(&fqn))
            .collect::<Vec<_>>();
        sort_units(&mut candidates);
        candidates.dedup();
        candidates
    }

    fn file_identifier_in_files(&self, files: &[ProjectFile], ident: &str) -> Vec<CodeUnit> {
        let mut out = Vec::new();
        for file in files {
            out.extend(self.file_identifier(file, ident));
        }
        sort_units(&mut out);
        out.dedup();
        out
    }
}

/// The canonical order definition-lookup results are published in: by source
/// path, then fq name, then signature, so a `dedup` after it collapses the
/// same declaration reached through two shards or two spellings.
pub fn sort_units(units: &mut [CodeUnit]) {
    units.sort_by(|left, right| {
        rel_path_string(left.source())
            .cmp(&rel_path_string(right.source()))
            .then_with(|| left.fq_name().cmp(&right.fq_name()))
            .then_with(|| left.signature().cmp(&right.signature()))
    });
}
