//! Canonical PHP import projections.
//!
//! [`crate::aliases::parse_php_import_syntax`] owns the parser interpretation
//! of one `namespace_use_declaration`. This module only lowers those already
//! interpreted leaves into the generic import DTO and the source-owned import
//! arena; neither path reparses the declaration text.

use brokk_bifrost_core::analyzer::common::node_span;
use brokk_bifrost_core::analyzer::model::{
    ImportInfo, StructuredImportPath, StructuredImportPathKind,
};
use brokk_bifrost_core::analyzer::parsed_file::SourceImportFact;
use brokk_bifrost_core::analyzer::php_facts::{PhpAliasKind, PhpAliasSourceFact};
use brokk_bifrost_core::analyzer::source_facts::{PrimarySourceFactCollector, SourceImportId};
use tree_sitter::Node;

pub use crate::aliases::{PhpImport, PhpImportKind, PhpImportSyntax, parse_php_import_syntax};

fn node_text<'source>(node: Node<'_>, source: &'source str) -> &'source str {
    node.utf8_text(source.as_bytes())
        .expect("PHP parser nodes must point into UTF-8 source")
        .trim()
}

fn declaration_text(declaration: Node<'_>, source: &str) -> String {
    node_text(declaration, source).to_owned()
}

impl<'tree> PhpImport<'tree> {
    /// Lower one parser-derived PHP clause to the generic import model.
    ///
    /// The enclosing declaration remains the statement text, including a
    /// grouped declaration's braces and sibling clauses. Canonical source
    /// facts may split that statement into one leaf per clause, while generic
    /// callers can retain their existing one-statement query behavior.
    pub fn to_import_info(&self, declaration: Node<'tree>, source: &str) -> ImportInfo {
        let identifier = self.path_segments.last().cloned();
        let alias = self.alias.map(|alias| node_text(alias, source).to_owned());
        let path = (!self.path_segments.is_empty()).then(|| StructuredImportPath {
            segments: self.path_segments.clone(),
            kind: Some(StructuredImportPathKind::Namespace),
            lexical_prefixes: Vec::new(),
            lexical_scopes: Vec::new(),
            declaration_start_byte: declaration.start_byte(),
        });
        let binder_span = self.alias.or(self.target).map(node_span);

        ImportInfo {
            raw_snippet: declaration_text(declaration, source),
            is_wildcard: false,
            is_global: self.is_global,
            identifier,
            alias,
            path,
            binder_span,
        }
    }

    /// Project one clause into the canonical source import arena while the
    /// primary AST is live. The declaration, terminal target, and alias
    /// identities all come from the exact nodes retained by [`PhpImport`].
    pub fn to_source_import_fact(
        &self,
        declaration: Node<'tree>,
        source: &str,
        source_collector: &mut PrimarySourceFactCollector<'_>,
    ) -> SourceImportFact {
        let declaration_occurrence = source_collector.intern_node(declaration);
        let target = self
            .target
            .map(|target| source_collector.intern_node(target));
        let alias_occurrence = self.alias.map(|alias| source_collector.intern_node(alias));
        SourceImportFact::from_import(
            self.to_import_info(declaration, source),
            declaration_occurrence,
            target,
            alias_occurrence,
            Vec::new(),
        )
    }

    /// Project the alias introduced by this clause into PHP's canonical alias
    /// arena. Each leaf references its exact canonical SourceImportId; PHP
    /// contributes only the namespace (type/function/constant) binding kind.
    pub fn to_alias_source_fact(&self, import: SourceImportId) -> Option<PhpAliasSourceFact> {
        self.path_segments.last()?;
        if self
            .alias
            .is_some_and(|alias| alias.start_byte() == alias.end_byte())
        {
            return None;
        }
        let kind = match self.kind {
            PhpImportKind::Type => PhpAliasKind::Type,
            PhpImportKind::Function => PhpAliasKind::Function,
            PhpImportKind::Const => PhpAliasKind::Constant,
        };
        Some(PhpAliasSourceFact { import, kind })
    }
}

/// Project every parser-derived leaf from one PHP import statement.
pub fn project_source_imports<'tree>(
    syntax: &PhpImportSyntax<'tree>,
    declaration: Node<'tree>,
    source: &str,
    source_collector: &mut PrimarySourceFactCollector<'_>,
) -> Vec<SourceImportFact> {
    syntax
        .imports
        .iter()
        .map(|import| import.to_source_import_fact(declaration, source, source_collector))
        .collect()
}

/// Project every valid alias from one PHP import statement, preserving source
/// order and skipping only clauses for which the parser produced no path.
pub fn project_alias_source_facts(
    syntax: &PhpImportSyntax<'_>,
    first_import: usize,
) -> Vec<PhpAliasSourceFact> {
    syntax
        .imports
        .iter()
        .enumerate()
        .filter_map(|(ordinal, import)| {
            let id = SourceImportId::try_from_index(first_import + ordinal)
                .expect("PHP source import ids fit in u32");
            import.to_alias_source_fact(id)
        })
        .collect()
}
