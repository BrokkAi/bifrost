//! The `LanguageAdapter` forwarding shell for C#.
//!
//! Every answer below comes from [`brokk_bifrost_csharp`] except
//! `lookup_candidate_short_names`, which assembles its result with
//! `lookup_suffix_candidates` -- the generic suffix walk four analysis-side
//! languages share -- around the C#-specific nested-owner spellings.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::tree_sitter_analyzer::lookup_suffix_candidates;
use crate::analyzer::{CodeUnit, FqName, Language, LanguageAdapter, ProjectFile};
use brokk_bifrost_csharp::adapter::{
    CSHARP_COGNITIVE_CONFIG, CSHARP_FILE_EXTENSION, csharp_extract_call_receiver,
    csharp_nested_owner_short_name_candidates,
};
use brokk_bifrost_csharp::declarations::parse_csharp_file;
use brokk_bifrost_csharp::preprocessor::csharp_included_ranges;
use brokk_bifrost_csharp::queries::CSHARP_QUERY_DIRECTORY;
use brokk_bifrost_csharp::test_detection::csharp_contains_tests;
use tree_sitter::Tree;

use super::{csharp_normalize_full_name, csharp_source_identifier, strip_csharp_generic_arity};

#[derive(Debug, Clone, Default)]
pub(crate) struct CSharpAdapter;

impl LanguageAdapter for CSharpAdapter {
    fn language(&self) -> Language {
        Language::CSharp
    }

    /// Relative to `brokk-bifrost-csharp`'s crate root: the `.scm` assets moved
    /// with the language knowledge and are embedded there.
    fn query_directory(&self) -> &'static str {
        CSHARP_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        CSHARP_FILE_EXTENSION
    }

    /// Hide preprocessor directive lines and inactive conditional branches from
    /// the parser, so a directive inside a declaration stops breaking the parse
    /// and losing the members around it (issue #1803).
    fn parser_included_ranges(
        &self,
        _file: &ProjectFile,
        source: &str,
    ) -> Option<Vec<tree_sitter::Range>> {
        csharp_included_ranges(source)
    }

    fn normalize_full_name(&self, fq_name: &str) -> String {
        csharp_normalize_full_name(fq_name)
    }

    fn normalize_fq_name(&self, fq_name: &FqName) -> FqName {
        brokk_bifrost_csharp::syntax::csharp_normalize_fq_name(fq_name)
    }

    fn visibility_containers(&self, unit: &CodeUnit) -> Vec<FqName> {
        let Some(last) = unit.fq().last() else {
            return Vec::new();
        };
        let (_, kind) = crate::analyzer::fq_name::segment_interner().resolve(last);
        if unit.is_class() && kind == brokk_bifrost_core::analyzer::fq_name::SegmentKind::Nested {
            vec![unit.package_fq()]
        } else {
            Vec::new()
        }
    }

    fn simple_type_name(&self, unit: &CodeUnit) -> String {
        csharp_source_identifier(unit).to_string()
    }

    fn persist_content_stable_lookup_keys(&self) -> bool {
        true
    }

    fn lookup_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        let separators = self.lookup_candidate_separators();
        let mut candidates = lookup_suffix_candidates(normalized_fq_name, separators);
        if let Some((owner, leaf)) = normalized_fq_name.rsplit_once('.') {
            let source_leaf = strip_csharp_generic_arity(leaf);
            if source_leaf != leaf {
                candidates.extend(lookup_suffix_candidates(
                    &format!("{owner}.{source_leaf}"),
                    separators,
                ));
            }
        }
        let base_candidates = candidates.clone();
        for candidate in base_candidates {
            candidates.extend(csharp_nested_owner_short_name_candidates(&candidate));
        }
        candidates.sort();
        candidates.dedup();
        candidates
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &crate::analyzer::tree_sitter_analyzer::ParsedFile,
    ) -> bool {
        csharp_contains_tests(tree.root_node(), source)
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        csharp_extract_call_receiver(reference)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> crate::analyzer::tree_sitter_analyzer::ParsedFile {
        parse_csharp_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&CSHARP_COGNITIVE_CONFIG)
    }
}
