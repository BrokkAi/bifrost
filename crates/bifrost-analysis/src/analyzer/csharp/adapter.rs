//! The `LanguageAdapter` forwarding shell for C#.
//!
//! Every answer below comes from [`brokk_bifrost_csharp`] except
//! `lookup_candidate_short_names`, which assembles its result with
//! `lookup_suffix_candidates` -- the generic suffix walk four analysis-side
//! languages share -- around the C#-specific nested-owner spellings.

use crate::analyzer::cognitive_complexity;
use crate::analyzer::tree_sitter_analyzer::lookup_suffix_candidates;
use crate::analyzer::{CodeUnit, Language, LanguageAdapter, ProjectFile, SignatureMetadata};
use brokk_bifrost_csharp::adapter::{
    CSHARP_COGNITIVE_CONFIG, CSHARP_FILE_EXTENSION, csharp_callable_return_type_text,
    csharp_extract_call_receiver, csharp_nested_owner_short_name_candidates,
};
use brokk_bifrost_csharp::declarations::parse_csharp_file;
use brokk_bifrost_csharp::test_detection::csharp_contains_tests;
use tree_sitter::Tree;

use super::{
    csharp_normalize_full_name, csharp_signature_arity, csharp_source_identifier,
    strip_csharp_generic_arity,
};

#[derive(Debug, Clone, Default)]
pub(super) struct CSharpAdapter;

impl LanguageAdapter for CSharpAdapter {
    fn language(&self) -> Language {
        Language::CSharp
    }

    fn query_directory(&self) -> &'static str {
        "resources/treesitter/c_sharp"
    }

    fn file_extension(&self) -> &'static str {
        CSHARP_FILE_EXTENSION
    }

    fn normalize_full_name(&self, fq_name: &str) -> String {
        csharp_normalize_full_name(fq_name)
    }

    fn simple_type_name(&self, unit: &CodeUnit) -> String {
        csharp_source_identifier(unit).to_string()
    }

    fn persist_content_stable_lookup_keys(&self) -> bool {
        true
    }

    fn lookup_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        let mut candidates = lookup_suffix_candidates(normalized_fq_name, &[".", "::"]);
        if let Some((owner, leaf)) = normalized_fq_name.rsplit_once('.') {
            let source_leaf = strip_csharp_generic_arity(leaf);
            if source_leaf != leaf {
                candidates.extend(lookup_suffix_candidates(
                    &format!("{owner}.{source_leaf}"),
                    &[".", "::"],
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

    fn callable_arity(
        &self,
        signature: &str,
        metadata: Option<&SignatureMetadata>,
    ) -> Option<usize> {
        metadata
            .and_then(SignatureMetadata::callable_arity)
            .map(|arity| arity.total())
            .or_else(|| Some(csharp_signature_arity(Some(signature))))
    }

    fn callable_return_type_text<'a>(&self, signature: &'a str) -> Option<&'a str> {
        csharp_callable_return_type_text(signature)
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
