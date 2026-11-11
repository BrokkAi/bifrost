//! The `LanguageAdapter` forwarding shell for Rust.
//!
//! Every answer below comes from [`brokk_bifrost_rust`]; this file exists only
//! because `LanguageAdapter` and `ParsedFile` are analysis-owned types the Rust
//! crate cannot name.

use brokk_bifrost_analysis::analyzer::cognitive_complexity;
use brokk_bifrost_core::retention_budget::RetentionBudget;
use brokk_bifrost_rust::crate_naming::RustCrateNamingCaches;
use brokk_bifrost_rust::lexical_scope::RustLexicalCaches;
use std::sync::Arc;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

use brokk_bifrost_core::analyzer::model::PackageAnchor;

use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_rust::adapter::{
    RUST_COGNITIVE_CONFIG, RUST_FILE_EXTENSION, rust_extract_call_receiver,
};
use brokk_bifrost_rust::declarations::{
    parse_rust_file_with, rust_file_package_fq_with, rust_package_name_with,
    rust_semantic_package_fq,
};
use brokk_bifrost_rust::queries::RUST_QUERY_DIRECTORY;
use brokk_bifrost_rust::test_detection::rust_source_contains_tests;
use tree_sitter::Tree;

/// Rust persists every unit's package prefix as an anchor plus a
/// content-stable tail, so `code_units.content_qualifier` is always empty for
/// this language. The SQL package prefilters that read that column
/// (`persisted_package_exists`, `forward_fqn_prefix_exists` in
/// `tree_sitter_analyzer.rs`) therefore cannot see any Rust row and would
/// report a false negative if one were ever asked about a Rust package. No
/// Rust caller reaches them today; a future one must resolve the anchor
/// instead of matching persisted text.
#[derive(Clone)]
#[doc(hidden)]
pub struct RustAdapter {
    pub(crate) naming: Arc<RustCrateNamingCaches>,
    pub(crate) lexical: Arc<RustLexicalCaches>,
}

impl std::fmt::Debug for RustAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustAdapter").finish_non_exhaustive()
    }
}

impl RustAdapter {
    pub fn new(naming: Arc<RustCrateNamingCaches>, lexical: Arc<RustLexicalCaches>) -> Self {
        Self { naming, lexical }
    }

    /// An adapter with no owner to charge, for parsing outside any analyzer.
    /// Its caches admit nothing, so each call computes and drops its own
    /// values.
    pub fn ownerless() -> Self {
        let budget = RetentionBudget::retain_nothing();
        Self::new(
            Arc::new(RustCrateNamingCaches::new(&budget)),
            Arc::new(RustLexicalCaches::new(&budget)),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests() -> Self {
        let budget = RetentionBudget::for_tests();
        Self::new(
            Arc::new(RustCrateNamingCaches::new(&budget)),
            Arc::new(RustLexicalCaches::new(&budget)),
        )
    }

    pub fn lexical_caches(&self) -> &RustLexicalCaches {
        &self.lexical
    }
}

static RUST_SEMANTIC_LOWERER: crate::analyzer::rust::semantic::RustSemanticLowerer =
    crate::analyzer::rust::semantic::RustSemanticLowerer;

impl LanguageAdapter for RustAdapter {
    fn for_project(
        &self,
        project: Arc<dyn brokk_bifrost_core::analyzer::project::Project>,
    ) -> Option<Self> {
        struct SelectedManifestSource(Arc<dyn brokk_bifrost_core::analyzer::project::Project>);
        impl brokk_bifrost_rust::crate_naming::RustManifestSource for SelectedManifestSource {
            fn lists_path(&self, file: &ProjectFile) -> bool {
                self.0.selected_configuration_lists_path(file.rel_path())
            }
            fn retained_bytes(&self) -> usize {
                self.0.selected_configuration_retained_bytes()
            }
            fn bytes(&self, file: &ProjectFile) -> std::io::Result<Option<Vec<u8>>> {
                self.0.selected_configuration_bytes(file.rel_path())
            }
        }
        let source = Arc::new(SelectedManifestSource(project));
        Some(Self::new(
            Arc::new(self.naming.for_source(source)),
            Arc::clone(&self.lexical),
        ))
    }

    fn record_file_identity_inputs(
        &self,
        analyzer: &brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer<Self>,
        file: &ProjectFile,
    ) {
        if file
            .rel_path()
            .extension()
            .is_none_or(|extension| extension != "rs")
            || !brokk_bifrost_analysis::analyzer::workspace_authority::memo_attribution(analyzer)
                .is_capturing()
        {
            return;
        }
        brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::record_identity_walk_inputs(
            analyzer,
            Language::Rust,
            brokk_bifrost_rust::crate_naming::rust_file_identity_inputs_with(&self.naming, file)
                .iter(),
        );
    }

    fn line_data_kinds(&self) -> brokk_bifrost_core::analyzer::tree_walk::LineDataKinds {
        brokk_bifrost_core::analyzer::tree_walk::LineDataKinds {
            literals: &[
                "string_literal",
                "raw_string_literal",
                "integer_literal",
                "float_literal",
                "char_literal",
            ],
            interpolations: &[],
            composites: &[
                ("array_expression", &["[", "]", ",", ";"]),
                ("tuple_expression", &["(", ")", ","]),
                ("unary_expression", &["-"]),
            ],
        }
    }

    fn cross_file_children(
        &self,
        analyzer: &brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer<Self>,
        owner: &brokk_bifrost_core::analyzer::model::CodeUnit,
        limit: usize,
    ) -> Option<
        Vec<(
            brokk_bifrost_core::analyzer::model::CodeUnit,
            Option<brokk_bifrost_core::analyzer::model::Range>,
        )>,
    > {
        if !owner.is_class() {
            return None;
        }
        let Some(read) = analyzer.canonical_source_read(owner.source(), "rust") else {
            return Some(Vec::new());
        };
        // No complete selected derivation, or an unresolved impl subject, adds
        // no members. direct_children has no incompleteness channel.
        Some(
            read.read(
                "reading resolved impl children",
                |store, oid, generation, adapter| {
                    store
                        .rust_impl_children(
                            oid,
                            generation,
                            analyzer.selected_workspace_snapshots().as_ref(),
                            adapter,
                            owner,
                            limit,
                        )?
                        .into_iter()
                        .map(|row| {
                            let unit =
                                brokk_bifrost_analysis::analyzer::store::hydrate_mounted_candidate(
                                    adapter,
                                    analyzer.project().root(),
                                    row.candidate,
                                    row.rel_path,
                                )?;
                            if let Some(member_read) =
                                analyzer.canonical_source_read(unit.source(), "rust")
                            {
                                member_read.record_read_key();
                            }
                            Ok((unit, row.primary_range))
                        })
                        .collect()
                },
            )
            .unwrap_or_default(),
        )
    }

    /// Relative to `brokk-bifrost-rust`'s crate root: the `.scm` assets moved
    /// with the language knowledge and are embedded there.
    fn query_directory(&self) -> &'static str {
        RUST_QUERY_DIRECTORY
    }

    fn file_extension(&self) -> &'static str {
        RUST_FILE_EXTENSION
    }

    fn persisted_content_qualifier_supports_substring_search(&self) -> bool {
        false
    }

    fn has_workspace_package_identity_inputs(&self) -> bool {
        true
    }

    fn workspace_package_identity_input_path(&self, path: &std::path::Path) -> bool {
        crate::analyzer::rust::is_cargo_topology_input(path)
    }

    /// The same parse crate reconciliation reads, minus what no Rust reader
    /// consumes. An input that does not parse has no meaning to compare, so
    /// any edit to it rebuilds.
    fn workspace_package_identity_digest(
        &self,
        file: &ProjectFile,
        source: &[u8],
    ) -> Option<[u8; 32]> {
        if brokk_bifrost_rust::cargo_config::is_cargo_configuration_path(file.rel_path()) {
            brokk_bifrost_rust::cargo_config::RustCargoConfigDocument::from_source_bytes(source)
                .ok()
                .map(|document| document.topology_digest())
        } else {
            brokk_bifrost_rust::cargo_manifest::RustCargoManifestDocument::from_source_bytes(
                source.into(),
            )
            .ok()
            .map(|document| document.topology_digest())
        }
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        rust_extract_call_receiver(reference)
    }

    fn contains_tests(
        &self,
        _file: &ProjectFile,
        source: &str,
        tree: &Tree,
        _parsed: &brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    ) -> bool {
        rust_source_contains_tests(tree.root_node(), source)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
        parse_rust_file_with(&self.naming, file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&RUST_COGNITIVE_CONFIG)
    }
}

impl brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter for RustAdapter {
    fn source_fact_storage(
        &self,
    ) -> Option<&'static brokk_bifrost_analysis::analyzer::store::source_facts::SourceFactStorage>
    {
        Some(&crate::analyzer::rust::source_publication::SOURCE_STORAGE)
    }

    fn language(&self) -> Language {
        Language::Rust
    }

    fn parse_time_semantic_lowerer(
        &self,
    ) -> Option<brokk_bifrost_semantic::analyzer::semantic::service::ParseTimeSemanticLowerer> {
        Some(
            brokk_bifrost_semantic::analyzer::semantic::service::ParseTimeSemanticLowerer::new(
                &RUST_SEMANTIC_LOWERER,
            ),
        )
    }

    /// `parse_rust_file` fills none of the language-specific families: Rust
    /// relations are crate rows, not supertypes, and the other four belong to
    /// Ruby, Scala, C++ and the materializing languages.
    fn side_fact_families(&self) -> brokk_bifrost_analysis::analyzer::store::SideFactFamilies {
        brokk_bifrost_analysis::analyzer::store::SideFactFamilies::NONE
    }

    fn storage_content_qualifier(
        &self,
        _code_unit: &brokk_bifrost_core::analyzer::model::CodeUnit,
        _content_qualifier: &str,
    ) -> String {
        // Every Rust unit carries an effective package anchor (its own, or this
        // adapter's default), so its package prefix is re-derived from the live
        // path at hydration. Baking the path-derived text into the row would
        // make a content-addressed blob unusable at a second mount point. A
        // unit that falls back to a fully persisted name needs no qualifier
        // either: mode FULL restores the complete structured name on its own.
        String::new()
    }

    fn storage_file_content_qualifier(&self, _package_name: &str) -> String {
        String::new()
    }

    fn hydrate_content_qualifier(
        &self,
        content_qualifier: &str,
        file: &ProjectFile,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<String> {
        Ok(if content_qualifier.is_empty() {
            rust_package_name_with(&self.naming, file)
        } else {
            content_qualifier.to_string()
        })
    }

    fn default_package_anchor(&self) -> Option<PackageAnchor> {
        Some(PackageAnchor::OwnModule { pop: 0 })
    }

    fn resolve_package_anchor(
        &self,
        anchor: PackageAnchor,
        _content_qualifier: &str,
        file: &ProjectFile,
    ) -> Option<brokk_bifrost_core::analyzer::fq_name::FqName> {
        match anchor {
            PackageAnchor::OwnModule { pop } => {
                let package = rust_file_package_fq_with(&self.naming, file);
                let keep = package.len().saturating_sub(usize::from(pop));
                Some(package.prefix(keep))
            }
            // An empty crate root (a crate mounted at the repository root) is a
            // legitimate empty prefix, not an absent one: it is what lets an
            // `impl crate::Type` member persist a package-free tail.
            PackageAnchor::CrateRoot => Some(rust_semantic_package_fq(
                &brokk_bifrost_rust::imports::rust_crate_root_package_with(&self.naming, file),
            )),
        }
    }

    fn declaration_visibility_facts_version(&self) -> Option<i64> {
        Some(brokk_bifrost_core::analyzer::source_facts::SOURCE_DECLARATION_VISIBILITY_VERSION)
    }

    fn produces_canonical_source_facts(&self) -> bool {
        true
    }
}
