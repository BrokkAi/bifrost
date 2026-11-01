//! The `LanguageAdapter` forwarding shell for C#.
//!
//! Every answer below comes from [`brokk_bifrost_csharp`] except
//! `lookup_candidate_short_names`, which assembles its result with
//! `lookup_suffix_candidates` -- the generic suffix walk four analysis-side
//! languages share -- around the C#-specific nested-owner spellings.

use brokk_bifrost_analysis::analyzer::cognitive_complexity;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::lookup_suffix_candidates;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::fq_name::FqName;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_csharp::adapter::{
    CSHARP_COGNITIVE_CONFIG, CSHARP_FILE_EXTENSION, csharp_extract_call_receiver,
    csharp_nested_owner_short_name_candidates,
};
use brokk_bifrost_csharp::declarations::parse_csharp_file;
use brokk_bifrost_csharp::preprocessor::csharp_included_ranges;
use brokk_bifrost_csharp::queries::CSHARP_QUERY_DIRECTORY;
use tree_sitter::Tree;

use brokk_bifrost_csharp::syntax::csharp_normalize_full_name;

use brokk_bifrost_csharp::syntax::csharp_source_identifier;

use brokk_bifrost_csharp::syntax::strip_csharp_generic_arity;

#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct CSharpAdapter;

use brokk_bifrost_analysis::analyzer::store::{
    AnalyzerStore, GenerationId, StoreError, WorkspaceConfigurationInput, WorkspaceId,
    WorkspaceSnapshotId,
};
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{ParseConfiguration, PathParse};
use brokk_bifrost_core::gitblob::{BlobKey, ParseVariant};
use brokk_bifrost_csharp::preprocessor::{
    OwnerEnvironments, SymbolEnvironment, assignment_digest, empty_decision_digest,
    scan_and_decide_preprocessor,
};

// Certificate: first process read only. Publication assertions cover later writes;
// out-of-band deletion after a cached count is outside this check's contract.
// Every process starts empty; eviction permits another count. No freshness SQL.
pub(super) static MISSING_DECISION_COUNTS: std::sync::LazyLock<
    moka::sync::Cache<(WorkspaceId, GenerationId), u64>,
> = std::sync::LazyLock::new(|| moka::sync::Cache::new(4096));

impl CSharpAdapter {
    pub(super) fn validate_decisions(
        store: &AnalyzerStore,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<(), StoreError> {
        assert_eq!(snapshot.lang, "csharp", "decision certificate is C# only");
        let key = (snapshot.workspace_id.clone(), snapshot.generation);
        debug_assert_eq!(key.0, snapshot.workspace_id);
        debug_assert_eq!(key.1, snapshot.generation);
        let count = MISSING_DECISION_COUNTS
            .try_get_with(key, || {
                store.csharp_missing_decision_count(&snapshot.workspace_id, snapshot.generation)
            })
            .map_err(|error| (*error).clone())?;
        if count != 0 {
            return Err(StoreError::corrupt(format!(
                "C# workspace {:?} generation {:?} has {count} source versions without decisions",
                snapshot.workspace_id, snapshot.generation
            )));
        }
        Ok(())
    }

    fn parse_owners(
        store: &AnalyzerStore,
        configuration: &ParseConfiguration,
        file: &ProjectFile,
    ) -> Result<Option<Vec<SymbolEnvironment>>, StoreError> {
        let Some(set) = configuration.set else {
            return Ok(None);
        };
        let Some(membership) = store.csharp_compilations_of_set(
            set,
            &brokk_bifrost_core::path_utils::rel_path_string(file),
        )?
        else {
            return Ok(None);
        };
        if !membership.open.is_empty() {
            return Ok(None);
        }
        membership
            .proven
            .into_iter()
            .map(|id| {
                let environment = store.csharp_owner_environment(id)?.ok_or_else(|| {
                    StoreError::corrupt(format!("compilation {id} has no owner environment"))
                })?;
                Ok(SymbolEnvironment {
                    compilation_key: environment.owner_key,
                    defined: environment.symbols.into_iter().collect(),
                    closed: environment.closed,
                    open_reason: environment.open_reason,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }
}

impl LanguageAdapter for CSharpAdapter {
    fn derive_parse_configuration(
        &self,
        store: &AnalyzerStore,
        workspace: &WorkspaceId,
        generation: GenerationId,
        captured: &[WorkspaceConfigurationInput],
    ) -> Result<Option<ParseConfiguration>, StoreError> {
        let set = store.derive_csharp_compilation_set(workspace, generation, captured)?;
        Ok(Some(ParseConfiguration {
            set: set.map(|set| set.id),
            output_digest: set.map(|set| set.output_digest),
        }))
    }

    fn snapshot_parse_configuration(
        &self,
        store: &AnalyzerStore,
        snapshot: &WorkspaceSnapshotId,
    ) -> Result<Option<ParseConfiguration>, StoreError> {
        Self::validate_decisions(store, snapshot)?;
        let set = store.csharp_selected_compilation_set(snapshot)?;
        Ok(Some(ParseConfiguration {
            set: set.map(|set| set.id),
            output_digest: set.map(|set| set.output_digest),
        }))
    }

    fn prepare_path_parse(
        &self,
        store: &AnalyzerStore,
        configuration: &ParseConfiguration,
        file: &ProjectFile,
        source: &str,
    ) -> Result<PathParse, StoreError> {
        let owners = Self::parse_owners(store, configuration, file)?;
        let ownership = owners
            .as_deref()
            .map_or(OwnerEnvironments::Unknown, OwnerEnvironments::Known);
        let scan = scan_and_decide_preprocessor(source, ownership);
        let undecided_chains = scan
            .undecided_chains
            .iter()
            .map(
                |chain| brokk_bifrost_analysis::analyzer::store::UndecidedChainRow {
                    chain: chain.chain,
                    directive_start: chain.directive_start,
                    directive_end: chain.directive_end,
                    omitted_nonblank: chain.omitted_nonblank,
                    invalid_condition: chain.reason.invalid_condition,
                    unknown_symbols: chain.reason.unknown_symbols.iter().cloned().collect(),
                    open_reasons: chain.reason.open_reasons.iter().cloned().collect(),
                    disagreeing_owners: chain.reason.disagreeing_owners.clone(),
                },
            )
            .collect();
        Ok(PathParse {
            variant: ParseVariant::Digest(scan.decisions.decision_digest),
            assignment_digest: Some(scan.decisions.assignment_digest),
            condition_symbols: scan.decisions.referenced_symbols.iter().cloned().collect(),
            undecided_chains,
            preprocessor: Some(std::sync::Arc::new(scan)),
        })
    }

    fn carry_path_parse(
        &self,
        store: &AnalyzerStore,
        configuration: &ParseConfiguration,
        previous: &WorkspaceSnapshotId,
        file: &ProjectFile,
        key: &BlobKey,
    ) -> Result<Option<PathParse>, StoreError> {
        let Some(decision) = store.csharp_file_version_decision(
            previous,
            &brokk_bifrost_core::path_utils::rel_path_string(file),
        )?
        else {
            return Ok(None);
        };
        if key.variant != ParseVariant::Digest(decision.decision_digest) {
            return Ok(None);
        }
        let symbols = store.csharp_referenced_symbols(key)?;
        let owners = Self::parse_owners(store, configuration, file)?;
        let ownership = owners
            .as_deref()
            .map_or(OwnerEnvironments::Unknown, OwnerEnvironments::Known);
        let digest = assignment_digest(
            ownership,
            &symbols.iter().cloned().collect(),
            decision.decision_digest != empty_decision_digest(),
        );
        Ok((digest == decision.assignment_digest).then_some(PathParse {
            variant: key.variant,
            assignment_digest: Some(digest),
            condition_symbols: symbols,
            undecided_chains: Vec::new(),
            preprocessor: None,
        }))
    }

    fn selected_path_variants(
        &self,
        store: &AnalyzerStore,
        snapshot: &WorkspaceSnapshotId,
        files: &[ProjectFile],
    ) -> Result<Vec<Option<ParseVariant>>, StoreError> {
        let variants = store.selected_parse_variants_for_paths(
            snapshot,
            &files
                .iter()
                .map(brokk_bifrost_core::path_utils::rel_path_string)
                .collect::<Vec<_>>(),
        )?;
        let unreadable = files
            .iter()
            .zip(&variants)
            .filter_map(|(file, variant)| (*variant == Some(ParseVariant::Empty)).then_some(file))
            .collect::<Vec<_>>();
        if !unreadable.is_empty() {
            return Err(StoreError::corrupt(format!(
                "C# sources without selected decisions: {unreadable:?}"
            )));
        }
        Ok(variants)
    }

    fn selected_path_variant(
        &self,
        store: &AnalyzerStore,
        snapshot: &WorkspaceSnapshotId,
        file: &ProjectFile,
    ) -> Result<Option<ParseVariant>, StoreError> {
        store
            .csharp_selected_file_decision(
                snapshot,
                &brokk_bifrost_core::path_utils::rel_path_string(file),
            )?
            .map(|decision| {
                decision
                    .map(|decision| ParseVariant::Digest(decision.decision_digest))
                    .ok_or_else(|| {
                        StoreError::corrupt(format!("C# source {file:?} has no selected decision"))
                    })
            })
            .transpose()
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

    fn preprocess(
        &self,
        _file: &ProjectFile,
        source: &str,
    ) -> Option<std::sync::Arc<dyn brokk_bifrost_core::analyzer::prepared_syntax::SourcePreprocessor>>
    {
        Some(std::sync::Arc::new(
            brokk_bifrost_csharp::preprocessor::scan_preprocessor(source),
        ))
    }

    fn parse_file_preprocessed(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
        preprocessor: Option<
            &dyn brokk_bifrost_core::analyzer::prepared_syntax::SourcePreprocessor,
        >,
    ) -> (
        brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
        Vec<(
            &'static str,
            brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
        )>,
    ) {
        #[cfg(any(test, feature = "test-support"))]
        if super::trial_native_csharp_selected() {
            let scan = preprocessor
                .expect("C# preprocessing precedes parsing")
                .as_any()
                .downcast_ref::<brokk_bifrost_csharp::preprocessor::PreprocessorScan>()
                .expect("C# scan");
            return (
                brokk_bifrost_csharp::declarations::parse_csharp_file_with_native_facts(
                    file, source, tree, scan,
                ),
                Vec::new(),
            );
        }
        let _ = preprocessor;
        (parse_csharp_file(file, source, tree), Vec::new())
    }

    fn visibility_containers(&self, unit: &CodeUnit) -> Vec<FqName> {
        let Some(last) = unit.fq().last() else {
            return Vec::new();
        };
        let (_, kind) = brokk_bifrost_core::analyzer::fq_name::segment_interner().resolve(last);
        if unit.is_class() && kind == brokk_bifrost_core::analyzer::fq_name::SegmentKind::Nested {
            vec![unit.package_fq()]
        } else {
            Vec::new()
        }
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
        _source: &str,
        _tree: &Tree,
        parsed: &brokk_bifrost_core::analyzer::parsed_file::ParsedFile,
    ) -> bool {
        parsed
            .contains_tests
            .expect("C# primary producer records test classification")
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        csharp_extract_call_receiver(reference)
    }

    fn parse_file(
        &self,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
        parse_csharp_file(file, source, tree)
    }

    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        Some(&CSHARP_COGNITIVE_CONFIG)
    }
}

static CSHARP_SEMANTIC_LOWERER: super::semantic::CSharpSemanticLowerer =
    super::semantic::CSharpSemanticLowerer;

impl brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter for CSharpAdapter {
    fn parse_time_semantic_lowerer(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::service::ParseTimeSemanticLowerer> {
        Some(
            brokk_bifrost_analysis::analyzer::semantic::service::ParseTimeSemanticLowerer::new(
                &CSHARP_SEMANTIC_LOWERER,
            ),
        )
    }

    fn requires_source_declaration_metadata_bridges(&self) -> bool {
        true
    }
    fn produces_canonical_source_facts(&self) -> bool {
        true
    }
    fn language(&self) -> Language {
        Language::CSharp
    }
    fn normalize_full_name(&self, fq_name: &str) -> String {
        csharp_normalize_full_name(fq_name)
    }
    fn normalize_fq_name(&self, fq_name: &FqName) -> FqName {
        brokk_bifrost_csharp::syntax::csharp_normalize_fq_name(fq_name)
    }
    fn simple_type_name(&self, unit: &CodeUnit) -> String {
        csharp_source_identifier(unit).to_string()
    }
    fn persist_content_stable_lookup_keys(&self) -> bool {
        true
    }
}
