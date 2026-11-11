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

use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};

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
pub struct CSharpAdapter {
    trial: brokk_bifrost_core::analyzer::config::CSharpNativeTrial,
}

#[allow(non_upper_case_globals)]
pub const CSharpAdapter: CSharpAdapter = CSharpAdapter {
    trial: brokk_bifrost_core::analyzer::config::CSharpNativeTrial::Off,
};

impl CSharpAdapter {
    pub fn from_config(
        config: &brokk_bifrost_core::analyzer::config::CSharpAnalyzerConfig,
    ) -> Self {
        Self {
            trial: config.native_trial,
        }
    }

    pub(crate) fn semantic_lowerer(&self) -> super::semantic::CSharpSemanticLowerer {
        super::semantic::CSharpSemanticLowerer::for_trial(self.trial)
    }
}

// Reproduce a pre-hold cache in tests. This guard lets a fixture publish
// native facts independently of the analyzer's trial configuration.
#[cfg(any(test, feature = "test-support"))]
static LEGACY_NATIVE_FIXTURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(any(test, feature = "test-support"))]
pub struct LegacyNativeFixtureGuard;

#[cfg(any(test, feature = "test-support"))]
impl Drop for LegacyNativeFixtureGuard {
    fn drop(&mut self) {
        LEGACY_NATIVE_FIXTURE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "test-support"))]
impl CSharpAdapter {
    pub fn legacy_native_fixture_guard() -> LegacyNativeFixtureGuard {
        assert!(
            !LEGACY_NATIVE_FIXTURE.swap(true, std::sync::atomic::Ordering::SeqCst),
            "legacy C# fixture already active"
        );
        LegacyNativeFixtureGuard
    }
}

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
                    named_open: environment.named_open.into_iter().collect(),
                    closed: environment.closed,
                    open_reason: environment.open_reason,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }
}

impl LanguageAdapter for CSharpAdapter {
    fn line_data_kinds(&self) -> brokk_bifrost_core::analyzer::tree_walk::LineDataKinds {
        brokk_bifrost_core::analyzer::tree_walk::LineDataKinds {
            literals: &[
                "string_literal",
                "verbatim_string_literal",
                "raw_string_literal",
                "interpolated_string_expression",
                "character_literal",
                "integer_literal",
                "real_literal",
            ],
            interpolations: &["interpolation"],
            composites: &[
                ("initializer_expression", &["{", "}", ","]),
                ("prefix_unary_expression", &["-", "+"]),
            ],
        }
    }

    fn for_config(self, config: &brokk_bifrost_core::analyzer::config::AnalyzerConfig) -> Self {
        Self::from_config(&config.csharp)
    }

    fn record_read_obligation(
        &self,
        analyzer: &TreeSitterAnalyzer<Self>,
        key: &brokk_bifrost_analysis::analyzer::ReadKey,
    ) {
        use brokk_bifrost_analysis::analyzer::ReadKey;
        match key {
            ReadKey::File {
                language: Language::CSharp,
                rel_path,
                parse_variant,
                ..
            } => {
                analyzer.record_csharp_unseen_branch_obligation(Some((rel_path, *parse_variant)));
            }
            ReadKey::Scope { languages, .. } if languages.contains(&Language::CSharp) => {
                analyzer.record_csharp_unseen_branch_obligation(None);
            }
            ReadKey::File { .. }
            | ReadKey::Scope { .. }
            | ReadKey::Index { .. }
            | ReadKey::PathAbsent { .. }
            | ReadKey::Lookup { .. }
            | ReadKey::Artifact { .. }
            | ReadKey::Models(..)
            | ReadKey::Policy { .. }
            | ReadKey::Configuration(..)
            | ReadKey::Epoch(..) => {}
        }
    }
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
            undecided_scan: Some(
                brokk_bifrost_analysis::analyzer::store::CSharpUndecidedScan {
                    oid: git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
                        .expect("C# scan source hashes as a Git blob"),
                    variant: ParseVariant::Digest(scan.decisions.decision_digest),
                    chains: undecided_chains,
                },
            ),
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
            undecided_scan: None,
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
        if self.trial.is_on() || LEGACY_NATIVE_FIXTURE.load(std::sync::atomic::Ordering::SeqCst) {
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

impl brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter for CSharpAdapter {
    fn resolution_producer_epoch(&self) -> &'static str {
        if self.trial.is_on() {
            brokk_bifrost_analysis::analyzer::store::resolution::csharp_trial_bundle_epoch()
        } else {
            brokk_bifrost_analysis::analyzer::store::resolution::resolution_bundle_epoch(
                Language::CSharp,
            )
        }
    }

    fn parse_time_semantic_lowerer(
        &self,
    ) -> Option<brokk_bifrost_analysis::analyzer::semantic::service::ParseTimeSemanticLowerer> {
        Some(
            brokk_bifrost_analysis::analyzer::semantic::service::ParseTimeSemanticLowerer::new(
                self.semantic_lowerer().as_static(),
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

#[cfg(test)]
mod trial_identity_tests {
    use super::CSharpAdapter;
    use brokk_bifrost_analysis::analyzer::semantic::ids::ContentIdentity;
    use brokk_bifrost_analysis::analyzer::semantic::service::{
        ProgramSemanticsLowerer, semantic_artifact_key_from_content,
    };
    use brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter;
    use brokk_bifrost_core::analyzer::config::{CSharpAnalyzerConfig, CSharpNativeTrial};
    use brokk_bifrost_core::analyzer::model::{Language, LanguageDialect};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#7314: cross-flag C# parsed rows and semantic artifacts shared an identity")]
    fn trial_and_plain_have_distinct_parse_and_semantic_identities() {
        use crate::inline_project::InlineTestProject;
        let fixture = InlineTestProject::with_language(Language::CSharp)
            .file("A.cs", "class A {}")
            .build();
        let file = fixture
            .project_dyn()
            .analyzable_files(Language::CSharp)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let plain = CSharpAdapter::from_config(&CSharpAnalyzerConfig {
            native_trial: CSharpNativeTrial::Off,
            ..Default::default()
        });
        let trial = CSharpAdapter::from_config(&CSharpAnalyzerConfig {
            native_trial: CSharpNativeTrial::On,
            ..Default::default()
        });
        assert_ne!(
            plain.resolution_producer_epoch(),
            trial.resolution_producer_epoch()
        );
        let plain_lowerer = plain.semantic_lowerer();
        let trial_lowerer = trial.semantic_lowerer();
        assert_ne!(
            plain_lowerer.identity().configuration,
            trial_lowerer.identity().configuration
        );
        let key_for = |lowerer: &super::super::semantic::CSharpSemanticLowerer| {
            semantic_artifact_key_from_content(
                &file,
                LanguageDialect::Standard(Language::CSharp),
                ContentIdentity::hash_bytes(b"class A {}"),
                None,
                lowerer.identity(),
            )
            .unwrap()
        };
        assert_ne!(key_for(&plain_lowerer), key_for(&trial_lowerer));
        let plain_ir =
            brokk_bifrost_analysis::analyzer::store::semantic_ir::semantic_ir_producer_epoch(
                &plain_lowerer.identity(),
            );
        let trial_ir =
            brokk_bifrost_analysis::analyzer::store::semantic_ir::semantic_ir_producer_epoch(
                &trial_lowerer.identity(),
            );
        assert_ne!(plain_ir, trial_ir);
    }
}
