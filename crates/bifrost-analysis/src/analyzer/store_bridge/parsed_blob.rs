//! Engine retained-source publication and configured epoch conveniences.
use super::epoch;
use crate::CancellationToken;
use crate::analyzer::store::semantic_ir::semantic_ir_producer_epoch;
use crate::analyzer::store::*;
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::tree_sitter_analyzer::{
    FileState, PreparedSyntaxPreparation, reparse_retained_source,
};
use crate::analyzer::{Language, ProjectFile};
use crate::hash::HashMap;
use git2::Oid;
use std::sync::Arc;
use tree_sitter::Language as TsLanguage;
#[doc(hidden)]
pub trait AnalyzerStoreEngineExt {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    fn write_parsed_blob<A: LanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        adapter: &A,
        state: &FileState,
    ) -> Result<()>;

    #[doc(hidden)]
    fn write_parsed_blob_at_generation<A: LanguageAdapter>(
        &self,
        file: &ProjectFile,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        adapter: &A,
        state: &FileState,
    ) -> Result<()>;

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    fn prepare_parsed_blob<A: LanguageAdapter>(
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        adapter: &A,
        state: Arc<FileState>,
    ) -> Result<PreparedParsedBlob>;

    fn ensure_language_epoch(
        &self,
        language: Language,
        ts_language: &TsLanguage,
    ) -> Result<GenerationId>;
}

impl AnalyzerStoreEngineExt for AnalyzerStore {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    fn write_parsed_blob<A: LanguageAdapter>(
        &self,
        oid: Oid,
        lang: &str,
        adapter: &A,
        state: &FileState,
    ) -> Result<()> {
        let generation = self.current_generation(lang)?;
        self.write_parsed_blob_at_generation(
            &test_blob_file(),
            oid,
            lang,
            generation,
            adapter,
            state,
        )
    }

    #[doc(hidden)]
    fn write_parsed_blob_at_generation<A: LanguageAdapter>(
        &self,
        file: &ProjectFile,
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        adapter: &A,
        state: &FileState,
    ) -> Result<()> {
        let mut generations = HashMap::default();
        generations.insert(lang.to_owned(), generation);
        if !state.additional_projections.is_empty() {
            let conn = self.active_read_conn()?;
            for (projection_lang, _) in &state.additional_projections {
                let projection_generation = current_generation_conn(&conn, projection_lang)?;
                if generations
                    .insert((*projection_lang).to_owned(), projection_generation)
                    .is_some()
                {
                    return Err(StoreError::new(format!(
                        "duplicate parsed storage projection {projection_lang} for blob {oid}"
                    )));
                }
            }
        }
        for storage_language in generations.keys() {
            self.ensure_resolution_producer_epoch(storage_language, adapter.language())?;
            if let Some(lowerer) = adapter.parse_time_semantic_lowerer() {
                self.ensure_semantic_ir_producer_epoch(
                    storage_language,
                    &semantic_ir_producer_epoch(&lowerer.lowerer().identity()),
                )?;
            }
        }
        require_complete_file_state(state)?;
        let syntax = match reparse_retained_source(adapter, file, state, None) {
            PreparedSyntaxPreparation::Complete(Some(syntax)) => syntax,
            PreparedSyntaxPreparation::Refused(reason) => {
                return Err(StoreError::new(format!(
                    "refusing to write parsed blob {oid}/{lang}: {reason}"
                )));
            }
            PreparedSyntaxPreparation::Complete(None) | PreparedSyntaxPreparation::TimedOut => {
                return Err(StoreError::new(format!(
                    "parsed blob {oid}/{lang} source does not parse within its budget"
                )));
            }
            PreparedSyntaxPreparation::Cancelled => {
                unreachable!("no cancellation token supplied")
            }
        };
        let prepared = match prepare_parsed_blob_at_generations(
            file,
            &syntax,
            oid,
            lang,
            &generations,
            adapter,
            Arc::new(state.clone()),
            &[],
            &CancellationToken::default(),
        )? {
            PreparedParsedBlobPreparation::Prepared(prepared) => *prepared,
            PreparedParsedBlobPreparation::Cancelled => {
                return Err(StoreError::new("parsed blob preparation was cancelled"));
            }
        };
        let (mut outcomes, _) =
            self.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
        let outcome = outcomes.pop().expect("one prepared blob has one outcome");
        match outcome.error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    fn prepare_parsed_blob<A: LanguageAdapter>(
        oid: Oid,
        lang: &str,
        generation: GenerationId,
        adapter: &A,
        state: Arc<FileState>,
    ) -> Result<PreparedParsedBlob> {
        prepare_parsed_blob(oid, lang, generation, adapter, state)
    }

    fn ensure_language_epoch(
        &self,
        language: Language,
        ts_language: &TsLanguage,
    ) -> Result<GenerationId> {
        let epoch = epoch::epoch_for(language, ts_language);
        self.ensure_language_epoch_value(language.config_label(), epoch.as_ref())
    }
}

#[cfg(any(test, feature = "test-support"))]
fn prepare_parsed_blob<A: LanguageAdapter>(
    oid: Oid,
    lang: &str,
    generation: GenerationId,
    adapter: &A,
    state: Arc<FileState>,
) -> Result<PreparedParsedBlob> {
    if !state.additional_projections.is_empty() {
        return Err(StoreError::new(
            "preparing projected parsed blobs requires the captured generation map",
        ));
    }
    let mut generations = HashMap::default();
    generations.insert(lang.to_owned(), generation);
    let file = test_blob_file();
    let syntax = test_blob_syntax(adapter, &file, &state);
    match prepare_parsed_blob_at_generations(
        &file,
        &syntax,
        oid,
        lang,
        &generations,
        adapter,
        state,
        &[],
        &CancellationToken::default(),
    )? {
        PreparedParsedBlobPreparation::Prepared(prepared) => Ok(*prepared),
        PreparedParsedBlobPreparation::Cancelled => {
            Err(StoreError::new("parsed blob preparation was cancelled"))
        }
    }
}
/// The tree a test blob's state is prepared with: the state's source parsed
/// again, the way a path that dropped its tree does.
#[cfg(any(test, feature = "test-support"))]
fn test_blob_syntax<A: LanguageAdapter>(
    adapter: &A,
    file: &ProjectFile,
    state: &FileState,
) -> Arc<PreparedSyntaxTree> {
    match reparse_retained_source(adapter, file, state, None) {
        PreparedSyntaxPreparation::Complete(Some(syntax)) => syntax,
        _ => panic!("a test blob's source must parse within its budget"),
    }
}
