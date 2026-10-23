//! Engine retained-source publication and configured epoch conveniences.
use super::epoch;
use crate::CancellationToken;
use crate::analyzer::store::semantic_ir::semantic_ir_producer_epoch;
use crate::analyzer::store::*;
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
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
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    fn prepare_parsed_blob_at_generations<A: LanguageAdapter>(
        file: &ProjectFile,
        syntax: &PreparedSyntaxTree,
        oid: Oid,
        lang: &str,
        generations: &HashMap<String, GenerationId>,
        adapter: &A,
        state: Arc<FileState>,
        required_existing_additional_storage_languages: &[String],
        cancellation: &CancellationToken,
    ) -> Result<PreparedParsedBlobPreparation>;

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
    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    fn prepare_parsed_blob_at_generations<A: LanguageAdapter>(
        file: &ProjectFile,
        syntax: &PreparedSyntaxTree,
        oid: Oid,
        lang: &str,
        generations: &HashMap<String, GenerationId>,
        adapter: &A,
        state: Arc<FileState>,
        required_existing_additional_storage_languages: &[String],
        cancellation: &CancellationToken,
    ) -> Result<PreparedParsedBlobPreparation> {
        prepare_parsed_blob_at_generations(
            file,
            syntax,
            oid,
            lang,
            generations,
            adapter,
            state,
            required_existing_additional_storage_languages,
            cancellation,
        )
    }

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
#[doc(hidden)]
pub fn prepare_parsed_blob<A: LanguageAdapter>(
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

use crate::analyzer::resolution::BindingFragmentId;
use crate::analyzer::resolution::lower_resolution_facts_with_identity_catalog;
use crate::analyzer::store::resolution_prepare::ResolutionInteriorPreparation;
use crate::analyzer::store::resolution_prepare::prepare_resolution_bundle_with_source_facts;
use crate::analyzer::store::semantic_ir::PreparedSemanticIr;

use crate::hash::HashSet;

#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn prepare_parsed_blob_at_generations<A: LanguageAdapter>(
    file: &ProjectFile,
    syntax: &PreparedSyntaxTree,
    oid: Oid,
    lang: &str,
    generations: &HashMap<String, GenerationId>,
    adapter: &A,
    state: Arc<FileState>,
    required_existing_additional_storage_languages: &[String],
    cancellation: &CancellationToken,
) -> Result<PreparedParsedBlobPreparation> {
    macro_rules! stop_if_cancelled {
        () => {
            if cancellation.is_cancelled() {
                return Ok(PreparedParsedBlobPreparation::Cancelled);
            }
        };
    }
    stop_if_cancelled!();
    require_complete_file_state(state.as_ref())?;
    assert!(
        adapter.side_fact_families().admits(state.as_ref()),
        "a {lang} parse produced side facts outside the families its adapter declares: {:?}",
        adapter.side_fact_families()
    );
    let source_facts_version = adapter
        .produces_canonical_source_facts()
        .then_some(source_facts::SOURCE_FACTS_VERSION);
    let source_storage = adapter.source_fact_storage();
    let metadata_bridges_required = adapter.requires_source_declaration_metadata_bridges();
    assert!(!metadata_bridges_required || source_facts_version.is_some());
    if source_facts_version.is_some() && state.source_facts.is_none() {
        return Err(StoreError::new(
            "canonical source publication is required by the producer",
        ));
    }
    let declaration_visibility_version = adapter.declaration_visibility_facts_version();
    let java_type_constructor_version = adapter.java_type_constructor_facts_version();
    let go_source_version = adapter.go_source_facts_version();
    let java_source_version = adapter.java_source_facts_version();
    let scala_source_version = adapter.scala_source_facts_version();
    if scala_source_version.is_some()
        && state
            .source_facts
            .as_ref()
            .and_then(|facts| facts.scala.as_ref())
            .is_none()
    {
        return Err(StoreError::new(
            "Scala publication requires canonical declaration source facts",
        ));
    }
    let ruby_source_version = adapter.ruby_source_facts_version();
    if ruby_source_version.is_some()
        && state
            .source_facts
            .as_ref()
            .and_then(|facts| facts.ruby.as_ref())
            .is_none()
    {
        return Err(StoreError::new(
            "Ruby publication requires canonical load source facts",
        ));
    }
    let php_source_version = adapter.php_source_facts_version();
    if php_source_version.is_some()
        && state
            .source_facts
            .as_ref()
            .and_then(|facts| facts.php.as_ref())
            .is_none()
    {
        return Err(StoreError::new(
            "PHP publication requires canonical declaration source facts",
        ));
    }
    let cpp_source_version = adapter.cpp_source_facts_version();
    let js_ts_source_version = adapter.js_ts_source_facts_version();
    let python_source_version = adapter.python_source_facts_version();
    if python_source_version.is_some()
        && state
            .source_facts
            .as_ref()
            .and_then(|facts| facts.python.as_ref())
            .is_none()
    {
        return Err(StoreError::new(
            "Python publication requires canonical callable return source facts",
        ));
    }
    if java_source_version.is_some()
        && state
            .source_facts
            .as_ref()
            .and_then(|facts| facts.java.as_ref())
            .is_none()
    {
        return Err(StoreError::new(
            "Java publication requires canonical declaration source facts",
        ));
    }
    if go_source_version.is_some()
        && state
            .source_facts
            .as_ref()
            .and_then(|facts| facts.go.as_ref())
            .is_none()
    {
        return Err(StoreError::new(
            "Go publication requires canonical declaration source facts",
        ));
    }
    if cpp_source_version.is_some()
        && state
            .source_facts
            .as_ref()
            .and_then(|facts| facts.cpp.as_ref())
            .is_none()
    {
        return Err(StoreError::new(
            "C++ publication requires canonical declaration source facts",
        ));
    }
    if js_ts_source_version.is_some()
        && state
            .source_facts
            .as_ref()
            .and_then(|facts| facts.js_ts.as_ref())
            .is_none()
    {
        return Err(StoreError::new(
            "JavaScript/TypeScript publication requires canonical source facts",
        ));
    }
    if declaration_visibility_version.is_some()
        && state
            .source_facts
            .as_ref()
            .and_then(|facts| facts.declaration_visibilities.as_ref())
            .is_none()
    {
        return Err(StoreError::new(format!(
            "{} publication requires canonical declaration visibility facts",
            adapter.language().config_label()
        )));
    }
    if adapter.language() == Language::Rust
        && state
            .source_facts
            .as_ref()
            .and_then(|facts| facts.rust_modules.as_ref())
            .is_none()
    {
        return Err(StoreError::new(
            "Rust publication requires canonical module source facts",
        ));
    }
    let generation = generations.get(lang).copied().ok_or_else(|| {
        StoreError::stale_generation(format!(
            "missing captured analyzer generation for prepared storage language {lang}"
        ))
    })?;
    assert_ne!(adapter.language(), Language::None);
    let _collect_units_timing = crate::profiling::scope_with(|| {
        format!("store.prepare_parsed_blob.collect_unit_keys[{lang}][{oid}]")
    });
    let stored_units = collect_stored_units(adapter, state.as_ref());
    let unit_keys = stored_unit_keys_from_units(&stored_units);
    let mut source_declaration_units = state
        .source_declaration_units
        .iter()
        .filter_map(|(declaration, unit)| unit_keys.get(unit).map(|key| (*declaration, *key)))
        .collect::<Vec<_>>();
    source_declaration_units.sort_unstable_by_key(|(declaration, key)| (declaration.get(), *key));
    source_declaration_units.dedup();
    let mut source_declaration_metadata = Vec::new();
    for link in &state.source_declaration_metadata {
        let unit_key = *unit_keys
            .get(&link.unit)
            .expect("source metadata links identify stored units");
        source_declaration_metadata.push((
            link.declaration,
            unit_key,
            usize_to_i64(link.metadata_ordinal)?,
        ));
    }
    source_declaration_metadata
        .sort_unstable_by_key(|(declaration, unit, ordinal)| (declaration.get(), *unit, *ordinal));
    source_declaration_metadata.dedup();
    drop(_collect_units_timing);
    let _resolution_timing = crate::profiling::scope_with(|| {
        format!("store.prepare_parsed_blob.resolution_prepare[{lang}][{oid}]")
    });
    let lowered = {
        let _lowering_timing = crate::profiling::scope_with(|| {
            format!("store.prepare_parsed_blob.resolution_lowering[{lang}][{oid}]")
        });
        lower_resolution_facts_with_identity_catalog(
            BindingFragmentId::unmounted(),
            adapter.language(),
            &state.resolution_facts,
        )
    };
    stop_if_cancelled!();
    let resolution = match prepare_resolution_bundle_with_source_facts(
        &lowered,
        &unit_keys,
        state.source_facts.as_ref(),
        Some(&state.source),
        cancellation,
    )? {
        ResolutionInteriorPreparation::Prepared(bundle) => *bundle,
        ResolutionInteriorPreparation::Cancelled => {
            return Ok(PreparedParsedBlobPreparation::Cancelled);
        }
    };
    drop(lowered);
    drop(_resolution_timing);
    stop_if_cancelled!();
    assert_eq!(resolution.semantic_language(), adapter.language());
    // The tree belongs to the file's primary storage language. A projection
    // reading has its own dialect and carries no semantic IR rows (C++ only).
    let semantic_ir = match adapter.parse_time_semantic_lowerer() {
        Some(lowerer) if lang == adapter.storage_language_key_for_file(file) => {
            let Some(prepared) = prepare_parse_time_semantic_ir(
                lowerer.lowerer(),
                file,
                syntax,
                oid,
                lang,
                cancellation,
            )?
            else {
                return Ok(PreparedParsedBlobPreparation::Cancelled);
            };
            Some(prepared)
        }
        _ => None,
    };
    stop_if_cancelled!();

    let _additional_timing = crate::profiling::scope_with(|| {
        format!("store.prepare_parsed_blob.additional_projections[{lang}][{oid}]")
    });
    // The same blob's other readings (see `FileState::additional_projections`)
    // carry the exact generation captured with the primary. A projection state
    // has no projections of its own, so this traversal is bounded to one level.
    let mut additional = Vec::with_capacity(state.additional_projections.len());
    let mut storage_languages = HashSet::default();
    storage_languages.insert(lang.to_owned());
    for (projection_lang, projection_state) in &state.additional_projections {
        stop_if_cancelled!();
        assert!(
            projection_state.additional_projections.is_empty(),
            "prepared projection nesting must be exactly one level"
        );
        if !storage_languages.insert((*projection_lang).to_owned()) {
            return Err(StoreError::new(format!(
                "duplicate prepared storage projection {projection_lang} for blob {oid}"
            )));
        }
        let projection = prepare_parsed_blob_at_generations(
            file,
            syntax,
            oid,
            projection_lang,
            generations,
            adapter,
            Arc::clone(projection_state),
            &[],
            cancellation,
        )?;
        match projection {
            PreparedParsedBlobPreparation::Prepared(projection) => additional.push(*projection),
            PreparedParsedBlobPreparation::Cancelled => {
                return Ok(PreparedParsedBlobPreparation::Cancelled);
            }
        }
    }
    let mut required_seen = HashSet::default();
    for projection_lang in required_existing_additional_storage_languages {
        stop_if_cancelled!();
        if projection_lang == lang {
            return Err(StoreError::new(format!(
                "required repair projection {projection_lang} equals its primary storage language for blob {oid}"
            )));
        }
        if !required_seen.insert(projection_lang.as_str()) {
            return Err(StoreError::new(format!(
                "duplicate required repair projection {projection_lang} for blob {oid}"
            )));
        }
        if storage_languages.contains(projection_lang) {
            // A fresh dialect-specific reading is more precise than the
            // identical-primary fallback used only when the adapter omits it.
            continue;
        }
        if !generations.contains_key(projection_lang) {
            return Err(StoreError::stale_generation(format!(
                "missing captured analyzer generation for required repair projection {projection_lang}"
            )));
        }
        storage_languages.insert(projection_lang.clone());
        let mut projection_state = state.as_ref().clone();
        projection_state.source.clear();
        projection_state.additional_projections.clear();
        let projection = prepare_parsed_blob_at_generations(
            file,
            syntax,
            oid,
            projection_lang,
            generations,
            adapter,
            Arc::new(projection_state),
            &[],
            cancellation,
        )?;
        match projection {
            PreparedParsedBlobPreparation::Prepared(projection) => additional.push(*projection),
            PreparedParsedBlobPreparation::Cancelled => {
                return Ok(PreparedParsedBlobPreparation::Cancelled);
            }
        }
    }
    stop_if_cancelled!();
    stop_if_cancelled!();
    drop(_additional_timing);
    let _structural_timing = crate::profiling::scope_with(|| {
        format!("store.prepare_parsed_blob.structural_rows[{lang}][{oid}]")
    });
    let persist_lookup_keys = adapter.persist_content_stable_lookup_keys();
    let mut units = Vec::with_capacity(stored_units.len());
    for stored in stored_units {
        stop_if_cancelled!();
        let content_qualifier =
            adapter.storage_content_qualifier(&stored.unit, &state.content_qualifier);
        let prepared_fq = prepare_unit_fq(adapter, &stored.unit, &content_qualifier)?;
        let exact_fqn = persist_lookup_keys.then(|| stored.unit.fq_name());
        let normalized_fqn = exact_fqn
            .as_deref()
            .map(|fqn| adapter.normalize_full_name(fqn));
        let simple_type_name = stored
            .unit
            .is_class()
            .then(|| adapter.simple_type_name(&stored.unit));
        units.push(PreparedUnitRow {
            key: stored.key,
            kind: code_unit_kind_to_i64(stored.unit.kind()),
            short_name: stored.unit.short_name().to_string(),
            identifier: stored.unit.identifier().to_string(),
            content_qualifier: content_qualifier.clone(),
            exact_fqn,
            normalized_fqn,
            simple_type_name,
            signature: stored.unit.signature().map(str::to_string),
            synthetic: bool_to_i64(stored.unit.is_synthetic()),
            is_type_alias: bool_to_i64(stored.is_type_alias),
            top_level_ordinal: stored.top_level_ordinal.map(usize_to_i64).transpose()?,
            in_declarations: bool_to_i64(stored.in_declarations),
            in_definition_lookup: bool_to_i64(stored.in_definition_lookup),
            in_test_region: bool_to_i64(stored.in_test_region),
            fq_segment_count: prepared_fq
                .as_ref()
                .map_or(Ok(0), |fq| usize_to_i64(fq.segments.len()))?,
            fq_segment_bytes: prepared_fq.as_ref().map_or(Ok(0), |fq| {
                usize_to_i64(
                    fq.segments
                        .iter()
                        .map(|(_, kind, segment)| kind.len() + segment.len())
                        .sum(),
                )
            })?,
            fq_anchor_kind: prepared_fq.as_ref().and_then(|fq| fq.anchor_kind),
            fq_anchor_pop: prepared_fq.as_ref().and_then(|fq| fq.anchor_pop),
            fq_package_tail_segments: prepared_fq.as_ref().map(|fq| fq.package_tail_segments),
            exact_fqn_tail: prepared_fq.as_ref().map(|fq| fq.exact_tail.clone()),
            normalized_fqn_tail: prepared_fq
                .as_ref()
                .and_then(|fq| fq.normalized_tail.clone()),
            exact_parent_fqn_tail: prepared_fq.as_ref().map(|fq| fq.exact_parent_tail.clone()),
            normalized_parent_fqn_tail: prepared_fq
                .as_ref()
                .and_then(|fq| fq.normalized_parent_tail.clone()),
            package_fqn_tail: prepared_fq.as_ref().map(|fq| fq.package_tail.clone()),
            relational_fq_segments: prepared_fq
                .as_ref()
                .map(|fq| fq.segments.clone())
                .unwrap_or_default(),
        });
    }

    let mut ranges = Vec::new();
    for (unit, entries) in &state.ranges {
        stop_if_cancelled!();
        let Some(&unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, range) in entries.iter().enumerate() {
            ranges.push((
                unit_key,
                usize_to_i64(ordinal)?,
                usize_to_i64(range.start_byte)?,
                usize_to_i64(range.end_byte)?,
                usize_to_i64(range.start_line)?,
                usize_to_i64(range.end_line)?,
            ));
        }
    }
    let mut signatures = Vec::new();
    for (unit, entries) in &state.signatures {
        stop_if_cancelled!();
        let Some(&unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, signature) in entries.iter().enumerate() {
            signatures.push((unit_key, usize_to_i64(ordinal)?, signature.clone()));
        }
    }
    let mut signature_metadata = Vec::new();
    let mut signature_metadata_signature_ordinals = Vec::new();
    for (unit, entries) in &state.signature_metadata {
        stop_if_cancelled!();
        let Some(&unit_key) = unit_keys.get(unit) else {
            continue;
        };
        if entries.is_empty() {
            continue;
        }
        let signature_ordinals = state
            .signature_metadata_signature_ordinals
            .get(unit)
            .unwrap_or_else(|| {
                panic!("signature metadata for {unit:?} has no captured signature ordinals")
            });
        assert_eq!(
            signature_ordinals.len(),
            entries.len(),
            "signature metadata and captured signature ordinal lengths must agree for {unit:?}"
        );
        let signatures = state.signatures.get(unit).unwrap_or_else(|| {
            panic!("signature metadata for {unit:?} has no captured signature rows")
        });
        for (ordinal, (metadata, &signature_ordinal)) in
            entries.iter().zip(signature_ordinals).enumerate()
        {
            stop_if_cancelled!();
            assert!(
                signature_ordinal < signatures.len(),
                "signature metadata for {unit:?} points ordinal {signature_ordinal} beyond {} signatures",
                signatures.len()
            );
            let mut columns = SignatureMetadataColumns::encode(metadata)?;
            if java_type_constructor_version.is_some()
                && !unit.is_synthetic()
                && unit.is_class()
                && metadata.java_type_constructor_shape().is_none()
            {
                return Err(StoreError::new(format!(
                    "canonical Java type constructor shape is unavailable for {unit:?}"
                )));
            }
            assert!(
                metadata.java_type_constructor_shape().is_none()
                    || (adapter.language() == Language::Java
                        && unit.is_class()
                        && !unit.is_synthetic()),
                "Java type constructor shape belongs to a nonsynthetic Java type: {unit:?}"
            );
            if declaration_visibility_version.is_some() && !unit.is_synthetic() {
                columns.callable_declared_visibility = None;
            }
            signature_metadata.push((unit_key, usize_to_i64(ordinal)?, columns));
            signature_metadata_signature_ordinals.push((
                unit_key,
                usize_to_i64(ordinal)?,
                usize_to_i64(signature_ordinal)?,
            ));
        }
    }
    signature_metadata_signature_ordinals.sort_unstable();
    for (unit, ordinals) in &state.signature_metadata_signature_ordinals {
        assert!(
            ordinals.is_empty()
                || !unit_keys.contains_key(unit)
                || state
                    .signature_metadata
                    .get(unit)
                    .is_some_and(|metadata| !metadata.is_empty()),
            "captured signature ordinals for {unit:?} have no metadata rows"
        );
    }
    let cpp_templates =
        cpp_template::PreparedCppTemplates::prepare(&state.cpp_template_metadata, &unit_keys)?;
    let mut supertypes = Vec::new();
    for (unit, entries) in &state.raw_supertypes {
        stop_if_cancelled!();
        let Some(&unit_key) = unit_keys.get(unit) else {
            continue;
        };
        for (ordinal, raw) in entries.iter().enumerate() {
            supertypes.push((
                unit_key,
                usize_to_i64(ordinal)?,
                raw.clone(),
                state
                    .supertype_lookup_paths
                    .get(unit)
                    .and_then(|paths| paths.get(ordinal))
                    .cloned()
                    .unwrap_or_default(),
            ));
        }
    }
    let mut children = Vec::new();
    for (parent, entries) in &state.children {
        stop_if_cancelled!();
        let Some(&parent_key) = unit_keys.get(parent) else {
            continue;
        };
        for (ordinal, child) in entries.iter().enumerate() {
            let Some(&child_key) = unit_keys.get(child) else {
                continue;
            };
            children.push((parent_key, child_key, usize_to_i64(ordinal)?));
        }
    }
    let mut ruby_dispatch_modes = Vec::new();
    for (unit, mode) in &state.ruby_method_dispatch_modes {
        stop_if_cancelled!();
        if let Some(&unit_key) = unit_keys.get(unit) {
            ruby_dispatch_modes.push((unit_key, ruby_dispatch_mode_to_i64(*mode)));
        }
    }
    let mut scala_traits = Vec::new();
    for unit in &state.scala_traits {
        stop_if_cancelled!();
        if let Some(&unit_key) = unit_keys.get(unit) {
            scala_traits.push(unit_key);
        }
    }
    let mut materialization_records = Vec::new();
    for (ordinal, record) in state.materialization_records.iter().enumerate() {
        stop_if_cancelled!();
        let (unit, payload) = record.split();
        let unit_key = match unit {
            Some(unit) => match unit_keys.get(unit) {
                Some(&key) => Some(key),
                None => continue,
            },
            None => None,
        };
        materialization_records.push((usize_to_i64(ordinal)?, unit_key, serialize_blob(&payload)?));
    }
    stop_if_cancelled!();
    let imports = ImportRows::from_imports(
        &state.imports,
        state
            .source_facts
            .as_ref()
            .map(|source| source.generic_imports.as_slice()),
    )?;
    stop_if_cancelled!();
    let mut scala_exports = Vec::new();
    for (owner, entries) in &state.scala_exports {
        stop_if_cancelled!();
        let Some(&owner_key) = unit_keys.get(owner) else {
            continue;
        };
        for (ordinal, info) in entries.iter().enumerate() {
            scala_exports.push((owner_key, usize_to_i64(ordinal)?, serialize_blob(info)?));
        }
    }
    stop_if_cancelled!();
    let rust_facts =
        RustFactRows::from_facts(&state.rust_usage_facts, state.source_facts.as_ref())?;
    stop_if_cancelled!();
    let mut type_identifiers: Vec<_> = state.type_identifiers.iter().cloned().collect();
    type_identifiers.sort();
    stop_if_cancelled!();
    drop(_structural_timing);

    let optional_counts = optional_fact_counts(
        cpp_templates.header_count(),
        ruby_dispatch_modes.len(),
        scala_traits.len(),
        scala_exports.len(),
        materialization_records.len(),
        signature_metadata_signature_ordinals.len(),
    );
    let semantic_logical_rows = semantic_ir
        .as_ref()
        .map_or(0, PreparedSemanticIr::logical_rows);
    let semantic_payload_bytes = semantic_ir
        .as_ref()
        .map_or(0, PreparedSemanticIr::payload_bytes);
    let parsed_logical_rows = saturating_sum([
        4,
        semantic_logical_rows,
        optional_counts.nonzero_len(),
        units.len(),
        saturating_sum(units.iter().map(|row| row.relational_fq_segments.len())),
        ranges.len(),
        signatures.len(),
        signature_metadata.len(),
        saturating_sum(
            signature_metadata
                .iter()
                .map(|(_, _, columns)| columns.parameter_count),
        ),
        signature_metadata_signature_ordinals.len(),
        supertypes.len(),
        children.len(),
        imports.logical_rows(),
        scala_exports.len(),
        type_identifiers.len(),
        ruby_dispatch_modes.len(),
        scala_traits.len(),
        materialization_records.len(),
        rust_facts.logical_rows(),
        cpp_templates.logical_rows(),
    ]);
    let unit_string_bytes = saturating_sum(units.iter().map(|row| {
        saturating_sum([
            row.short_name.len(),
            row.identifier.len(),
            row.content_qualifier.len(),
            row.exact_fqn.as_ref().map_or(0, String::len),
            row.normalized_fqn.as_ref().map_or(0, String::len),
            row.simple_type_name.as_ref().map_or(0, String::len),
            row.signature.as_ref().map_or(0, String::len),
            row.fq_anchor_kind.map_or(0, str::len),
            row.exact_fqn_tail.as_ref().map_or(0, String::len),
            row.normalized_fqn_tail.as_ref().map_or(0, String::len),
            row.exact_parent_fqn_tail.as_ref().map_or(0, String::len),
            row.normalized_parent_fqn_tail
                .as_ref()
                .map_or(0, String::len),
            row.package_fqn_tail.as_ref().map_or(0, String::len),
            saturating_sum(
                row.relational_fq_segments
                    .iter()
                    .map(|(_, kind, segment)| kind.len().saturating_add(segment.len())),
            ),
        ])
    }));
    let string_bytes = saturating_sum([
        unit_string_bytes,
        saturating_sum(signatures.iter().map(|(_, _, text)| text.len())),
        // Sum the metadata cells and relational parameter payload. Read-side
        // materialization separately budgets the generated parameter JSON.
        saturating_sum(
            signature_metadata
                .iter()
                .map(|(_, _, columns)| columns.stored_text_bytes()),
        ),
        saturating_sum(
            supertypes
                .iter()
                .map(|(_, _, raw, path)| raw.len().saturating_add(path.len())),
        ),
        imports.string_bytes(),
        saturating_sum(type_identifiers.iter().map(String::len)),
        rust_facts.string_bytes(),
        cpp_templates.payload_bytes(),
    ]);
    let binary_bytes = saturating_sum([
        saturating_sum(scala_exports.iter().map(|(_, _, bytes)| bytes.len())),
        saturating_sum(
            materialization_records
                .iter()
                .map(|(_, _, bytes)| bytes.len()),
        ),
    ]);
    let content_package = adapter.storage_file_content_qualifier(&state.content_qualifier);
    let contains_tests = bool_to_i64(adapter.storage_contains_tests(&state));
    let parsed_payload_bytes = state
        .source
        .len()
        .saturating_add(string_bytes)
        .saturating_add(binary_bytes)
        .saturating_add(content_package.len())
        .saturating_add(semantic_payload_bytes);
    stop_if_cancelled!();
    let (source_rows, source_bytes) = state.source_facts.as_ref().map_or((0, 0), |facts| {
        source_facts::source_fact_cost(
            source_storage,
            facts,
            &source_declaration_units,
            &source_declaration_metadata,
        )
    });
    let (projected_visibility_rows, projected_visibility_bytes) =
        if declaration_visibility_version.is_some() {
            let Some(cost) = resolution.declaration_visibility_storage_cost(cancellation) else {
                return Ok(PreparedParsedBlobPreparation::Cancelled);
            };
            cost
        } else {
            (0, 0)
        };
    let logical_rows = parsed_logical_rows
        .saturating_add(
            resolution
                .logical_rows()
                .checked_sub(projected_visibility_rows)
                .expect("projected visibility rows belong to the native logical family"),
        )
        .saturating_add(source_rows);
    let payload_bytes = parsed_payload_bytes
        .saturating_add(
            resolution
                .payload_bytes()
                .checked_sub(projected_visibility_bytes)
                .expect("projected visibility bytes belong to the native logical family"),
        )
        .saturating_add(source_bytes)
        .saturating_add(lang.len());

    let _fragment_timing = crate::profiling::scope_with(|| {
        format!("store.prepare_parsed_blob.fragment_build[{lang}][{oid}]")
    });
    Ok(PreparedParsedBlobPreparation::Prepared(Box::new(
        PreparedParsedBlob {
            oid,
            oid_text: oid.to_string(),
            lang: lang.to_string(),
            generation,
            state,
            units,
            source_declaration_units,
            source_declaration_metadata,
            declaration_visibility_version,
            java_type_constructor_version,
            go_source_version,
            java_source_version,
            scala_source_version,
            ruby_source_version,
            php_source_version,
            cpp_source_version,
            source_facts_version,
            source_storage,
            metadata_bridges_required,
            js_ts_source_version,
            python_source_version,
            ranges,
            signatures,
            signature_metadata,
            signature_metadata_signature_ordinals,
            cpp_templates,
            supertypes,
            children,
            imports,
            scala_exports,
            rust_facts,
            type_identifiers,
            ruby_dispatch_modes,
            scala_traits,
            materialization_records,
            contains_tests,
            content_package,
            resolution,
            semantic_ir,
            logical_rows,
            payload_bytes,
            mutation_logical_rows: saturating_sum(
                std::iter::once(logical_rows)
                    .chain(additional.iter().map(|blob| blob.mutation_logical_rows)),
            ),
            mutation_payload_bytes: saturating_sum(
                std::iter::once(payload_bytes)
                    .chain(additional.iter().map(|blob| blob.mutation_payload_bytes)),
            ),
            additional,
        },
    )))
}

#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::store::python_unit_summaries::{PythonEnvironmentPublication, portable};
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::store::resolution_publication::{
    ResolutionContentInput, ResolutionContentPublicationOutcome,
};
#[cfg(any(test, feature = "test-support"))]
use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;
#[cfg(any(test, feature = "test-support"))]
use std::path::PathBuf;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub trait PythonEnvironmentPublicationEngineExt {
    #[allow(clippy::too_many_arguments)]
    /// Publish one prepared selected source, then stage its file-local facts.
    /// The language crate owns parsing; preparation artifacts die here.
    fn stage_prepared_source<A: LanguageAdapter>(
        &self,
        file: ProjectFile,
        syntax: &PreparedSyntaxTree,
        oid: git2::Oid,
        adapter: &A,
        state: Arc<FileState>,
        revision: i64,
        facts: FileResolutionFacts,
        roots: Vec<PathBuf>,
    ) -> Result<()>;
}
#[cfg(any(test, feature = "test-support"))]
impl PythonEnvironmentPublicationEngineExt for PythonEnvironmentPublication {
    #[allow(clippy::too_many_arguments)]
    fn stage_prepared_source<A: LanguageAdapter>(
        &self,
        file: ProjectFile,
        syntax: &PreparedSyntaxTree,
        oid: git2::Oid,
        adapter: &A,
        state: Arc<FileState>,
        revision: i64,
        facts: FileResolutionFacts,
        roots: Vec<PathBuf>,
    ) -> Result<()> {
        let generations = [("python".to_owned(), self.snapshot.generation)]
            .into_iter()
            .collect();
        let prepared = AnalyzerStore::prepare_parsed_blob_at_generations(
            &file,
            syntax,
            oid,
            "python",
            &generations,
            adapter,
            state,
            &[],
            &CancellationToken::default(),
        )?;
        let PreparedParsedBlobPreparation::Prepared(prepared) = prepared else {
            return Err(StoreError::new("native Python preparation was cancelled"));
        };
        let mut snapshot = self.snapshot.clone();
        snapshot.revision = revision;
        // The explicit native harness bridges cached admission and publication.
        // Keep that pair atomic with respect to other harness sessions: a second
        // profile must not replace identical blob rows and cascade old summaries.
        // This bounded lock retains no workspace data and is never on production.
        static PUBLICATION: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let publication_guard = PUBLICATION.lock().expect("native publication lock");
        let cached = self.store.admit_cached_selected_content(
            &snapshot,
            &portable(file.rel_path()),
            oid,
            &ResolutionContentInput::Parsed {
                content_oid: oid,
                semantic_language: Language::Python,
            },
            &CancellationToken::default(),
        )?;
        let current = if let ResolutionContentPublicationOutcome::Ready(content) = &cached {
            self.store
                .python_binding_source_is_current(content.witness().blob_id())?
        } else {
            false
        };
        let published = if current {
            cached
        } else {
            self.store.publish_selected_parsed_content(
                &snapshot,
                &portable(file.rel_path()),
                *prepared,
                &CancellationToken::default(),
            )?
        };
        drop(publication_guard);
        let ResolutionContentPublicationOutcome::Ready(content) = published else {
            return Err(StoreError::new(format!(
                "native Python publication: {published:?}"
            )));
        };
        let blob_id = content.witness().blob_id();
        self.stage_facts(file, oid.to_string(), blob_id, facts, roots)
    }
}
