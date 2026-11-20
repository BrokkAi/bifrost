//! One exact Rust syntax backing and its inventories in the active request.
pub use super::prepared_macro_source::{
    PreparedMacroSource as PreparedRustSource, SourceCancelled,
};
use crate::analyzer::i_analyzer::{AnalyzerQueryScope, QueryReadReceipt, QueryScope};
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::structural::spec::{EmbeddedSyntaxForest, EmbeddedSyntaxStop};
use brokk_bifrost_core::domain_memo::{Counter, ReplayingRegion};
use brokk_bifrost_core::retention_budget::{BudgetedValue, RetainedBytes};
use brokk_bifrost_rust::macro_matcher::MacroDefinitionInventory;
use std::sync::Arc;

#[derive(Clone, PartialEq, Eq, Hash)]
struct SourceKey {
    file: ProjectFile,
    blob: git2::Oid,
    variant: brokk_bifrost_core::gitblob::ParseVariant,
}
impl RetainedBytes for SourceKey {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.file.retained_bytes()
    }
}

brokk_bifrost_core::domain_memo_set! {
    struct RustSourceMemo {
        entries: ReplayingRegion<SourceKey, PreparedRustSource>,
        builds: Counter<std::sync::atomic::AtomicUsize>,
    }
}

/// Exact source already owned by a dispatch caller without indexed syntax.
/// This backing is never inserted into the request registry.
pub fn exact_rust_source(
    source: Arc<str>,
    tree: tree_sitter::Tree,
    cancellation: Option<&crate::CancellationToken>,
) -> Result<PreparedRustSource, SourceCancelled> {
    use brokk_bifrost_core::analyzer::prepared_syntax::{
        PreparedSourceOrigin, PreparedSyntaxSource,
    };
    let lines = brokk_bifrost_core::text_utils::compute_line_starts(&source);
    let prepared = Arc::new(PreparedSyntaxTree::new(
        PreparedSyntaxSource::Exact(source),
        tree,
        lines,
        crate::analyzer::LanguageDialect::Standard(Language::Rust),
        PreparedSourceOrigin::Disk,
        None,
    ));
    build_prepared_source(prepared, None, cancellation)
}

fn build_prepared_source(
    prepared: Arc<PreparedSyntaxTree>,
    receipt: Option<QueryReadReceipt>,
    cancellation: Option<&crate::CancellationToken>,
) -> Result<PreparedRustSource, SourceCancelled> {
    let spec =
        crate::analyzer::structural_spec_for(Language::Rust).expect("Rust has a structural spec");
    let embedded = match EmbeddedSyntaxForest::parse(
        spec,
        prepared.tree().root_node(),
        prepared.source(),
        200_000,
        cancellation,
    ) {
        Err(EmbeddedSyntaxStop::Cancelled) => return Err(SourceCancelled),
        other => other.map(Arc::new),
    };
    let mut inventories = std::collections::HashMap::new();
    let fragments = embedded
        .as_ref()
        .ok()
        .into_iter()
        .flat_map(|forest| forest.trees().iter().map(|fragment| &fragment.tree));
    for tree in std::iter::once(prepared.tree()).chain(fragments) {
        let inventory = MacroDefinitionInventory::build(tree, prepared.source(), &|| {
            !cancellation.is_some_and(crate::CancellationToken::is_cancelled)
        })
        .map_err(|_| SourceCancelled)?;
        inventories.insert(tree.root_node().id(), Arc::new(inventory));
    }
    let source = match prepared.backing() {
        brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxSource::Exact(source) => {
            Arc::clone(source)
        }
        brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxSource::Indexed(_) => {
            Arc::from(prepared.source())
        }
    };
    Ok(PreparedRustSource {
        prepared,
        source,
        embedded,
        inventories,
        receipt,
    })
}

/// Prepare only complete source reads. Cancellation is never retained. An
/// embedded forest's deterministic fixed-limit result belongs only to syntax
/// consumers; primary-source proofs do not consume that auxiliary result.
pub fn request_rust_source(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    cancellation: Option<&crate::CancellationToken>,
) -> Result<Option<BudgetedValue<PreparedRustSource>>, SourceCancelled> {
    let active = analyzer.active_query_cancellation();
    let combined = cancellation
        .zip(active.as_ref())
        .map(|(operation, request)| request.combined_with(operation));
    let cancellation = combined.as_ref().or(cancellation).or(active.as_ref());
    if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
        return Err(SourceCancelled);
    }
    let cpu = crate::profiling::enabled().then(crate::profiling::thread_cpu_time);
    let scope = AnalyzerQueryScope::new(analyzer);
    let (prepared, receipt) = QueryReadReceipt::capture(analyzer, || {
        crate::analyzer::languages::language_support_for_hook(
            Language::Rust,
            "request_prepared_syntax",
        )
        .and_then(|support| support.request_prepared_syntax(analyzer, scope.token(), file))
    });
    let Some(prepared) = prepared else {
        return Ok(None);
    };
    if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
        return Err(SourceCancelled);
    }
    let key = SourceKey {
        file: file.clone(),
        blob: prepared.source_oid(),
        variant: prepared.parse_variant(),
    };
    let registry = analyzer.owned_lookup_memo();
    let memo = registry
        .as_ref()
        .and_then(|registry| registry.memo::<RustSourceMemo>());
    let retain = receipt.reusable();
    let fallback_cancellation = crate::CancellationToken::default();
    let cancellation = cancellation.unwrap_or(&fallback_cancellation);
    let prepare = || {
        let mut source = build_prepared_source(prepared, Some(receipt), Some(cancellation))?;
        if cancellation.is_cancelled() {
            return Err(SourceCancelled);
        }
        if retain {
            source
                .receipt
                .as_mut()
                .expect("prepared source captured its reads")
                .retain_root();
        }
        brokk_bifrost_core::profile_count!("rust_source.prepared.builds", 1);
        if let Some(cpu) = cpu {
            crate::profiling::note_with(|| {
                format!(
                    "rust_source.prepared_build process={} file={:?} blob={} cpu_ns={}",
                    std::process::id(),
                    crate::path_utils::rel_path_string(file),
                    key.blob,
                    crate::profiling::thread_cpu_time()
                        .saturating_sub(cpu)
                        .as_nanos(),
                )
            });
        }
        if let Some(memo) = &memo {
            memo.builds
                .0
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(source)
    };
    if retain && let Some(memo) = &memo {
        return memo
            .entries
            .get_or_try_build(&key, cancellation, prepare, |source| {
                source
                    .receipt
                    .as_ref()
                    .expect("retained source has a complete receipt")
                    .replay(analyzer);
                brokk_bifrost_core::profile_count!("rust_source.prepared.hits", 1);
            })?
            .map(Some)
            .ok_or(SourceCancelled);
    }
    prepare().map(BudgetedValue::request_only).map(Some)
}

#[cfg(any(test, feature = "test-support"))]
pub fn source_builds_for_test(analyzer: &dyn IAnalyzer) -> usize {
    analyzer
        .owned_lookup_memo()
        .and_then(|registry| registry.memo::<RustSourceMemo>())
        .map_or(0, |memo| {
            memo.builds.0.load(std::sync::atomic::Ordering::Relaxed)
        })
}
