//! The `ReceiverFactsFactory` boundary adapter for JS/TS.
//!
//! The SPI trait and `ReceiverFactContext` carry the framework's
//! `&dyn IAnalyzer`, so this block cannot cross into `brokk-bifrost-js-ts`. It
//! is the whole of what stayed: one downcast per file, then every question is
//! answered by the crate's `JsTsReceiverFactProvider`.
//!
//! JS/TS is the only implementer of `ReceiverFactsFactory` in the repo.

use crate::analyzer::js_ts::providers::resolve_js_ts_source;
use crate::analyzer::languages::{ReceiverFactContext, ReceiverFactsFactory};
use crate::cancellation::CancellationToken;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverFacts;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverFileCtx, ReceiverFileFacts, ReceiverFileSetup,
};
use brokk_bifrost_js_ts::graph::receiver_analysis::{
    JsTsReceiverFactProvider, JsTsReceiverSyntaxIndex, JsTsReceiverSyntaxIndexBuild,
    build_js_ts_receiver_syntax_index_bounded,
};
use brokk_bifrost_js_ts::syntax::{
    JsTsImportBinder, compute_import_binder as compute_jsts_import_binder, parse_js_ts_tree,
};
use std::sync::Arc;

/// One factory for both dialects: the syntax index, import binder and provider are
/// dialect-blind once the grammar has been chosen, and the grammar is chosen by
/// `parse_js_ts_tree` from the file.
pub struct JsTsReceiverFacts;

/// The per-file state a JS/TS receiver query reuses. Both halves cost a full tree walk,
/// which is why they are built once per file and cloned into each query's provider rather
/// than recomputed per query (the binder's per-request retention, #1451).
struct JsTsReceiverFileFacts {
    imports: JsTsImportBinder,
    syntax_index: Arc<JsTsReceiverSyntaxIndex>,
}

impl ReceiverFactsFactory for JsTsReceiverFacts {
    fn prepare_file(&self, ctx: &ReceiverFileCtx<'_>) -> ReceiverFileSetup {
        let Some(tree) = parse_js_ts_tree(ctx.file, ctx.source, ctx.language) else {
            return ReceiverFileSetup::ParseFailed;
        };
        if ctx
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return ReceiverFileSetup::Cancelled;
        }
        match build_js_ts_receiver_syntax_index_bounded(
            tree.root_node(),
            ctx.source,
            ctx.cancellation,
            ctx.max_scope_nodes,
        ) {
            JsTsReceiverSyntaxIndexBuild::Complete { index, visited } => {
                let facts = ReceiverFileFacts::new(JsTsReceiverFileFacts {
                    imports: compute_jsts_import_binder(ctx.source, &tree),
                    syntax_index: index,
                });
                ReceiverFileSetup::Ready {
                    tree,
                    facts,
                    visited,
                }
            }
            JsTsReceiverSyntaxIndexBuild::ExceededScope { visited } => {
                ReceiverFileSetup::ExceededScope { visited }
            }
            JsTsReceiverSyntaxIndexBuild::Cancelled => ReceiverFileSetup::Cancelled,
        }
    }

    fn make_receiver_facts<'a, 'tree: 'a>(
        &self,
        ctx: ReceiverFactContext<'a, 'tree>,
    ) -> Box<dyn ReceiverFacts<'tree> + 'a> {
        // This factory is the only thing that writes these facts, so the stored
        // type is this one by construction; a mismatch is a registration bug.
        let facts = ctx
            .facts
            .downcast::<JsTsReceiverFileFacts>()
            .expect("receiver facts are read back by the language that produced them");
        // The SPI hands the framework's `&dyn IAnalyzer`; everything below the
        // factory is on `JsTsSource`, so the downcast happens once, here.
        // `ReceiverFactsFactory` has no error channel and only the JavaScript and
        // TypeScript language modules register this factory, so a miss is a
        // registration bug rather than a runtime condition.
        let host = resolve_js_ts_source(ctx.analyzer, ctx.language).expect(
            "JsTsReceiverFacts is registered only by the JavaScript and TypeScript language modules",
        );
        Box::new(JsTsReceiverFactProvider::new_with_syntax_index(
            host,
            ctx.definitions,
            ctx.language,
            ctx.file,
            ctx.source,
            ctx.root,
            facts.imports.clone(),
            Arc::clone(&facts.syntax_index),
        ))
    }
}
