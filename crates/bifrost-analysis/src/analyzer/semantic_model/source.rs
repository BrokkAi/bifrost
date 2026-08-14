use super::{AuthoredSemanticModelPack, Diagnostic};
use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy};
use std::io::Cursor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    Json,
    Yaml,
}

pub(crate) fn parse_source(
    format: SourceFormat,
    bytes: &[u8],
) -> Result<AuthoredSemanticModelPack, Vec<Diagnostic>> {
    let parsed = match format {
        SourceFormat::Json => serde_json::from_slice(bytes).map_err(|error| error.to_string()),
        SourceFormat::Yaml => {
            let options = serde_saphyr::options! {
                budget: serde_saphyr::budget! {
                    max_reader_input_bytes: Some(bytes.len()),
                    max_events: 2_000_000,
                    max_aliases: 0,
                    max_anchors: 0,
                    max_depth: 64,
                    max_inclusion_depth: 0,
                    max_documents: 1,
                    max_nodes: 1_000_000,
                    max_total_scalar_bytes: bytes.len(),
                    max_total_comment_bytes: bytes.len(),
                    max_merge_keys: 0,
                },
                duplicate_keys: DuplicateKeyPolicy::Error,
                merge_keys: MergeKeyPolicy::Error,
                alias_limits: serde_saphyr::alias_limits! {
                    max_total_replayed_events: 0,
                    max_replay_stack_depth: 0,
                    max_alias_expansions_per_anchor: 0,
                },
                strict_booleans: true,
                no_schema: true,
            };
            serde_saphyr::from_reader_with_options(Cursor::new(bytes), options)
                .map_err(|error| error.to_string())
        }
    };

    parsed.map_err(|message| vec![Diagnostic::error("source.parse", "$", message)])
}
