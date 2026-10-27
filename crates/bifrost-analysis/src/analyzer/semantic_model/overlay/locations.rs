//! Locations supplied by the eager analyzer or a build's authored anchors.

use super::*;

/// Lazy record projection needs source translation only for Source locators.
#[doc(hidden)]
pub trait SemanticModelLocations {
    fn record_location(
        &self,
        shard: &ActiveSemanticModelShard,
        locator: &Locator,
        fallback_symbol: &str,
        record_kind: &str,
        record_id: &str,
    ) -> SemanticModelLocation;
}

impl<T: IAnalyzer + ?Sized> SemanticModelLocations for T {
    fn record_location(
        &self,
        shard: &ActiveSemanticModelShard,
        locator: &Locator,
        fallback_symbol: &str,
        record_kind: &str,
        record_id: &str,
    ) -> SemanticModelLocation {
        authored_anchor(
            self,
            &shard.manifest.carried_sources,
            locator,
            fallback_symbol,
        )
        .map(SemanticModelLocation::Authored)
        .unwrap_or_else(|| model_location(shard, record_kind, record_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SourceRecordIdentity {
    pack_digest: String,
    record_kind: String,
    record_id: String,
}

impl SourceRecordIdentity {
    fn new(shard: &ActiveSemanticModelShard, record_kind: &str, record_id: &str) -> Self {
        Self {
            pack_digest: shard.manifest.semantic_sha256.clone(),
            record_kind: record_kind.to_owned(),
            record_id: record_id.to_owned(),
        }
    }
}

/// Workspace-derived kind-1 facts, like generated symbols. Only Source
/// locators are translated eagerly; artifact packs contribute no entries.
/// M4 bounds these authored anchors together with the generated facts.
#[derive(Debug, Default)]
pub(crate) struct SourceAnchors {
    anchors: HashMap<SourceRecordIdentity, SemanticModelAuthoredAnchor>,
}

impl SourceAnchors {
    pub(crate) fn digest(&self) -> String {
        let mut entries = self.anchors.iter().collect::<Vec<_>>();
        entries.sort_unstable_by(|(a, _), (b, _)| {
            (&a.pack_digest, &a.record_kind, &a.record_id).cmp(&(
                &b.pack_digest,
                &b.record_kind,
                &b.record_id,
            ))
        });
        let mut digest =
            crate::analyzer::semantic::LengthDelimitedDigest::new(b"semantic-source-anchors-v1");
        for (key, anchor) in entries {
            digest.push(format!("{key:?}:{anchor:?}").as_bytes());
        }
        digest.finish().to_string()
    }

    pub(crate) fn ids_at_path(&self, path: &str) -> Vec<String> {
        self.anchors
            .iter()
            .filter(|(_, anchor)| anchor.path == path)
            .map(|(key, _)| key.record_id.clone())
            .collect()
    }

    pub(crate) fn insert_symbol(&mut self, record_kind: &'static str, symbol: SemanticModelSymbol) {
        if let SemanticModelLocation::Authored(anchor) = symbol.location {
            self.anchors.insert(
                SourceRecordIdentity {
                    pack_digest: symbol.provenance.pack_digest,
                    record_kind: record_kind.to_owned(),
                    record_id: symbol.id,
                },
                anchor,
            );
        }
    }
}

impl SemanticModelLocations for SourceAnchors {
    fn record_location(
        &self,
        shard: &ActiveSemanticModelShard,
        _locator: &Locator,
        _fallback_symbol: &str,
        record_kind: &str,
        record_id: &str,
    ) -> SemanticModelLocation {
        self.anchors
            .get(&SourceRecordIdentity::new(shard, record_kind, record_id))
            .cloned()
            .map(SemanticModelLocation::Authored)
            .unwrap_or_else(|| model_location(shard, record_kind, record_id))
    }
}
