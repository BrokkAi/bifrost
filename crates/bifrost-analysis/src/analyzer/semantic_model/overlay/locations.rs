//! Locations supplied by the eager analyzer or a build's authored anchors.

use super::*;
use brokk_bifrost_semantic::analyzer::semantic_model::validate::is_canonical_relative_path;

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
        // Row-backed activation hydrates every source locator here, including
        // locators that have no workspace or carried-source anchor.
        if let Locator::Source { path, .. } = locator {
            assert!(is_canonical_relative_path(path), "{path:?}");
        }
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

pub struct CarriedSourceLocations;

impl SemanticModelLocations for CarriedSourceLocations {
    fn record_location(
        &self,
        shard: &ActiveSemanticModelShard,
        locator: &Locator,
        fallback_symbol: &str,
        record_kind: &str,
        record_id: &str,
    ) -> SemanticModelLocation {
        carried_source_anchor(&shard.manifest.carried_sources, locator, fallback_symbol)
            .map(SemanticModelLocation::Authored)
            .unwrap_or_else(|| model_location(shard, record_kind, record_id))
    }
}

pub use crate::analyzer::store::semantic_composition::SourceAnchors;

pub struct SourceAnchorView<'a> {
    pub activation: &'a SourceAnchors,
    pub request: Option<RequestAnchors>,
}

pub enum RequestAnchors {
    Standalone(crate::retention_budget::BudgetedValue<SourceAnchors>),
    Search(
        crate::retention_budget::BudgetedValue<
            crate::analyzer::store::semantic_composition::ComposedSearchInputs,
        >,
    ),
}

impl std::ops::Deref for RequestAnchors {
    type Target = SourceAnchors;
    fn deref(&self) -> &SourceAnchors {
        match self {
            Self::Standalone(value) => value,
            Self::Search(value) => &value.anchors,
        }
    }
}

impl SourceAnchorView<'_> {
    /// Every authored path of the activation and request anchors.
    pub fn authored_paths(&self) -> impl Iterator<Item = &str> {
        self.activation.authored_paths().chain(
            self.request
                .iter()
                .flat_map(|request| request.authored_paths()),
        )
    }

    pub fn ids_at_path(&self, path: &str) -> Vec<String> {
        let mut ids = self.activation.ids_at_path(path);
        if let Some(request) = &self.request {
            ids.extend(request.ids_at_path(path));
        }
        ids
    }
}

impl SemanticModelLocations for SourceAnchorView<'_> {
    fn record_location(
        &self,
        shard: &ActiveSemanticModelShard,
        _locator: &Locator,
        _fallback_symbol: &str,
        record_kind: &str,
        record_id: &str,
    ) -> SemanticModelLocation {
        self.activation
            .get(shard, record_kind, record_id)
            .or_else(|| {
                self.request
                    .as_ref()
                    .and_then(|request| request.get(shard, record_kind, record_id))
            })
            .cloned()
            .map(SemanticModelLocation::Authored)
            .unwrap_or_else(|| model_location(shard, record_kind, record_id))
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
        self.get(shard, record_kind, record_id)
            .cloned()
            .map(SemanticModelLocation::Authored)
            .unwrap_or_else(|| model_location(shard, record_kind, record_id))
    }
}

/// Activation source inputs have one owner. The authored view serves queries;
/// the eager dependency view includes locators that have no authored anchor.
/// Row-backed dependencies stay in the catalog's indexed authored_path column.
#[derive(Debug, Clone, Default)]
pub(super) struct SourceLocationInputs {
    authored: SourceAnchors,
    eager_by_path: std::collections::BTreeMap<String, SourcePathBindings>,
}

#[derive(Debug, Clone, Default)]
struct SourcePathBindings {
    locators: Vec<SourceLocatorBinding>,
    generated: bool,
}

/// Indexed form of the shared component-wise changed-path relation. A listed
/// file can replace a former directory, or lie below a former file, so both
/// ancestor equality and the descendant subtree are candidates.
pub(super) struct LocatorPathQuery {
    ancestors: Vec<String>,
    pub(super) ancestors_json: String,
    pub(super) descendant_start: String,
    pub(super) descendant_end: String,
}

impl LocatorPathQuery {
    fn new(path: &Path) -> Self {
        let normalized = path.to_string_lossy().replace('\\', "/");
        let ancestors = path
            .ancestors()
            .filter(|path| !path.as_os_str().is_empty())
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .collect::<Vec<_>>();
        Self {
            ancestors_json: serde_json::to_string(&ancestors).expect("paths serialize"),
            ancestors,
            descendant_start: format!("{normalized}/"),
            // '/' has the immediate ASCII successor '0'. These bounds select
            // exactly the normalized subtree, including non-ASCII components.
            descendant_end: format!("{normalized}0"),
        }
    }
}

#[derive(Debug, Clone)]
struct SourceLocatorBinding {
    shard_index: usize,
    locator: Locator,
    fallback_symbol: String,
    record_kind: &'static str,
    record_id: String,
}

impl std::ops::Deref for SourceLocationInputs {
    type Target = SourceAnchors;

    fn deref(&self) -> &SourceAnchors {
        &self.authored
    }
}

impl SourceLocationInputs {
    pub(super) fn new(
        authored: SourceAnchors,
        active: &ResolvedActiveSemanticModels,
        eager_symbols: &[SemanticModelSymbol],
    ) -> Self {
        let mut inputs = Self {
            authored,
            ..Self::default()
        };
        // These references live only during construction. Originals are still
        // present here, before composition removes contributing declarations.
        let mut locators = HashMap::default();
        for (index, shard) in active.shards.iter().enumerate() {
            if shard.decoded.is_none() {
                continue;
            }
            if let Some((types, members, _)) = shard.decoded().payload().declaration_facts() {
                for record in types {
                    locators.insert(
                        (
                            shard.manifest.semantic_sha256.as_str(),
                            "type",
                            record.id.as_str(),
                        ),
                        (index, &record.locator),
                    );
                }
                for record in members {
                    locators.insert(
                        (
                            shard.manifest.semantic_sha256.as_str(),
                            "member",
                            record.id.as_str(),
                        ),
                        (index, &record.locator),
                    );
                }
            }
        }
        // Build both eager views together from the same inventory. There is
        // no dependency index over the post-composition query results.
        for symbol in eager_symbols {
            let record_kind = if symbol.owner_id.is_none() {
                "type"
            } else {
                "member"
            };
            let source = locators
                .get(&(
                    symbol.provenance.pack_digest.as_str(),
                    record_kind,
                    symbol.id.as_str(),
                ))
                .copied();
            if let Some((shard_index, locator @ Locator::Source { path, .. })) = source {
                assert!(is_canonical_relative_path(path), "{path:?}");
                inputs
                    .eager_by_path
                    .entry(path.clone())
                    .or_default()
                    .locators
                    .push(SourceLocatorBinding {
                        shard_index,
                        locator: locator.clone(),
                        fallback_symbol: symbol.qualified_name.clone(),
                        record_kind,
                        record_id: symbol.id.clone(),
                    });
            } else if let SemanticModelLocation::Authored(anchor) = &symbol.location {
                inputs
                    .eager_by_path
                    .entry(anchor.path.clone())
                    .or_default()
                    .generated = true;
            }
            inputs.authored.insert_symbol(record_kind, symbol.clone());
        }
        inputs
    }

    pub(super) fn retained_bytes_lower_bound(&self) -> usize {
        self.authored
            .retained_bytes_lower_bound()
            .saturating_add(std::mem::size_of::<Self>())
            .saturating_add(
                self.eager_by_path
                    .len()
                    .saturating_mul(std::mem::size_of::<(String, SourcePathBindings)>()),
            )
            .saturating_add(
                self.eager_by_path
                    .iter()
                    .map(|(path, bindings)| {
                        path.capacity()
                            + bindings.locators.capacity()
                                * std::mem::size_of::<SourceLocatorBinding>()
                            + bindings
                                .locators
                                .iter()
                                .map(|binding| {
                                    binding.record_id.capacity()
                                        + binding.fallback_symbol.capacity()
                                        + match &binding.locator {
                                            Locator::Source { path, symbol } => {
                                                path.capacity()
                                                    + symbol.as_ref().map_or(0, String::capacity)
                                            }
                                            _ => unreachable!("only source locators are indexed"),
                                        }
                                })
                                .sum::<usize>()
                    })
                    .sum::<usize>(),
            )
    }

    pub(super) fn bindings_unchanged(
        &self,
        analyzer: &dyn IAnalyzer,
        active: &ResolvedActiveSemanticModels,
        generated: &[SemanticModelSymbol],
        relations: &[SemanticModelRelation],
        changed: &brokk_bifrost_core::analyzer::changed_paths::ChangedPaths,
    ) -> bool {
        // Keep the old spelling protection for workspace-bound anchors.
        // Only uncertain events scan that retained view; ordinary listed file
        // saves discover their related bindings through the path indexes.
        if changed.has_uncertified_paths()
            && self.authored.authored_anchors().any(|anchor| {
                is_workspace_anchor(anchor) && changed.touches(Path::new(&anchor.path))
            })
        {
            return false;
        }
        let paths = changed.exact_paths();
        let queries = paths
            .iter()
            .map(|path| LocatorPathQuery::new(path))
            .collect::<Vec<_>>();
        let mut eager_paths = std::collections::BTreeSet::new();
        for query in &queries {
            for ancestor in &query.ancestors {
                if let Some((path, _)) = self.eager_by_path.get_key_value(ancestor) {
                    eager_paths.insert(path);
                }
            }
            eager_paths.extend(
                self.eager_by_path
                    .range(query.descendant_start.clone()..query.descendant_end.clone())
                    .map(|(path, _)| path),
            );
        }
        let comparison = SourceAnchorComparison {
            analyzer,
            published: &self.authored,
            changed,
            unchanged: std::cell::Cell::new(true),
        };
        for path in eager_paths {
            let bindings = &self.eager_by_path[path];
            if bindings.generated {
                return false;
            }
            for binding in &bindings.locators {
                comparison.record_location(
                    &active.shards[binding.shard_index],
                    &binding.locator,
                    &binding.fallback_symbol,
                    binding.record_kind,
                    &binding.record_id,
                );
            }
        }
        if !comparison.unchanged.get() {
            return false;
        }
        if !active
            .shards
            .iter()
            .any(|shard| shard.decoded.is_none() && !shard.request_owned())
        {
            return true;
        }
        let reads = composition::RowCompositionReads::activation_only(active, generated, relations);
        let answer = reads.source_bindings_unchanged(&comparison, &queries);
        // An incomplete catalog read cannot prove carry; the ordinary warm
        // retries activation on the next generation.
        crate::analyzer::store::model_catalog::semantic_catalog_question(
            "SOURCE_LOCATOR_BINDINGS",
            active.active_model_set_hash(),
            answer,
        )
        .is_ok_and(|complete| complete && comparison.unchanged.get())
    }
}

pub(super) struct SourceAnchorComparison<'a> {
    analyzer: &'a dyn IAnalyzer,
    published: &'a SourceAnchors,
    changed: &'a brokk_bifrost_core::analyzer::changed_paths::ChangedPaths,
    pub(super) unchanged: std::cell::Cell<bool>,
}

impl SemanticModelLocations for SourceAnchorComparison<'_> {
    fn record_location(
        &self,
        shard: &ActiveSemanticModelShard,
        locator: &Locator,
        fallback_symbol: &str,
        record_kind: &str,
        record_id: &str,
    ) -> SemanticModelLocation {
        // Request-owned sources bind only to the pack's immutable carried
        // entries. Workspace edits cannot change their anchor, even when a
        // local declaration shares the locator's path and name.
        if shard.request_owned() {
            return CarriedSourceLocations.record_location(
                shard,
                locator,
                fallback_symbol,
                record_kind,
                record_id,
            );
        }
        if let Locator::Source { path, .. } = locator
            && self.changed.touches(Path::new(path))
        {
            let previous = self.published.get(shard, record_kind, record_id);
            if previous.is_some_and(is_workspace_anchor) {
                // A workspace-bound Authored location keeps master's touched
                // path rule, including normalized dot spellings (#12435).
                self.unchanged.set(false);
            } else {
                let current = authored_anchor(
                    self.analyzer,
                    &shard.manifest.carried_sources,
                    locator,
                    fallback_symbol,
                );
                if current.as_ref() != previous {
                    self.unchanged.set(false);
                }
            }
        }
        self.published
            .record_location(shard, locator, fallback_symbol, record_kind, record_id)
    }
}

/// carried_source_anchor constructs exactly this zero range. A workspace
/// definition keeps the parser's range, including its one-based line numbers.
fn is_workspace_anchor(anchor: &SemanticModelAuthoredAnchor) -> bool {
    let range = &anchor.range;
    range.start_byte != 0 || range.end_byte != 0 || range.start_line != 0 || range.end_line != 0
}
