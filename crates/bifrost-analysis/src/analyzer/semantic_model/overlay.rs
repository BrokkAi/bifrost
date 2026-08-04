use std::collections::{BTreeMap, VecDeque};
use std::path::Path;

use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    ActiveSemanticModelShard, AsciiTransform, CaptureBinding, CaptureProjection, CaptureSource,
    CatalogPackSourceKind, Completeness, EmbeddedTypeFact, EmittedDeclaration, GeneratorRule,
    HierarchyFact, HierarchyKind, Locator, MemberFact, MemberKind, ReceiverFact, RelationFact,
    RelationKind, ResolvedActiveSemanticModels, RuleEmission, RuleTrigger,
    SemanticModelActivationStatus, SemanticModelMatchDisposition, Signature,
    StructuredTypeExpression, TemplateExpression, TemplateSignature, TemplateTypeRef, TypeFact,
    TypeKind, TypeParameterConstraint, TypeRef, Visibility,
};
use crate::analyzer::structural::{FileFacts, NormalizedKind, Role};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, Range};
use crate::hash::{HashMap, HashSet};

const MODEL_URI_BASE: &str = "bifrost-model://v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelOriginKind {
    WorkspaceSource,
    ExactGeneratedOutput,
    DependencySource,
    DependencyBinary,
    PrebuiltApiIndex,
    DeclarativeModel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelProof {
    AuthoredAnchor,
    ExactArtifact,
    PackFact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelCompleteness {
    Partial,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelSymbolKind {
    Class,
    Annotation,
    Delegate,
    Interface,
    Trait,
    Struct,
    Union,
    Enum,
    Record,
    Module,
    TypeAlias,
    Constructor,
    Method,
    Function,
    Field,
    Property,
    Constant,
    Static,
    Macro,
    Event,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelRange {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub end_line: usize,
}

impl From<Range> for SemanticModelRange {
    fn from(range: Range) -> Self {
        Self {
            start_byte: range.start_byte,
            end_byte: range.end_byte,
            start_line: range.start_line,
            end_line: range.end_line,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelAuthoredAnchor {
    pub path: String,
    pub symbol: String,
    pub range: SemanticModelRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelVirtualLocation {
    pub uri: String,
    pub range: SemanticModelRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticModelLocation {
    Authored(SemanticModelAuthoredAnchor),
    Model(SemanticModelVirtualLocation),
}

impl SemanticModelLocation {
    pub fn identity(&self) -> &str {
        match self {
            Self::Authored(anchor) => &anchor.path,
            Self::Model(location) => &location.uri,
        }
    }

    pub fn range(&self) -> &SemanticModelRange {
        match self {
            Self::Authored(anchor) => &anchor.range,
            Self::Model(location) => &location.range,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelActivationProvenance {
    pub status: String,
    pub reason: String,
    pub source_kind: String,
    pub source_id: String,
    pub matched_evidence: SemanticModelMatchedEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelMatchedCoordinate {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelMatchedEvidence {
    pub language: String,
    pub ecosystem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<SemanticModelMatchedCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<SemanticModelMatchedCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<SemanticModelMatchedCoordinate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelProvenance {
    pub active_model_set_hash: String,
    pub pack_digest: String,
    pub pack_id: String,
    pub pack_version: String,
    pub producer: String,
    pub producer_version: String,
    pub record_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub origin: SemanticModelOriginKind,
    pub activation: SemanticModelActivationProvenance,
    pub proof: SemanticModelProof,
    pub completeness: SemanticModelCompleteness,
    pub ambiguous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelSymbol {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    pub name: String,
    pub qualified_name: String,
    pub language: String,
    pub kind: SemanticModelSymbolKind,
    pub visibility: Visibility,
    #[serde(skip)]
    pub(crate) is_static: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip)]
    pub(crate) structured_signature: Option<Signature>,
    #[serde(skip)]
    pub(crate) has_explicit_type_terms: bool,
    #[serde(skip)]
    pub(crate) callable_shape: Option<String>,
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub type_parameter_constraints: Vec<TypeParameterConstraint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub underlying_type: Option<StructuredTypeExpression>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub embedded_types: Vec<EmbeddedTypeFact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<ReceiverFact>,
    #[serde(skip)]
    pub(crate) extension_receiver: Option<TypeRef>,
    #[serde(skip)]
    pub(crate) extension_receiver_constraints: Vec<TypeRef>,
    pub location: SemanticModelLocation,
    pub provenance: SemanticModelProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelRelation {
    pub id: String,
    pub kind: String,
    pub from: String,
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declaration_ordinal: Option<u32>,
    pub provenance: SemanticModelProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticModelOverlayDisposition {
    Empty,
    Unique,
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemanticModelOverlayBuildError {
    Cancelled,
    RetainedBytesExceeded,
    GoSurfaceTraversalExceeded,
}

#[derive(Debug)]
pub struct SemanticModelOverlayMatch<'a, T> {
    pub records: Vec<&'a T>,
    pub disposition: SemanticModelOverlayDisposition,
}

#[derive(Debug)]
pub struct SemanticModelOverlay {
    active_model_set_hash: String,
    symbols: Vec<SemanticModelSymbol>,
    relations: Vec<SemanticModelRelation>,
    symbols_by_id: HashMap<String, Vec<usize>>,
    symbols_by_name: HashMap<String, Vec<usize>>,
    symbols_by_uri: HashMap<String, Vec<usize>>,
    symbols_by_owner: HashMap<String, Vec<usize>>,
    relations_from: HashMap<String, Vec<usize>>,
    relations_to: HashMap<String, Vec<usize>>,
}

impl SemanticModelOverlay {
    pub(crate) fn build(
        analyzer: &dyn IAnalyzer,
        active: &ResolvedActiveSemanticModels,
        cancellation: &crate::CancellationToken,
        max_combined_retained_bytes: u64,
    ) -> Result<Self, SemanticModelOverlayBuildError> {
        let mut type_ids = Vec::new();
        let mut member_ids = Vec::new();
        let mut relation_ids = Vec::new();
        for shard in active.shards() {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            if let Some((types, members, relations)) = shard.shard.payload().declaration_facts() {
                type_ids.extend(types.iter().map(|record| record.id.clone()));
                member_ids.extend(members.iter().map(|record| record.id.clone()));
                relation_ids.extend(relations.iter().map(|record| record.id.clone()));
            }
        }
        type_ids.sort_unstable();
        type_ids.dedup();
        member_ids.sort_unstable();
        member_ids.dedup();
        relation_ids.sort_unstable();
        relation_ids.dedup();

        let mut symbols = Vec::new();
        let mut hierarchy_relations = Vec::new();
        let mut qualified_types = HashMap::default();
        for id in type_ids {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            let matched = active.types_with_id(&id);
            let ambiguous = matched.disposition == SemanticModelMatchDisposition::Conflict;
            for activated in matched.records {
                let symbol = type_symbol(
                    analyzer,
                    active,
                    activated.shard,
                    activated.record,
                    ambiguous,
                );
                if !ambiguous {
                    qualified_types.insert(symbol.id.clone(), symbol.qualified_name.clone());
                }
                hierarchy_relations.extend(activated.record.hierarchy.iter().map(|hierarchy| {
                    hierarchy_relation(
                        active,
                        activated.shard,
                        &activated.record.id,
                        hierarchy,
                        ambiguous,
                    )
                }));
                symbols.push(symbol);
            }
        }
        for id in member_ids {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            let matched = active.members_with_id(&id);
            let ambiguous = matched.disposition == SemanticModelMatchDisposition::Conflict;
            for activated in matched.records {
                symbols.push(member_symbol(
                    analyzer,
                    active,
                    activated.shard,
                    activated.record,
                    qualified_types
                        .get(&activated.record.owner)
                        .map(String::as_str),
                    ambiguous,
                ));
            }
        }
        let generated = generated_overlay_facts(analyzer, active, cancellation)?;
        symbols.extend(generated.symbols);
        mark_symbol_identity_conflicts(&mut symbols);
        augment_go_overlay_surface(&mut symbols, &mut hierarchy_relations, cancellation)?;
        mark_symbol_identity_conflicts(&mut symbols);
        symbols.sort_by(|left, right| {
            left.qualified_name
                .cmp(&right.qualified_name)
                .then_with(|| left.id.cmp(&right.id))
                .then_with(|| {
                    left.provenance
                        .pack_digest
                        .cmp(&right.provenance.pack_digest)
                })
        });

        let mut relations = hierarchy_relations;
        relations.extend(generated.relations);
        for id in relation_ids {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            let matched = active.relations_with_id(&id);
            let ambiguous = matched.disposition == SemanticModelMatchDisposition::Conflict;
            for activated in matched.records {
                relations.push(relation(
                    active,
                    activated.shard,
                    activated.record,
                    ambiguous,
                ));
            }
        }
        relations.sort_by(|left, right| {
            left.from
                .cmp(&right.from)
                .then_with(|| {
                    left.declaration_ordinal
                        .is_some()
                        .cmp(&right.declaration_ordinal.is_some())
                })
                .then_with(|| left.declaration_ordinal.cmp(&right.declaration_ordinal))
                .then_with(|| left.to.cmp(&right.to))
                .then_with(|| left.id.cmp(&right.id))
        });

        let mut overlay = Self {
            active_model_set_hash: active.active_model_set_hash().to_string(),
            symbols,
            relations,
            symbols_by_id: HashMap::default(),
            symbols_by_name: HashMap::default(),
            symbols_by_uri: HashMap::default(),
            symbols_by_owner: HashMap::default(),
            relations_from: HashMap::default(),
            relations_to: HashMap::default(),
        };
        overlay.rebuild_indexes(cancellation)?;
        if active
            .retained_bytes()
            .saturating_add(overlay.retained_bytes_lower_bound())
            > max_combined_retained_bytes
        {
            return Err(SemanticModelOverlayBuildError::RetainedBytesExceeded);
        }
        Ok(overlay)
    }

    pub fn active_model_set_hash(&self) -> &str {
        &self.active_model_set_hash
    }

    pub fn symbols(&self) -> &[SemanticModelSymbol] {
        &self.symbols
    }

    pub fn relations(&self) -> &[SemanticModelRelation] {
        &self.relations
    }

    pub fn symbols_with_id(&self, id: &str) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        self.symbol_match(self.symbols_by_id.get(id))
    }

    pub fn symbols_named(&self, name: &str) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        self.symbol_match(self.symbols_by_name.get(name))
    }

    pub fn symbols_at_uri(&self, uri: &str) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        self.symbol_match(self.symbols_by_uri.get(uri))
    }

    pub fn members_of(&self, owner_id: &str) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        self.symbol_match(self.symbols_by_owner.get(owner_id))
    }

    pub fn search<'a>(
        &'a self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
    ) -> Vec<&'a SemanticModelSymbol> {
        self.search_with_limit(patterns, usize::MAX, None).0
    }

    pub fn search_with_limit<'a>(
        &'a self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
        limit: usize,
        cancellation: Option<&crate::CancellationToken>,
    ) -> (Vec<&'a SemanticModelSymbol>, usize, bool) {
        self.search_with_limit_filter(patterns, limit, cancellation, |_| true)
    }

    pub fn search_with_limit_filter<'a>(
        &'a self,
        patterns: &crate::analyzer::SearchSymbolPatternBatch,
        limit: usize,
        cancellation: Option<&crate::CancellationToken>,
        include: impl Fn(&SemanticModelSymbol) -> bool,
    ) -> (Vec<&'a SemanticModelSymbol>, usize, bool) {
        let mut records = Vec::new();
        let mut total = 0usize;
        for symbol in &self.symbols {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return (records, total, false);
            }
            let matched = patterns.is_match(&symbol.name)
                || patterns.is_match(&symbol.qualified_name)
                || symbol.aliases.iter().any(|alias| patterns.is_match(alias));
            if matched && symbol.externally_visible() && include(symbol) {
                total = total.saturating_add(1);
                if records.len() < limit {
                    records.push(symbol);
                }
            }
        }
        (records, total, true)
    }

    pub fn relations_from(&self, id: &str) -> SemanticModelOverlayMatch<'_, SemanticModelRelation> {
        self.relation_match(self.relations_from.get(id))
    }

    pub fn relations_to(&self, id: &str) -> SemanticModelOverlayMatch<'_, SemanticModelRelation> {
        self.relation_match(self.relations_to.get(id))
    }

    /// Resolve a model type's transitive ancestors without materializing
    /// universal-root edges for every declaration in the overlay.
    pub fn ancestors_of(
        &self,
        symbol: &SemanticModelSymbol,
    ) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        let mut records = Vec::new();
        let mut queue = VecDeque::from([symbol]);
        let mut seen = HashSet::from_iter([symbol.id.as_str()]);
        let mut conflict = symbol.provenance.ambiguous;
        while let Some(current) = queue.pop_front() {
            let direct = self.direct_ancestors_of(current);
            conflict |= direct.disposition == SemanticModelOverlayDisposition::Conflict;
            for ancestor in direct.records {
                if seen.insert(&ancestor.id) {
                    records.push(ancestor);
                    queue.push_back(ancestor);
                }
            }
        }
        let disposition = if conflict {
            SemanticModelOverlayDisposition::Conflict
        } else if records.is_empty() {
            SemanticModelOverlayDisposition::Empty
        } else {
            SemanticModelOverlayDisposition::Unique
        };
        SemanticModelOverlayMatch {
            records,
            disposition,
        }
    }

    /// Return the active universal root for Java or Scala when it is uniquely
    /// present. The name indexes are already retained by the overlay, so this
    /// lazy lookup is cheaper than another per-type cache or authored edge.
    pub fn universal_root_for_language(
        &self,
        language: &str,
    ) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        let root = match language {
            "java" => "java.lang.Object",
            "scala" => "scala.Any",
            _ => return self.symbol_match(None),
        };
        self.symbols_named(root)
    }

    fn direct_ancestors_of(
        &self,
        symbol: &SemanticModelSymbol,
    ) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        let hierarchy = self
            .relations_from(&symbol.id)
            .records
            .into_iter()
            .filter(|relation| {
                matches!(
                    relation.kind.as_str(),
                    "extends" | "implements" | "uses_trait" | "mixin_include" | "mixin_prepend"
                )
            })
            .collect::<Vec<_>>();
        let has_class_parent = hierarchy.iter().any(|relation| relation.kind == "extends");
        let mut records = Vec::new();
        let mut conflict = hierarchy
            .iter()
            .any(|relation| relation.provenance.ambiguous);
        for relation in hierarchy {
            let mut matched = self.symbols_with_id(&relation.to);
            if matched.records.is_empty() {
                matched = self.symbols_named(&relation.to);
            }
            conflict |= matched.disposition == SemanticModelOverlayDisposition::Conflict;
            records.extend(matched.records);
        }
        if !has_class_parent
            && universal_root_name(symbol).is_some_and(|root| root != symbol.qualified_name)
        {
            let root = self.universal_root_for_language(&symbol.language);
            conflict |= root.disposition == SemanticModelOverlayDisposition::Conflict;
            records.extend(root.records);
        }
        let mut seen = HashSet::default();
        records.retain(|record| seen.insert(record.id.as_str()));
        SemanticModelOverlayMatch {
            disposition: if conflict {
                SemanticModelOverlayDisposition::Conflict
            } else if records.is_empty() {
                SemanticModelOverlayDisposition::Empty
            } else {
                SemanticModelOverlayDisposition::Unique
            },
            records,
        }
    }

    fn rebuild_indexes(
        &mut self,
        cancellation: &crate::CancellationToken,
    ) -> Result<(), SemanticModelOverlayBuildError> {
        for (index, symbol) in self.symbols.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            push_unique_posting(&mut self.symbols_by_id, &symbol.id, index);
            push_unique_posting(&mut self.symbols_by_name, &symbol.name, index);
            push_unique_posting(&mut self.symbols_by_name, &symbol.qualified_name, index);
            for alias in &symbol.aliases {
                push_unique_posting(&mut self.symbols_by_name, alias, index);
            }
            if let Some(owner) = &symbol.owner_id {
                self.symbols_by_owner
                    .entry(owner.clone())
                    .or_default()
                    .push(index);
            }
            if let SemanticModelLocation::Model(location) = &symbol.location {
                self.symbols_by_uri
                    .entry(location.uri.clone())
                    .or_default()
                    .push(index);
            }
        }
        for (index, relation) in self.relations.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            self.relations_from
                .entry(relation.from.clone())
                .or_default()
                .push(index);
            self.relations_to
                .entry(relation.to.clone())
                .or_default()
                .push(index);
        }
        Ok(())
    }

    fn retained_bytes_lower_bound(&self) -> u64 {
        let symbol_bytes = self
            .symbols
            .iter()
            .map(|symbol| {
                std::mem::size_of::<SemanticModelSymbol>()
                    .saturating_add(symbol.id.capacity())
                    .saturating_add(symbol.owner_id.as_ref().map_or(0, String::capacity))
                    .saturating_add(symbol.name.capacity())
                    .saturating_add(symbol.qualified_name.capacity())
                    .saturating_add(symbol.language.capacity())
                    .saturating_add(symbol.signature.as_ref().map_or(0, String::capacity))
                    .saturating_add(symbol.aliases.iter().map(String::capacity).sum::<usize>())
                    .saturating_add(match &symbol.location {
                        SemanticModelLocation::Authored(anchor) => anchor
                            .path
                            .capacity()
                            .saturating_add(anchor.symbol.capacity()),
                        SemanticModelLocation::Model(location) => location.uri.capacity(),
                    })
                    .saturating_add(symbol.provenance.retained_string_bytes())
            })
            .sum::<usize>();
        let relation_bytes = self
            .relations
            .iter()
            .map(|relation| {
                std::mem::size_of::<SemanticModelRelation>()
                    .saturating_add(relation.id.capacity())
                    .saturating_add(relation.kind.capacity())
                    .saturating_add(relation.from.capacity())
                    .saturating_add(relation.to.capacity())
                    .saturating_add(relation.provenance.retained_string_bytes())
            })
            .sum::<usize>();
        let mut index_bytes = 0usize;
        for map in [
            &self.symbols_by_id,
            &self.symbols_by_name,
            &self.symbols_by_uri,
            &self.symbols_by_owner,
            &self.relations_from,
            &self.relations_to,
        ] {
            for (key, posting) in map {
                index_bytes = index_bytes.saturating_add(key.capacity()).saturating_add(
                    posting
                        .capacity()
                        .saturating_mul(std::mem::size_of::<usize>()),
                );
            }
        }
        u64::try_from(
            std::mem::size_of::<Self>()
                .saturating_add(symbol_bytes)
                .saturating_add(relation_bytes)
                .saturating_add(index_bytes),
        )
        .unwrap_or(u64::MAX)
    }

    fn symbol_match(
        &self,
        posting: Option<&Vec<usize>>,
    ) -> SemanticModelOverlayMatch<'_, SemanticModelSymbol> {
        let records = posting
            .into_iter()
            .flatten()
            .map(|index| &self.symbols[*index])
            .collect::<Vec<_>>();
        SemanticModelOverlayMatch {
            disposition: disposition(&records, |record| record.provenance.ambiguous),
            records,
        }
    }

    fn relation_match(
        &self,
        posting: Option<&Vec<usize>>,
    ) -> SemanticModelOverlayMatch<'_, SemanticModelRelation> {
        let records = posting
            .into_iter()
            .flatten()
            .map(|index| &self.relations[*index])
            .collect::<Vec<_>>();
        SemanticModelOverlayMatch {
            disposition: if records.is_empty() {
                SemanticModelOverlayDisposition::Empty
            } else if records.iter().any(|record| record.provenance.ambiguous) {
                SemanticModelOverlayDisposition::Conflict
            } else {
                SemanticModelOverlayDisposition::Unique
            },
            records,
        }
    }
}

impl SemanticModelSymbol {
    pub fn externally_visible(&self) -> bool {
        matches!(
            self.visibility,
            Visibility::Public | Visibility::Protected | Visibility::ProtectedInternal
        )
    }
}

fn universal_root_name(symbol: &SemanticModelSymbol) -> Option<&'static str> {
    if symbol.owner_id.is_some() {
        return None;
    }
    match symbol.language.as_str() {
        "java"
            if matches!(
                symbol.kind,
                SemanticModelSymbolKind::Class
                    | SemanticModelSymbolKind::Enum
                    | SemanticModelSymbolKind::Record
            ) =>
        {
            Some("java.lang.Object")
        }
        "scala"
            if matches!(
                symbol.kind,
                SemanticModelSymbolKind::Class
                    | SemanticModelSymbolKind::Interface
                    | SemanticModelSymbolKind::Trait
                    | SemanticModelSymbolKind::Enum
                    | SemanticModelSymbolKind::Record
                    | SemanticModelSymbolKind::Module
            ) =>
        {
            Some("scala.Any")
        }
        _ => None,
    }
}

impl SemanticModelProvenance {
    fn retained_string_bytes(&self) -> usize {
        let evidence = &self.activation.matched_evidence;
        self.active_model_set_hash
            .capacity()
            .saturating_add(self.pack_digest.capacity())
            .saturating_add(self.pack_id.capacity())
            .saturating_add(self.pack_version.capacity())
            .saturating_add(self.producer.capacity())
            .saturating_add(self.producer_version.capacity())
            .saturating_add(self.record_id.capacity())
            .saturating_add(self.rule_id.as_ref().map_or(0, String::capacity))
            .saturating_add(self.activation.status.capacity())
            .saturating_add(self.activation.reason.capacity())
            .saturating_add(self.activation.source_kind.capacity())
            .saturating_add(self.activation.source_id.capacity())
            .saturating_add(evidence.language.capacity())
            .saturating_add(evidence.ecosystem.capacity())
            .saturating_add(coordinate_string_bytes(evidence.package.as_ref()))
            .saturating_add(coordinate_string_bytes(evidence.module.as_ref()))
            .saturating_add(coordinate_string_bytes(evidence.toolchain.as_ref()))
            .saturating_add(evidence.target.as_ref().map_or(0, String::capacity))
            .saturating_add(evidence.configuration.as_ref().map_or(0, String::capacity))
            .saturating_add(
                evidence
                    .artifact_sha256
                    .as_ref()
                    .map_or(0, String::capacity),
            )
    }
}

fn coordinate_string_bytes(coordinate: Option<&SemanticModelMatchedCoordinate>) -> usize {
    coordinate.map_or(0, |coordinate| {
        coordinate
            .name
            .capacity()
            .saturating_add(coordinate.version.as_ref().map_or(0, String::capacity))
    })
}

fn disposition<T>(
    records: &[&T],
    ambiguous: impl Fn(&T) -> bool,
) -> SemanticModelOverlayDisposition {
    if records.is_empty() {
        SemanticModelOverlayDisposition::Empty
    } else if records.len() == 1 && !ambiguous(records[0]) {
        SemanticModelOverlayDisposition::Unique
    } else {
        SemanticModelOverlayDisposition::Conflict
    }
}

fn push_unique_posting(postings: &mut HashMap<String, Vec<usize>>, key: &str, index: usize) {
    let posting = postings.entry(key.to_string()).or_default();
    if posting.last() != Some(&index) {
        posting.push(index);
    }
}

fn mark_symbol_identity_conflicts(symbols: &mut [SemanticModelSymbol]) {
    let mut identities: HashMap<String, Vec<usize>> = HashMap::default();
    for (index, symbol) in symbols.iter().enumerate() {
        identities.entry(symbol.id.clone()).or_default().push(index);
    }
    for posting in identities.values().filter(|posting| posting.len() > 1) {
        for &index in posting {
            symbols[index].provenance.ambiguous = true;
        }
    }
}

fn augment_go_overlay_surface(
    symbols: &mut Vec<SemanticModelSymbol>,
    relations: &mut Vec<SemanticModelRelation>,
    cancellation: &crate::CancellationToken,
) -> Result<(), SemanticModelOverlayBuildError> {
    const MAX_GO_OVERLAY_TRAVERSAL_STEPS: usize = 2_000_000;

    let mut qualified_counts = HashMap::<String, usize>::default();
    for symbol in symbols.iter().filter(|symbol| symbol.language == "go") {
        *qualified_counts
            .entry(symbol.qualified_name.clone())
            .or_default() += 1;
    }
    let type_indices = symbols
        .iter()
        .enumerate()
        .filter(|(_, symbol)| {
            symbol.language == "go"
                && symbol.owner_id.is_none()
                && symbol.externally_visible()
                && !symbol.provenance.ambiguous
                && qualified_counts.get(&symbol.qualified_name) == Some(&1)
        })
        .map(|(index, symbol)| (symbol.id.clone(), index))
        .collect::<HashMap<_, _>>();
    let qualified_type_ids = type_indices
        .iter()
        .map(|(id, index)| (symbols[*index].qualified_name.clone(), id.clone()))
        .collect::<HashMap<_, _>>();
    let direct_members = symbols
        .iter()
        .enumerate()
        .filter_map(|(index, symbol)| symbol.owner_id.as_ref().map(|owner| (owner.clone(), index)))
        .fold(
            HashMap::<String, Vec<usize>>::default(),
            |mut grouped, (owner, index)| {
                grouped.entry(owner).or_default().push(index);
                grouped
            },
        );

    let mut promoted = Vec::new();
    let mut traversal_steps = 0usize;
    for owner in type_indices.values().map(|index| &symbols[*index]) {
        if cancellation.is_cancelled() {
            return Err(SemanticModelOverlayBuildError::Cancelled);
        }
        let mut resolved_names = direct_members
            .get(&owner.id)
            .into_iter()
            .flatten()
            .map(|index| symbols[*index].name.clone())
            .collect::<HashSet<_>>();
        let mut current = HashMap::<(String, bool), u8>::default();
        for embedded in &owner.embedded_types {
            if let Some(target) = overlay_declared_type_id(&embedded.target, &qualified_type_ids) {
                current
                    .entry((target, embedded.pointer))
                    .and_modify(|count| *count = 2)
                    .or_insert(1);
            }
        }
        let mut seen_depth = HashMap::<(String, bool), usize>::default();
        seen_depth.insert((owner.id.clone(), false), 0);
        let mut depth = 1usize;
        while !current.is_empty() {
            let mut candidates = HashMap::<String, (Option<(usize, bool)>, u8)>::default();
            let mut next = HashMap::<(String, bool), u8>::default();
            for ((type_id, pointer_available), multiplicity) in current {
                traversal_steps = traversal_steps.saturating_add(1);
                if traversal_steps > MAX_GO_OVERLAY_TRAVERSAL_STEPS {
                    return Err(SemanticModelOverlayBuildError::GoSurfaceTraversalExceeded);
                }
                if let Some(member_indices) = direct_members.get(&type_id) {
                    for &member_index in member_indices {
                        let member = &symbols[member_index];
                        if !member.externally_visible()
                            || member.provenance.ambiguous
                            || resolved_names.contains(&member.name)
                        {
                            continue;
                        }
                        let entry = candidates.entry(member.name.clone()).or_insert((None, 0));
                        entry.1 = entry.1.saturating_add(multiplicity).min(2);
                        if entry.1 == 1 {
                            entry.0 = Some((member_index, pointer_available));
                        } else {
                            entry.0 = None;
                        }
                    }
                }
                let Some(&embedded_index) = type_indices.get(&type_id) else {
                    continue;
                };
                for embedded in &symbols[embedded_index].embedded_types {
                    let Some(target) =
                        overlay_declared_type_id(&embedded.target, &qualified_type_ids)
                    else {
                        continue;
                    };
                    let state = (target, pointer_available || embedded.pointer);
                    match seen_depth.get(&state).copied() {
                        Some(previous) if previous < depth + 1 => continue,
                        Some(_) => {}
                        None => {
                            seen_depth.insert(state.clone(), depth + 1);
                        }
                    }
                    next.entry(state)
                        .and_modify(|count| *count = count.saturating_add(multiplicity).min(2))
                        .or_insert(multiplicity);
                }
            }
            let mut candidate_names = candidates.into_iter().collect::<Vec<_>>();
            candidate_names.sort_by(|left, right| left.0.cmp(&right.0));
            for (name, (member, multiplicity)) in candidate_names {
                resolved_names.insert(name);
                if multiplicity != 1 {
                    continue;
                }
                let (member_index, pointer_available) = member.expect("unique member has an index");
                let mut member = symbols[member_index].clone();
                member.id = format!("go-promoted:{}:{}", owner.id, member.id);
                member.owner_id = Some(owner.id.clone());
                member.qualified_name = format!("{}.{}", owner.qualified_name, member.name);
                if member.receiver.is_some_and(|receiver| receiver.pointer) && pointer_available {
                    member.receiver = Some(ReceiverFact { pointer: false });
                }
                promoted.push(member);
            }
            current = next;
            depth += 1;
        }
    }
    symbols.extend(promoted);

    let methods_by_owner = symbols
        .iter()
        .filter(|symbol| {
            symbol.language == "go"
                && symbol.kind == SemanticModelSymbolKind::Method
                && symbol.externally_visible()
                && !symbol.provenance.ambiguous
        })
        .filter_map(|symbol| {
            symbol
                .owner_id
                .as_ref()
                .map(|owner| (owner.clone(), symbol))
        })
        .fold(
            HashMap::<String, Vec<&SemanticModelSymbol>>::default(),
            |mut grouped, (owner, symbol)| {
                grouped.entry(owner).or_default().push(symbol);
                grouped
            },
        );
    let interfaces = type_indices
        .values()
        .map(|index| &symbols[*index])
        .filter(|symbol| {
            symbol.kind == SemanticModelSymbolKind::Interface && !symbol.has_explicit_type_terms
        })
        .filter_map(|symbol| {
            let methods = methods_by_owner.get(&symbol.id)?;
            (!methods.is_empty()).then_some((symbol, methods.as_slice()))
        })
        .collect::<Vec<_>>();
    let candidates = type_indices
        .values()
        .map(|index| &symbols[*index])
        .filter(|symbol| {
            !matches!(
                symbol.kind,
                SemanticModelSymbolKind::Module | SemanticModelSymbolKind::TypeAlias
            )
        })
        .collect::<Vec<_>>();
    if interfaces.len().saturating_mul(candidates.len()) > MAX_GO_OVERLAY_TRAVERSAL_STEPS {
        return Err(SemanticModelOverlayBuildError::GoSurfaceTraversalExceeded);
    }
    let existing = relations
        .iter()
        .map(|relation| {
            (
                relation.from.clone(),
                relation.to.clone(),
                relation.kind.clone(),
            )
        })
        .collect::<HashSet<_>>();
    for candidate in candidates {
        let candidate_methods = methods_by_owner
            .get(&candidate.id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for (interface, required_methods) in &interfaces {
            if candidate.id == interface.id
                || existing.contains(&(
                    candidate.id.clone(),
                    interface.id.clone(),
                    "implements".to_owned(),
                ))
                || !required_methods.iter().all(|required| {
                    candidate_methods.iter().any(|method| {
                        !method.receiver.is_some_and(|receiver| receiver.pointer)
                            && overlay_go_method_matches(method, required)
                    })
                })
            {
                continue;
            }
            let id = format!("hierarchy:{}:implements:{}", candidate.id, interface.id);
            let mut provenance = candidate.provenance.clone();
            provenance.record_id = id.clone();
            relations.push(SemanticModelRelation {
                id,
                kind: "implements".to_owned(),
                from: candidate.id.clone(),
                to: interface.id.clone(),
                declaration_ordinal: None,
                provenance,
            });
        }
    }
    Ok(())
}

fn overlay_declared_type_id(
    reference: &TypeRef,
    qualified_type_ids: &HashMap<String, String>,
) -> Option<String> {
    match reference {
        TypeRef::Declared { id, .. } => Some(id.clone()),
        TypeRef::Named { name, .. } => qualified_type_ids.get(name).cloned(),
        TypeRef::Pointer { element } => overlay_declared_type_id(element, qualified_type_ids),
        _ => None,
    }
}

fn overlay_go_method_matches(
    candidate: &SemanticModelSymbol,
    required: &SemanticModelSymbol,
) -> bool {
    if candidate.name != required.name {
        return false;
    }
    match (
        candidate.structured_signature.as_ref(),
        required.structured_signature.as_ref(),
    ) {
        (Some(candidate), Some(required)) => {
            candidate.type_parameters.len() == required.type_parameters.len()
                && candidate.parameters.len() == required.parameters.len()
                && candidate.parameters.iter().zip(&required.parameters).all(
                    |(candidate, required)| {
                        candidate.r#type == required.r#type
                            && candidate.variadic == required.variadic
                    },
                )
                && candidate.returns == required.returns
        }
        _ => false,
    }
}

pub const SEMANTIC_MODEL_MATCH_EXPLANATION_FORMAT: &str =
    "bifrost_semantic_model_match_explanation/v1";
pub const SEMANTIC_MODEL_EMISSION_PREVIEW_FORMAT: &str =
    "bifrost_semantic_model_emission_preview/v1";
pub const SEMANTIC_MODEL_UNMAPPED_SCAN_FORMAT: &str = "bifrost_semantic_model_unmapped_scan/v1";
pub const SEMANTIC_MODEL_CONFORMANCE_FORMAT: &str = "bifrost_semantic_model_conformance/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelSite {
    pub path: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelEmittedAlias {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelRuleExplanation {
    pub pack_id: String,
    pub pack_version: String,
    pub shard_id: String,
    pub rule_id: String,
    pub source_kind: String,
    pub source_id: String,
    pub shadowing: String,
    pub matched: bool,
    pub activation_evidence: SemanticModelMatchedEvidence,
    pub captures: BTreeMap<String, String>,
    pub emitted_symbols: Vec<SemanticModelSymbol>,
    pub emitted_relations: Vec<SemanticModelRelation>,
    pub emitted_aliases: Vec<SemanticModelEmittedAlias>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_failed_predicate: Option<SemanticModelPredicateFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelMatchExplanationReport {
    pub format: &'static str,
    pub site: SemanticModelSite,
    pub complete: bool,
    pub explanations: Vec<SemanticModelRuleExplanation>,
    pub diagnostics: Vec<String>,
}

pub fn explain_semantic_model_site(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    site: SemanticModelSite,
    rule_id: Option<&str>,
    cancellation: &crate::CancellationToken,
    max_explanations: usize,
) -> SemanticModelMatchExplanationReport {
    let mut report = SemanticModelMatchExplanationReport {
        format: SEMANTIC_MODEL_MATCH_EXPLANATION_FORMAT,
        site: site.clone(),
        complete: true,
        explanations: Vec::new(),
        diagnostics: Vec::new(),
    };
    let mut rule_ids = active
        .shards()
        .iter()
        .flat_map(|shard| {
            shard
                .shard
                .payload()
                .generator_rules()
                .into_iter()
                .flatten()
                .map(|rule| rule.id.clone())
        })
        .filter(|id| rule_id.is_none_or(|requested| requested == id))
        .collect::<Vec<_>>();
    rule_ids.sort_unstable();
    rule_ids.dedup();
    if rule_ids.is_empty() {
        report
            .diagnostics
            .push("no active generator rule matches the requested rule id".to_owned());
        return report;
    }

    for rule_id in rule_ids {
        if cancellation.is_cancelled() {
            report.complete = false;
            report.diagnostics.push("operation cancelled".to_owned());
            break;
        }
        if report.explanations.len() >= max_explanations {
            report.complete = false;
            report
                .diagnostics
                .push("explanation limit exceeded".to_owned());
            break;
        }
        let matched_rule = active.rules_with_id(&rule_id);
        let shadowing = match matched_rule.disposition {
            SemanticModelMatchDisposition::Empty => "absent",
            SemanticModelMatchDisposition::Unique => "unique",
            SemanticModelMatchDisposition::Conflict => "conflict",
        };
        for activated in matched_rule.records {
            if report.explanations.len() >= max_explanations {
                report.complete = false;
                report
                    .diagnostics
                    .push("explanation limit exceeded".to_owned());
                break;
            }
            let mut explanation = SemanticModelRuleExplanation {
                pack_id: activated.shard.manifest.pack_id.clone(),
                pack_version: activated.shard.manifest.version.clone(),
                shard_id: activated.shard.shard.shard_id.clone(),
                rule_id: activated.record.id.clone(),
                source_kind: source_kind(activated.shard.source_kind).to_owned(),
                source_id: activated.shard.source_id.clone(),
                shadowing: shadowing.to_owned(),
                matched: false,
                activation_evidence: matched_evidence(&activated.shard.matched_evidence),
                captures: BTreeMap::new(),
                emitted_symbols: Vec::new(),
                emitted_relations: Vec::new(),
                emitted_aliases: Vec::new(),
                first_failed_predicate: None,
            };
            if matched_rule.disposition == SemanticModelMatchDisposition::Conflict {
                explanation.first_failed_predicate = Some(SemanticModelPredicateFailure {
                    code: "rule.shadowed".to_owned(),
                    message: "equal-precedence active rules conflict, so production emits neither"
                        .to_owned(),
                });
                report.explanations.push(explanation);
                continue;
            }
            evaluate_explanation_at_site(
                analyzer,
                active,
                activated.shard,
                activated.record,
                &site,
                &mut explanation,
            );
            report.explanations.push(explanation);
        }
    }
    report
}

fn evaluate_explanation_at_site(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    rule: &GeneratorRule,
    site: &SemanticModelSite,
    explanation: &mut SemanticModelRuleExplanation,
) {
    let path = Path::new(&site.path);
    let provider_file = analyzer
        .structural_search_providers()
        .into_iter()
        .filter(|provider| provider.structural_language().config_label() == shard.manifest.language)
        .find_map(|provider| {
            provider
                .structural_files()
                .into_iter()
                .find(|file| file.rel_path() == path)
                .map(|file| (provider, file))
        });
    let Some((provider, file)) = provider_file else {
        explanation.first_failed_predicate = Some(SemanticModelPredicateFailure {
            code: "site.not_indexed".to_owned(),
            message: "the requested path is not indexed for the rule language".to_owned(),
        });
        return;
    };
    let Some(facts) = provider.structural_facts(&file) else {
        explanation.first_failed_predicate = Some(SemanticModelPredicateFailure {
            code: "site.no_structural_facts".to_owned(),
            message: "the production structural provider has no facts for this file".to_owned(),
        });
        return;
    };
    let mut nodes = facts
        .nodes()
        .iter()
        .enumerate()
        .filter(|(_, node)| node.range.start_line <= site.line && node.range.end_line >= site.line)
        .collect::<Vec<_>>();
    nodes.sort_by_key(|(_, node)| node.range.end_byte.saturating_sub(node.range.start_byte));
    if nodes.is_empty() {
        explanation.first_failed_predicate = Some(SemanticModelPredicateFailure {
            code: "site.no_node".to_owned(),
            message: "the requested line has no normalized structural node".to_owned(),
        });
        return;
    }
    let mut first_failure = None;
    for (node_index, node) in nodes {
        let node_id = u32::try_from(node_index).expect("structural fact IDs fit u32");
        let enclosing = analyzer.enclosing_code_unit(&file, &node.range);
        match evaluate_rule_at_node(analyzer, rule, &facts, node_id, &file, enclosing.as_ref()) {
            Ok(matches) if !matches.is_empty() => {
                explanation.matched = true;
                explanation.captures = matches[0]
                    .iter()
                    .map(|(name, value)| (name.clone(), value.value.clone()))
                    .collect();
                let mut aliases = Vec::new();
                for captures in &matches {
                    emit_rule_match(
                        active,
                        shard,
                        rule,
                        captures,
                        &mut explanation.emitted_symbols,
                        &mut explanation.emitted_relations,
                        &mut aliases,
                    );
                }
                explanation.emitted_aliases = aliases
                    .into_iter()
                    .map(|(from, to)| SemanticModelEmittedAlias { from, to })
                    .collect();
                return;
            }
            Ok(_) => {}
            Err(failure) if first_failure.is_none() => first_failure = Some(failure),
            Err(_) => {}
        }
    }
    explanation.first_failed_predicate = first_failure;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelEmissionPreview {
    pub format: &'static str,
    pub complete: bool,
    pub pack_id: Option<String>,
    pub rule_id: String,
    pub shadowing: String,
    pub captures: BTreeMap<String, String>,
    pub emitted_symbols: Vec<SemanticModelSymbol>,
    pub emitted_relations: Vec<SemanticModelRelation>,
    pub emitted_aliases: Vec<SemanticModelEmittedAlias>,
    pub diagnostics: Vec<String>,
}

pub fn preview_semantic_model_emissions(
    active: &ResolvedActiveSemanticModels,
    rule_id: &str,
    captures: &BTreeMap<String, String>,
) -> SemanticModelEmissionPreview {
    let matched = active.rules_with_id(rule_id);
    let shadowing = match matched.disposition {
        SemanticModelMatchDisposition::Empty => "absent",
        SemanticModelMatchDisposition::Unique => "unique",
        SemanticModelMatchDisposition::Conflict => "conflict",
    };
    let mut report = SemanticModelEmissionPreview {
        format: SEMANTIC_MODEL_EMISSION_PREVIEW_FORMAT,
        complete: matched.disposition == SemanticModelMatchDisposition::Unique,
        pack_id: None,
        rule_id: rule_id.to_owned(),
        shadowing: shadowing.to_owned(),
        captures: captures.clone(),
        emitted_symbols: Vec::new(),
        emitted_relations: Vec::new(),
        emitted_aliases: Vec::new(),
        diagnostics: Vec::new(),
    };
    let [activated] = matched.records.as_slice() else {
        report.diagnostics.push(
            match matched.disposition {
                SemanticModelMatchDisposition::Empty => "the active model set has no such rule",
                SemanticModelMatchDisposition::Conflict => {
                    "equal-precedence active rules conflict, so production emits neither"
                }
                SemanticModelMatchDisposition::Unique => unreachable!(),
            }
            .to_owned(),
        );
        return report;
    };
    report.pack_id = Some(activated.shard.manifest.pack_id.clone());
    let missing_captures = activated
        .record
        .captures
        .iter()
        .filter(|capture| {
            capture.cardinality == super::CaptureCardinality::One
                && !captures.contains_key(&capture.name)
        })
        .map(|capture| capture.name.clone())
        .collect::<Vec<_>>();
    if !missing_captures.is_empty() {
        report.complete = false;
        report.diagnostics.push(format!(
            "required captures are missing: {missing_captures:?}"
        ));
        return report;
    }
    let captures = captures
        .iter()
        .map(|(name, value)| {
            (
                name.clone(),
                CapturedValue {
                    value: value.clone(),
                    anchor: None,
                },
            )
        })
        .collect::<HashMap<_, _>>();
    let mut aliases = Vec::new();
    emit_rule_match(
        active,
        activated.shard,
        activated.record,
        &captures,
        &mut report.emitted_symbols,
        &mut report.emitted_relations,
        &mut aliases,
    );
    report.emitted_aliases = aliases
        .into_iter()
        .map(|(from, to)| SemanticModelEmittedAlias { from, to })
        .collect();
    report
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticModelGeneratorSiteKind {
    ModelEligibleGenerator,
    InspectableSourceMacro,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelGeneratorSelector {
    pub language: String,
    pub trigger: RuleTrigger,
    pub site_kind: SemanticModelGeneratorSiteKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelUnmappedScanLimits {
    pub max_files: usize,
    pub max_nodes: usize,
    pub max_sites: usize,
}

impl Default for SemanticModelUnmappedScanLimits {
    fn default() -> Self {
        Self {
            max_files: 1_024,
            max_nodes: 1_000_000,
            max_sites: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelUnmappedSite {
    pub path: String,
    pub line: usize,
    pub name: Option<String>,
    pub site_kind: SemanticModelGeneratorSiteKind,
    pub requested_trigger: RuleTrigger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelUnmappedScanReport {
    pub format: &'static str,
    pub complete: bool,
    pub scanned_files: usize,
    pub scanned_nodes: usize,
    pub sites: Vec<SemanticModelUnmappedSite>,
    pub diagnostics: Vec<String>,
}

pub fn scan_unmapped_semantic_model_sites(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    selectors: &[SemanticModelGeneratorSelector],
    limits: SemanticModelUnmappedScanLimits,
    cancellation: &crate::CancellationToken,
) -> SemanticModelUnmappedScanReport {
    let mut report = SemanticModelUnmappedScanReport {
        format: SEMANTIC_MODEL_UNMAPPED_SCAN_FORMAT,
        complete: true,
        scanned_files: 0,
        scanned_nodes: 0,
        sites: Vec::new(),
        diagnostics: Vec::new(),
    };
    let active_rules = unique_active_rules(active);
    let provider_files = analyzer
        .structural_search_providers()
        .into_iter()
        .map(|provider| {
            let mut files = provider.structural_files();
            files.sort();
            files.dedup();
            (provider, files)
        })
        .collect::<Vec<_>>();
    for selector in selectors {
        for (provider, files) in provider_files.iter().filter(|(provider, _)| {
            provider.structural_language().config_label() == selector.language
        }) {
            for file in files {
                if cancellation.is_cancelled() {
                    report.complete = false;
                    report.diagnostics.push("operation cancelled".to_owned());
                    return report;
                }
                if report.scanned_files >= limits.max_files {
                    report.complete = false;
                    report.diagnostics.push("file limit exceeded".to_owned());
                    return report;
                }
                report.scanned_files += 1;
                let Some(facts) = provider.structural_facts(file) else {
                    continue;
                };
                for (node_index, node) in facts.nodes().iter().enumerate() {
                    if report.scanned_nodes >= limits.max_nodes {
                        report.complete = false;
                        report.diagnostics.push("node limit exceeded".to_owned());
                        return report;
                    }
                    report.scanned_nodes += 1;
                    let node_id = u32::try_from(node_index).expect("structural fact IDs fit u32");
                    if !rule_trigger_matches(analyzer, file, &selector.trigger, &facts, node_id) {
                        continue;
                    }
                    let enclosing = analyzer.enclosing_code_unit(file, &node.range);
                    let modeled = active_rules.iter().any(|(shard, rule)| {
                        shard.manifest.language == selector.language
                            && evaluate_rule_at_node(
                                analyzer,
                                rule,
                                &facts,
                                node_id,
                                file,
                                enclosing.as_ref(),
                            )
                            .is_ok_and(|matches| !matches.is_empty())
                    });
                    if modeled {
                        continue;
                    }
                    if report.sites.len() >= limits.max_sites {
                        report.complete = false;
                        report.diagnostics.push("site limit exceeded".to_owned());
                        return report;
                    }
                    report.sites.push(SemanticModelUnmappedSite {
                        path: file.rel_path().to_string_lossy().replace('\\', "/"),
                        line: node.range.start_line,
                        name: node.name.map(|name| name.text(facts.source()).to_owned()),
                        site_kind: selector.site_kind,
                        requested_trigger: selector.trigger.clone(),
                    });
                }
            }
        }
    }
    report.sites.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.line.cmp(&right.line))
            .then_with(|| left.name.cmp(&right.name))
    });
    report
}

fn unique_active_rules(
    active: &ResolvedActiveSemanticModels,
) -> Vec<(&ActiveSemanticModelShard, &GeneratorRule)> {
    let mut rule_ids = active
        .shards()
        .iter()
        .flat_map(|shard| {
            shard
                .shard
                .payload()
                .generator_rules()
                .into_iter()
                .flatten()
                .map(|rule| rule.id.clone())
        })
        .collect::<Vec<_>>();
    rule_ids.sort_unstable();
    rule_ids.dedup();
    rule_ids
        .iter()
        .filter_map(|rule_id| {
            let matched = active.rules_with_id(rule_id);
            let [activated] = matched.records.as_slice() else {
                return None;
            };
            Some((activated.shard, activated.record))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelConformanceSymbol {
    pub id: String,
    #[serde(default)]
    pub owner_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub signature: Option<String>,
    pub location_prefix: String,
    pub pack_id: String,
    #[serde(default)]
    pub rule_id: Option<String>,
    pub completeness: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelConformanceRelationship {
    pub id: String,
    pub kind: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelConformanceLink {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelConformanceMatch {
    pub site: SemanticModelSite,
    pub rule_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelConformanceFixture {
    pub schema_version: u32,
    #[serde(default)]
    pub symbols: Vec<SemanticModelConformanceSymbol>,
    #[serde(default)]
    pub relationships: Vec<SemanticModelConformanceRelationship>,
    #[serde(default)]
    pub forward_definitions: Vec<SemanticModelConformanceLink>,
    #[serde(default)]
    pub inverse_usages: Vec<SemanticModelConformanceLink>,
    #[serde(default)]
    pub positive_matches: Vec<SemanticModelConformanceMatch>,
    #[serde(default)]
    pub negative_matches: Vec<SemanticModelConformanceMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticModelConformanceReport {
    pub format: &'static str,
    pub complete: bool,
    pub passed: bool,
    pub checked_assertions: usize,
    pub failures: Vec<String>,
}

pub fn run_semantic_model_conformance(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    fixture: &SemanticModelConformanceFixture,
    cancellation: &crate::CancellationToken,
    max_assertions: usize,
) -> SemanticModelConformanceReport {
    let mut report = SemanticModelConformanceReport {
        format: SEMANTIC_MODEL_CONFORMANCE_FORMAT,
        complete: true,
        passed: false,
        checked_assertions: 0,
        failures: Vec::new(),
    };
    if fixture.schema_version != 1 {
        report.complete = false;
        report.failures.push(format!(
            "unsupported conformance schema version {}",
            fixture.schema_version
        ));
        return report;
    }
    let assertion_count = fixture
        .symbols
        .len()
        .saturating_add(fixture.relationships.len())
        .saturating_add(fixture.forward_definitions.len())
        .saturating_add(fixture.inverse_usages.len())
        .saturating_add(fixture.positive_matches.len())
        .saturating_add(fixture.negative_matches.len());
    if assertion_count > max_assertions {
        report.complete = false;
        report.failures.push(format!(
            "conformance assertions exceed the limit of {max_assertions}"
        ));
        return report;
    }
    let overlay = match SemanticModelOverlay::build(analyzer, active, cancellation, u64::MAX) {
        Ok(overlay) => overlay,
        Err(error_value) => {
            report.complete = false;
            report
                .failures
                .push(format!("production overlay build failed: {error_value:?}"));
            return report;
        }
    };
    for expected in &fixture.symbols {
        report.checked_assertions += 1;
        let matched = overlay.symbols.iter().any(|symbol| {
            symbol.id == expected.id
                && symbol.owner_id == expected.owner_id
                && symbol.name == expected.name
                && symbol.signature == expected.signature
                && symbol
                    .location
                    .identity()
                    .starts_with(&expected.location_prefix)
                && symbol.provenance.pack_id == expected.pack_id
                && symbol.provenance.rule_id == expected.rule_id
                && semantic_completeness_name(symbol.provenance.completeness)
                    == expected.completeness
        });
        if !matched {
            report
                .failures
                .push(format!("missing expected symbol `{}`", expected.id));
        }
    }
    for expected in &fixture.relationships {
        report.checked_assertions += 1;
        if !overlay.relations.iter().any(|relation| {
            relation.id == expected.id
                && relation.kind == expected.kind
                && relation.from == expected.from
                && relation.to == expected.to
        }) {
            report
                .failures
                .push(format!("missing expected relationship `{}`", expected.id));
        }
    }
    for expected in &fixture.forward_definitions {
        report.checked_assertions += 1;
        if !overlay.relations.iter().any(|relation| {
            relation.kind == "navigates_to"
                && relation.from == expected.from
                && relation.to == expected.to
        }) {
            report.failures.push(format!(
                "missing forward definition {} -> {}",
                expected.from, expected.to
            ));
        }
    }
    for expected in &fixture.inverse_usages {
        report.checked_assertions += 1;
        if !overlay.relations.iter().any(|relation| {
            relation.kind == "references"
                && relation.from == expected.from
                && relation.to == expected.to
        }) {
            report.failures.push(format!(
                "missing inverse usage {} -> {}",
                expected.from, expected.to
            ));
        }
    }
    for expected in &fixture.positive_matches {
        report.checked_assertions += 1;
        let explanation = explain_semantic_model_site(
            analyzer,
            active,
            expected.site.clone(),
            Some(&expected.rule_id),
            cancellation,
            64,
        );
        if !explanation
            .explanations
            .iter()
            .any(|explanation| explanation.matched)
        {
            report.failures.push(format!(
                "expected rule `{}` to match {}:{}",
                expected.rule_id, expected.site.path, expected.site.line
            ));
        }
    }
    for expected in &fixture.negative_matches {
        report.checked_assertions += 1;
        let explanation = explain_semantic_model_site(
            analyzer,
            active,
            expected.site.clone(),
            Some(&expected.rule_id),
            cancellation,
            64,
        );
        if explanation
            .explanations
            .iter()
            .any(|explanation| explanation.matched)
        {
            report.failures.push(format!(
                "expected rule `{}` to miss {}:{}",
                expected.rule_id, expected.site.path, expected.site.line
            ));
        }
    }
    if cancellation.is_cancelled() {
        report.complete = false;
        report.failures.push("operation cancelled".to_owned());
    }
    report.passed = report.complete && report.failures.is_empty();
    report
}

fn semantic_completeness_name(completeness: SemanticModelCompleteness) -> &'static str {
    match completeness {
        SemanticModelCompleteness::Partial => "partial",
        SemanticModelCompleteness::Complete => "complete",
    }
}

struct GeneratedOverlayFacts {
    symbols: Vec<SemanticModelSymbol>,
    relations: Vec<SemanticModelRelation>,
}

fn generated_overlay_facts(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    cancellation: &crate::CancellationToken,
) -> Result<GeneratedOverlayFacts, SemanticModelOverlayBuildError> {
    let mut rule_ids = active
        .shards()
        .iter()
        .flat_map(|shard| {
            shard
                .shard
                .payload()
                .generator_rules()
                .into_iter()
                .flatten()
                .map(|rule| rule.id.clone())
        })
        .collect::<Vec<_>>();
    rule_ids.sort_unstable();
    rule_ids.dedup();

    let provider_files = analyzer
        .structural_search_providers()
        .into_iter()
        .map(|provider| {
            let mut files = provider.structural_files();
            files.sort();
            files.dedup();
            (provider, files)
        })
        .collect::<Vec<_>>();

    let mut symbols = Vec::new();
    let mut relations = Vec::new();
    let mut aliases = Vec::new();
    for rule_id in rule_ids {
        if cancellation.is_cancelled() {
            return Err(SemanticModelOverlayBuildError::Cancelled);
        }
        let matched = active.rules_with_id(&rule_id);
        if matched.disposition != SemanticModelMatchDisposition::Unique {
            continue;
        }
        let activated = &matched.records[0];
        for (provider, files) in provider_files.iter().filter(|(provider, _)| {
            provider.structural_language().config_label() == activated.shard.manifest.language
        }) {
            for file in files {
                if cancellation.is_cancelled() {
                    return Err(SemanticModelOverlayBuildError::Cancelled);
                }
                let Some(facts) = provider.structural_facts(file) else {
                    continue;
                };
                for (node_index, node) in facts.nodes().iter().enumerate() {
                    if cancellation.is_cancelled() {
                        return Err(SemanticModelOverlayBuildError::Cancelled);
                    }
                    let node_id = u32::try_from(node_index)
                        .expect("structural fact IDs are bounded to u32 by FileFacts");
                    let enclosing = analyzer.enclosing_code_unit(file, &node.range);
                    let Ok(captures) = evaluate_rule_at_node(
                        analyzer,
                        activated.record,
                        &facts,
                        node_id,
                        file,
                        enclosing.as_ref(),
                    ) else {
                        continue;
                    };
                    for captures in &captures {
                        emit_rule_match(
                            active,
                            activated.shard,
                            activated.record,
                            captures,
                            &mut symbols,
                            &mut relations,
                            &mut aliases,
                        );
                    }
                }
            }
        }
    }
    for (alias, target) in aliases {
        if let Some(symbol) = symbols
            .iter_mut()
            .find(|symbol| symbol.id == target || symbol.qualified_name == target)
            && !symbol.aliases.contains(&alias)
        {
            symbol.aliases.push(alias);
        }
    }
    Ok(GeneratedOverlayFacts { symbols, relations })
}

fn rule_trigger_matches(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    trigger: &RuleTrigger,
    facts: &FileFacts,
    node_id: u32,
) -> bool {
    let node = facts.node(node_id);
    let name = node.name.map(|span| span.text(facts.source()));
    match trigger {
        RuleTrigger::LanguageConstruct { construct } => {
            node.construct.as_deref() == Some(construct)
                || NormalizedKind::from_label(construct).is_some_and(|kind| node.kind == kind)
        }
        RuleTrigger::Annotation { name: expected } => {
            node.kind == NormalizedKind::Decorator
                && (name.is_some_and(|actual| exact_trigger_name_matches(expected, actual))
                    || qualified_decorator_matches(expected, node.span().text(facts.source()))
                    || name.is_some_and(|actual| {
                        imported_trigger_name_matches(analyzer, file, expected, actual)
                    }))
        }
        RuleTrigger::MacroInvocation { name: expected }
        | RuleTrigger::GeneratorInvocation { name: expected } => {
            node.kind == NormalizedKind::Call
                && name.is_some_and(|actual| exact_trigger_name_matches(expected, actual))
        }
        RuleTrigger::ResolvedOwner { .. } | RuleTrigger::ResolvedCall { .. } => false,
    }
}

fn imported_trigger_name_matches(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    expected: &str,
    actual: &str,
) -> bool {
    if !expected.contains('.') || actual.contains('.') {
        return false;
    }
    let Some(provider) = analyzer.import_analysis_provider_for_file(file) else {
        return false;
    };
    let local_imports = provider
        .import_info_of(file)
        .into_iter()
        .filter(|import| !import.is_wildcard && import.local_name() == Some(actual))
        .collect::<Vec<_>>();
    local_imports.len() == 1
        && local_imports.iter().all(|import| {
            import
                .path
                .as_ref()
                .is_some_and(|path| path.render_segments(".") == expected)
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SemanticModelPredicateFailure {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
struct CapturedValue {
    value: String,
    anchor: Option<SemanticModelAuthoredAnchor>,
}

type GeneratorRuleMatch = HashMap<String, CapturedValue>;

fn evaluate_rule_at_node(
    analyzer: &dyn IAnalyzer,
    rule: &GeneratorRule,
    facts: &FileFacts,
    node_id: u32,
    file: &ProjectFile,
    enclosing: Option<&CodeUnit>,
) -> Result<Vec<GeneratorRuleMatch>, SemanticModelPredicateFailure> {
    if !rule_trigger_matches(analyzer, file, &rule.trigger, facts, node_id) {
        let message = match rule.trigger {
            RuleTrigger::ResolvedOwner { .. } | RuleTrigger::ResolvedCall { .. } => {
                "the schema-v1 overlay has no resolved-owner evidence for this site"
            }
            _ => "the normalized node kind or exact trigger name does not match",
        };
        return Err(SemanticModelPredicateFailure {
            code: "trigger.mismatch".to_owned(),
            message: message.to_owned(),
        });
    }
    rule_capture_values(analyzer, rule, facts, node_id, file, enclosing)
}

fn qualified_decorator_matches(expected: &str, decorator_source: &str) -> bool {
    if !expected.contains('.') && !expected.contains("::") {
        return false;
    }
    let Some(body) = decorator_source.trim().strip_prefix('@') else {
        return false;
    };
    body == expected
        || body
            .strip_prefix(expected)
            .is_some_and(|suffix| suffix.starts_with('('))
}

fn exact_trigger_name_matches(expected: &str, actual: &str) -> bool {
    if expected.contains('.') || expected.contains("::") {
        actual == expected
    } else {
        terminal_name(actual.trim_end_matches('!')) == expected
    }
}

fn rule_capture_values(
    analyzer: &dyn IAnalyzer,
    rule: &GeneratorRule,
    facts: &FileFacts,
    node_id: u32,
    file: &ProjectFile,
    enclosing: Option<&CodeUnit>,
) -> Result<Vec<GeneratorRuleMatch>, SemanticModelPredicateFailure> {
    let mut scalar_match = HashMap::default();
    let mut repeated = Vec::new();
    for capture in &rule.captures {
        let values = capture_values(analyzer, &capture.binding, facts, node_id, file, enclosing);
        match (capture.cardinality, values.as_slice()) {
            (super::CaptureCardinality::One, []) => {
                return Err(SemanticModelPredicateFailure {
                    code: "capture.unbound".to_owned(),
                    message: format!(
                        "required capture `{}` has no structured value",
                        capture.name
                    ),
                });
            }
            (super::CaptureCardinality::One | super::CaptureCardinality::Optional, [value]) => {
                scalar_match.insert(capture.name.clone(), value.clone());
            }
            (super::CaptureCardinality::Optional, []) => {}
            (super::CaptureCardinality::Many, []) => return Ok(Vec::new()),
            (super::CaptureCardinality::Many, values) => {
                repeated.push((capture.name.clone(), values.to_vec()));
            }
            (_, _) => {
                return Err(SemanticModelPredicateFailure {
                    code: "capture.cardinality".to_owned(),
                    message: format!(
                        "capture `{}` produced more than one structured value",
                        capture.name
                    ),
                });
            }
        }
    }
    let Some((_, first_values)) = repeated.first() else {
        return Ok(vec![scalar_match]);
    };
    let row_count = first_values.len();
    if repeated.iter().any(|(_, values)| values.len() != row_count) {
        return Err(SemanticModelPredicateFailure {
            code: "capture.repeated_length".to_owned(),
            message: "repeated captures produced different row counts".to_owned(),
        });
    }
    Ok((0..row_count)
        .map(|index| {
            let mut row = scalar_match.clone();
            for (name, values) in &repeated {
                row.insert(name.clone(), values[index].clone());
            }
            row
        })
        .collect())
}

fn capture_values(
    analyzer: &dyn IAnalyzer,
    binding: &CaptureBinding,
    facts: &FileFacts,
    node_id: u32,
    file: &ProjectFile,
    enclosing: Option<&CodeUnit>,
) -> Vec<CapturedValue> {
    let scalar = |value: Option<String>, anchor| {
        value
            .map(|value| CapturedValue { value, anchor })
            .into_iter()
            .collect()
    };
    match &binding.source {
        CaptureSource::MatchedNode => scalar(
            projected_node_value(binding.projection, facts, node_id, file, enclosing),
            Some(span_anchor(
                facts,
                file,
                facts.node(node_id).span(),
                enclosing,
            )),
        ),
        CaptureSource::EnclosingDeclaration => {
            let Some(enclosing) = enclosing else {
                return Vec::new();
            };
            scalar(
                projected_declaration_value(analyzer, binding.projection, file, enclosing),
                authored_anchor(
                    analyzer,
                    &Locator::Source {
                        path: file.rel_path().to_string_lossy().replace('\\', "/"),
                        symbol: Some(enclosing.fq_name()),
                    },
                    &enclosing.fq_name(),
                ),
            )
        }
        CaptureSource::OwningType => {
            let Some(enclosing) = enclosing else {
                return Vec::new();
            };
            let owner = if enclosing.is_class() || enclosing.is_module() {
                Some(enclosing.clone())
            } else {
                analyzer.parent_of(enclosing)
            };
            let Some(owner) = owner.filter(|unit| unit.is_class() || unit.is_module()) else {
                return Vec::new();
            };
            scalar(
                projected_declaration_value(analyzer, binding.projection, file, &owner),
                authored_anchor(
                    analyzer,
                    &Locator::Source {
                        path: file.rel_path().to_string_lossy().replace('\\', "/"),
                        symbol: Some(owner.fq_name()),
                    },
                    &owner.fq_name(),
                ),
            )
        }
        CaptureSource::OwnedFields | CaptureSource::OwnedMutableFields => {
            let Some(enclosing) = enclosing else {
                return Vec::new();
            };
            let mut fields = if enclosing.is_field() {
                vec![enclosing.clone()]
            } else {
                analyzer.get_members_in_class(enclosing)
            };
            fields.retain(CodeUnit::is_field);
            fields.retain(|field| {
                let metadata = analyzer.signature_metadata_of(field);
                !metadata.iter().any(|metadata| metadata.field_is_static())
                    && (!matches!(&binding.source, CaptureSource::OwnedMutableFields)
                        || !metadata.iter().any(|metadata| metadata.field_is_final()))
            });
            fields.sort();
            fields.dedup();
            fields
                .into_iter()
                .filter_map(|field| {
                    projected_declaration_value(analyzer, binding.projection, file, &field).map(
                        |value| CapturedValue {
                            value,
                            anchor: authored_anchor(
                                analyzer,
                                &Locator::Source {
                                    path: file.rel_path().to_string_lossy().replace('\\', "/"),
                                    symbol: Some(field.fq_name()),
                                },
                                &field.fq_name(),
                            ),
                        },
                    )
                })
                .collect()
        }
        CaptureSource::Argument { index } => scalar(
            facts
                .role_targets(node_id, Role::Arg)
                .nth(*index as usize)
                .and_then(|target| {
                    projected_role_value(binding.projection, facts, target, file, enclosing)
                }),
            facts
                .role_targets(node_id, Role::Arg)
                .nth(*index as usize)
                .map(|target| role_span_anchor(facts, file, target, enclosing)),
        ),
        CaptureSource::Arguments { from } => facts
            .roles(node_id)
            .iter()
            .filter(|target| matches!(target.role, Role::Arg | Role::Kwarg))
            .skip(*from as usize)
            .filter_map(|target| {
                projected_role_value(binding.projection, facts, target, file, enclosing).map(
                    |value| CapturedValue {
                        value,
                        anchor: Some(role_span_anchor(facts, file, target, enclosing)),
                    },
                )
            })
            .collect(),
        CaptureSource::AnnotationArgument { name } => facts
            .role_targets(node_id, Role::Kwarg)
            .find(|target| {
                target
                    .keyword
                    .is_some_and(|keyword| keyword.text(facts.source()) == name)
            })
            .and_then(|target| {
                projected_role_value(binding.projection, facts, target, file, enclosing)
                    .map(|value| (target, value))
            })
            .map(|(target, value)| CapturedValue {
                value,
                anchor: Some(role_span_anchor(facts, file, target, enclosing)),
            })
            .into_iter()
            .collect(),
        CaptureSource::ResolvedOwner => Vec::new(),
    }
}

fn role_span_anchor(
    facts: &FileFacts,
    file: &ProjectFile,
    target: &crate::analyzer::structural::RoleTarget,
    enclosing: Option<&CodeUnit>,
) -> SemanticModelAuthoredAnchor {
    let mut anchor = span_anchor(facts, file, target.span, enclosing);
    if let Some(enclosing) = enclosing {
        let name = target.name.unwrap_or(target.span).text(facts.source());
        anchor.symbol = format!("{}.{}", enclosing.fq_name(), name);
    }
    anchor
}

fn span_anchor(
    facts: &FileFacts,
    file: &ProjectFile,
    span: crate::analyzer::structural::Span,
    enclosing: Option<&CodeUnit>,
) -> SemanticModelAuthoredAnchor {
    SemanticModelAuthoredAnchor {
        path: file.rel_path().to_string_lossy().replace('\\', "/"),
        symbol: enclosing
            .map(CodeUnit::fq_name)
            .unwrap_or_else(|| span.text(facts.source()).to_owned()),
        range: SemanticModelRange {
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            start_line: facts.line_of_byte(span.start_byte),
            end_line: facts.line_of_byte(span.end_byte),
        },
    }
}

fn projected_node_value(
    projection: CaptureProjection,
    facts: &FileFacts,
    node_id: u32,
    file: &ProjectFile,
    enclosing: Option<&CodeUnit>,
) -> Option<String> {
    let node = facts.node(node_id);
    match projection {
        CaptureProjection::Name => node
            .name
            .map(|name| name.text(facts.source()).trim_end_matches('!').to_string()),
        CaptureProjection::Text => Some(node.span().text(facts.source()).to_string()),
        CaptureProjection::Path => Some(file.rel_path().to_string_lossy().replace('\\', "/")),
        CaptureProjection::StableId | CaptureProjection::Type => {
            enclosing.map(|unit| unit.fq_name())
        }
    }
}

fn projected_declaration_value(
    analyzer: &dyn IAnalyzer,
    projection: CaptureProjection,
    file: &ProjectFile,
    declaration: &CodeUnit,
) -> Option<String> {
    Some(match projection {
        CaptureProjection::Name => declaration.identifier().to_string(),
        CaptureProjection::StableId => declaration.fq_name(),
        CaptureProjection::Type => analyzer
            .signature_metadata_of(declaration)
            .into_iter()
            .find_map(|metadata| metadata.return_type_text().map(str::to_owned))?,
        CaptureProjection::Path => file.rel_path().to_string_lossy().replace('\\', "/"),
        CaptureProjection::Text => return None,
    })
}

fn projected_role_value(
    projection: CaptureProjection,
    facts: &FileFacts,
    target: &crate::analyzer::structural::RoleTarget,
    file: &ProjectFile,
    enclosing: Option<&CodeUnit>,
) -> Option<String> {
    match projection {
        CaptureProjection::Name => Some(
            target
                .name
                .unwrap_or(target.span)
                .text(facts.source())
                .to_string(),
        ),
        CaptureProjection::Text => Some(target.span.text(facts.source()).to_string()),
        CaptureProjection::Path => Some(file.rel_path().to_string_lossy().replace('\\', "/")),
        CaptureProjection::StableId => enclosing.map(|unit| {
            let name = target.name.unwrap_or(target.span).text(facts.source());
            format!("{}.{}", unit.fq_name(), name)
        }),
        CaptureProjection::Type => enclosing.map(|unit| unit.fq_name()),
    }
}

fn emit_rule_match(
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    rule: &GeneratorRule,
    captures: &GeneratorRuleMatch,
    symbols: &mut Vec<SemanticModelSymbol>,
    relations: &mut Vec<SemanticModelRelation>,
    aliases: &mut Vec<(String, String)>,
) {
    for emission in &rule.emissions {
        match emission {
            RuleEmission::Declaration {
                id,
                name,
                anchor,
                declaration,
            } => {
                let (Some(id), Some(name)) = (
                    evaluate_template(id, captures),
                    evaluate_template(name, captures),
                ) else {
                    continue;
                };
                let location = anchor
                    .as_ref()
                    .and_then(|expression| capture_anchor(expression, captures))
                    .map(SemanticModelLocation::Authored)
                    .unwrap_or_else(|| {
                        model_location(shard, "generated", &format!("{}:{id}", rule.id))
                    });
                let mut model_provenance = provenance(active, shard, &id, &location, None, false);
                model_provenance.rule_id = Some(rule.id.clone());
                let symbol = match declaration {
                    EmittedDeclaration::Type {
                        type_kind: emitted_kind,
                        ..
                    } => SemanticModelSymbol {
                        id,
                        owner_id: None,
                        name: terminal_name(&name).to_string(),
                        qualified_name: name,
                        language: shard.manifest.language.clone(),
                        kind: type_kind(*emitted_kind),
                        visibility: Visibility::Public,
                        is_static: false,
                        signature: None,
                        structured_signature: None,
                        has_explicit_type_terms: false,
                        callable_shape: None,
                        aliases: Vec::new(),
                        type_parameter_constraints: Vec::new(),
                        underlying_type: None,
                        embedded_types: Vec::new(),
                        receiver: None,
                        extension_receiver: None,
                        extension_receiver_constraints: Vec::new(),
                        location,
                        provenance: model_provenance,
                    },
                    EmittedDeclaration::Member {
                        owner,
                        member_kind: emitted_kind,
                        signature,
                        is_static,
                        ..
                    } => {
                        let Some(owner) = evaluate_template(owner, captures) else {
                            continue;
                        };
                        SemanticModelSymbol {
                            id,
                            owner_id: Some(owner.clone()),
                            name: name.clone(),
                            qualified_name: format!("{owner}.{name}"),
                            language: shard.manifest.language.clone(),
                            kind: member_kind(*emitted_kind),
                            visibility: Visibility::Public,
                            is_static: *is_static,
                            signature: signature.as_ref().and_then(|signature| {
                                render_template_signature(&name, signature, captures)
                            }),
                            structured_signature: signature.as_ref().and_then(|signature| {
                                evaluate_template_signature(signature, captures)
                            }),
                            has_explicit_type_terms: false,
                            callable_shape: signature.as_ref().and_then(|signature| {
                                render_template_callable_shape(signature, captures)
                            }),
                            aliases: Vec::new(),
                            type_parameter_constraints: Vec::new(),
                            underlying_type: None,
                            embedded_types: Vec::new(),
                            receiver: None,
                            extension_receiver: None,
                            extension_receiver_constraints: Vec::new(),
                            location,
                            provenance: model_provenance,
                        }
                    }
                };
                symbols.push(symbol);
            }
            RuleEmission::Alias { from, to, .. } => {
                if let (Some(from), Some(to)) = (
                    evaluate_template(from, captures),
                    evaluate_template(to, captures),
                ) {
                    aliases.push((from, to));
                }
            }
            RuleEmission::Relation {
                id,
                relation_kind,
                from,
                to,
            } => {
                let (Some(id), Some(from), Some(to)) = (
                    evaluate_template(id, captures),
                    evaluate_template(from, captures),
                    evaluate_template(to, captures),
                ) else {
                    continue;
                };
                let location =
                    model_location(shard, "generated-relation", &format!("{}:{id}", rule.id));
                let mut model_provenance = provenance(active, shard, &id, &location, None, false);
                model_provenance.rule_id = Some(rule.id.clone());
                relations.push(SemanticModelRelation {
                    id,
                    kind: relation_kind_label(*relation_kind).to_string(),
                    from,
                    to,
                    declaration_ordinal: None,
                    provenance: model_provenance,
                });
            }
        }
    }
}

fn evaluate_template(
    expression: &TemplateExpression,
    captures: &GeneratorRuleMatch,
) -> Option<String> {
    match expression {
        TemplateExpression::Literal { value } => Some(value.clone()),
        TemplateExpression::Capture { name } => captures.get(name).map(|value| value.value.clone()),
        TemplateExpression::Concat { values } => {
            let mut rendered = String::new();
            for value in values {
                rendered.push_str(&evaluate_template(value, captures)?);
            }
            Some(rendered)
        }
        TemplateExpression::Transform { transform, value } => {
            evaluate_template(value, captures).map(|value| ascii_transform(*transform, &value))
        }
        TemplateExpression::Conditional {
            condition,
            then_value,
            else_value,
        } => {
            let matches = match condition {
                super::TemplateCondition::Equals { left, right } => {
                    evaluate_template(left, captures)? == evaluate_template(right, captures)?
                }
                super::TemplateCondition::StartsWith { value, prefix } => {
                    evaluate_template(value, captures)?
                        .starts_with(&evaluate_template(prefix, captures)?)
                }
            };
            let branch = if matches { then_value } else { else_value };
            evaluate_template(branch, captures)
        }
    }
}

fn capture_anchor(
    expression: &TemplateExpression,
    captures: &GeneratorRuleMatch,
) -> Option<SemanticModelAuthoredAnchor> {
    match expression {
        TemplateExpression::Capture { name } => captures.get(name)?.anchor.clone(),
        _ => None,
    }
}

fn ascii_transform(transform: AsciiTransform, value: &str) -> String {
    match transform {
        AsciiTransform::Lowercase => value.to_ascii_lowercase(),
        AsciiTransform::Uppercase => value.to_ascii_uppercase(),
        AsciiTransform::SnakeCase => ascii_words(value).join("_"),
        AsciiTransform::KebabCase => ascii_words(value).join("-"),
        AsciiTransform::PascalCase => ascii_words(value)
            .into_iter()
            .map(|word| capitalize_ascii(&word))
            .collect(),
        AsciiTransform::CamelCase => {
            let mut words = ascii_words(value).into_iter();
            let Some(first) = words.next() else {
                return String::new();
            };
            first
                + &words
                    .map(|word| capitalize_ascii(&word))
                    .collect::<String>()
        }
    }
}

fn ascii_words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for character in value.chars() {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current).to_ascii_lowercase());
            }
            previous_lower = false;
            continue;
        }
        if character.is_ascii_uppercase() && previous_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current).to_ascii_lowercase());
        }
        previous_lower = character.is_ascii_lowercase() || character.is_ascii_digit();
        current.push(character);
    }
    if !current.is_empty() {
        words.push(current.to_ascii_lowercase());
    }
    words
}

fn capitalize_ascii(value: &str) -> String {
    let mut characters = value.chars();
    characters
        .next()
        .map(|first| first.to_ascii_uppercase().to_string() + characters.as_str())
        .unwrap_or_default()
}

fn render_template_signature(
    name: &str,
    signature: &TemplateSignature,
    captures: &GeneratorRuleMatch,
) -> Option<String> {
    let parameters = signature
        .parameters
        .iter()
        .map(|parameter| {
            Some(format!(
                "{}: {}{}{}",
                evaluate_template(&parameter.name, captures)?,
                render_template_type(&parameter.r#type, captures)?,
                if parameter.optional { "?" } else { "" },
                if parameter.variadic { "..." } else { "" },
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    let returns = match &signature.returns {
        Some(returns) => format!(" -> {}", render_template_type(returns, captures)?),
        None => String::new(),
    };
    Some(format!("{name}({}){returns}", parameters.join(", ")))
}

fn evaluate_template_signature(
    signature: &TemplateSignature,
    captures: &GeneratorRuleMatch,
) -> Option<Signature> {
    Some(Signature {
        type_parameters: signature
            .type_parameters
            .iter()
            .map(|parameter| evaluate_template(parameter, captures))
            .collect::<Option<Vec<_>>>()?,
        parameters: signature
            .parameters
            .iter()
            .map(|parameter| {
                Some(super::Parameter {
                    name: Some(evaluate_template(&parameter.name, captures)?),
                    r#type: evaluate_template_type(&parameter.r#type, captures)?,
                    optional: parameter.optional,
                    variadic: parameter.variadic,
                })
            })
            .collect::<Option<Vec<_>>>()?,
        returns: match &signature.returns {
            Some(returns) => Some(evaluate_template_type(returns, captures)?),
            None => None,
        },
    })
}

fn evaluate_template_type(
    reference: &TemplateTypeRef,
    captures: &GeneratorRuleMatch,
) -> Option<TypeRef> {
    match reference {
        TemplateTypeRef::Named {
            name,
            arguments,
            nullable,
        } => Some(TypeRef::Named {
            name: evaluate_template(name, captures)?,
            arguments: arguments
                .iter()
                .map(|argument| evaluate_template_type(argument, captures))
                .collect::<Option<Vec<_>>>()?,
            nullable: *nullable,
        }),
        TemplateTypeRef::Capture { name } => Some(TypeRef::Named {
            name: captures.get(name)?.value.clone(),
            arguments: Vec::new(),
            nullable: false,
        }),
        TemplateTypeRef::Array { element } => Some(TypeRef::Array {
            element: Box::new(evaluate_template_type(element, captures)?),
        }),
    }
}

fn render_template_callable_shape(
    signature: &TemplateSignature,
    captures: &GeneratorRuleMatch,
) -> Option<String> {
    let parameters = signature
        .parameters
        .iter()
        .map(|parameter| {
            Some(format!(
                "{}{}{}",
                render_template_type(&parameter.r#type, captures)?,
                if parameter.optional { "?" } else { "" },
                if parameter.variadic { "..." } else { "" },
            ))
        })
        .collect::<Option<Vec<_>>>()?
        .join(",");
    Some(format!("{}<{parameters}>", signature.type_parameters.len()))
}

fn render_template_type(
    reference: &TemplateTypeRef,
    captures: &GeneratorRuleMatch,
) -> Option<String> {
    match reference {
        TemplateTypeRef::Named {
            name,
            arguments,
            nullable,
        } => {
            let mut rendered = evaluate_template(name, captures)?;
            if !arguments.is_empty() {
                rendered.push('<');
                rendered.push_str(
                    &arguments
                        .iter()
                        .map(|argument| render_template_type(argument, captures))
                        .collect::<Option<Vec<_>>>()?
                        .join(", "),
                );
                rendered.push('>');
            }
            if *nullable {
                rendered.push('?');
            }
            Some(rendered)
        }
        TemplateTypeRef::Capture { name } => captures.get(name).map(|value| value.value.clone()),
        TemplateTypeRef::Array { element } => {
            render_template_type(element, captures).map(|element| format!("{element}[]"))
        }
    }
}

fn type_symbol(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    record: &TypeFact,
    ambiguous: bool,
) -> SemanticModelSymbol {
    let location = location(
        analyzer,
        shard,
        &record.locator,
        &record.name,
        "type",
        &record.id,
    );
    SemanticModelSymbol {
        id: record.id.clone(),
        owner_id: None,
        name: terminal_name(&record.name).to_string(),
        qualified_name: record.name.clone(),
        language: shard.manifest.language.clone(),
        kind: type_kind(record.type_kind),
        visibility: record.visibility,
        is_static: false,
        signature: None,
        structured_signature: None,
        has_explicit_type_terms: record.has_explicit_type_terms,
        callable_shape: None,
        aliases: record.aliases.clone(),
        type_parameter_constraints: record.type_parameter_constraints.clone(),
        underlying_type: record.underlying_type.clone(),
        embedded_types: record.embedded_types.clone(),
        receiver: None,
        extension_receiver: None,
        extension_receiver_constraints: Vec::new(),
        provenance: provenance(
            active,
            shard,
            &record.id,
            &location,
            Some(&record.locator),
            ambiguous,
        ),
        location,
    }
}

fn member_symbol(
    analyzer: &dyn IAnalyzer,
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    record: &MemberFact,
    qualified_owner: Option<&str>,
    ambiguous: bool,
) -> SemanticModelSymbol {
    let qualified_name = format!(
        "{}.{}",
        qualified_owner.unwrap_or(&record.owner),
        record.name
    );
    let location = location(
        analyzer,
        shard,
        &record.locator,
        &qualified_name,
        "member",
        &record.id,
    );
    SemanticModelSymbol {
        id: record.id.clone(),
        owner_id: Some(record.owner.clone()),
        name: record.name.clone(),
        qualified_name,
        language: shard.manifest.language.clone(),
        kind: member_kind(record.member_kind),
        visibility: record.visibility,
        is_static: record.is_static,
        signature: record
            .signature
            .as_ref()
            .map(|signature| render_signature(&record.name, signature)),
        structured_signature: record.signature.clone(),
        has_explicit_type_terms: false,
        callable_shape: record.signature.as_ref().map(render_callable_shape),
        aliases: record.aliases.clone(),
        type_parameter_constraints: Vec::new(),
        underlying_type: None,
        embedded_types: Vec::new(),
        receiver: record.receiver,
        extension_receiver: record.extension_receiver.clone(),
        extension_receiver_constraints: record.extension_receiver_constraints.clone(),
        provenance: provenance(
            active,
            shard,
            &record.id,
            &location,
            Some(&record.locator),
            ambiguous,
        ),
        location,
    }
}

fn relation(
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    record: &RelationFact,
    ambiguous: bool,
) -> SemanticModelRelation {
    let location = model_location(shard, "relation", &record.id);
    SemanticModelRelation {
        id: record.id.clone(),
        kind: relation_kind_label(record.relation_kind).to_string(),
        from: record.from.clone(),
        to: record.to.clone(),
        declaration_ordinal: None,
        provenance: provenance(active, shard, &record.id, &location, None, ambiguous),
    }
}

fn hierarchy_relation(
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    owner_id: &str,
    hierarchy: &HierarchyFact,
    ambiguous: bool,
) -> SemanticModelRelation {
    let target = match &hierarchy.target {
        TypeRef::Declared { id, .. } => id.clone(),
        TypeRef::Named { name, .. } => name.clone(),
        other => render_type_ref(other),
    };
    let kind = hierarchy_kind_label(hierarchy.hierarchy_kind).to_string();
    let id = format!("hierarchy:{owner_id}:{kind}:{target}");
    let location = model_location(shard, "hierarchy", &id);
    SemanticModelRelation {
        id: id.clone(),
        kind,
        from: owner_id.to_string(),
        to: target,
        declaration_ordinal: hierarchy.declaration_ordinal,
        provenance: provenance(active, shard, &id, &location, None, ambiguous),
    }
}

fn relation_kind_label(kind: RelationKind) -> &'static str {
    match kind {
        RelationKind::NavigatesTo => "navigates_to",
        RelationKind::References => "references",
    }
}

fn hierarchy_kind_label(kind: HierarchyKind) -> &'static str {
    match kind {
        HierarchyKind::Extends => "extends",
        HierarchyKind::Implements => "implements",
        HierarchyKind::UsesTrait => "uses_trait",
        HierarchyKind::MixinInclude => "mixin_include",
        HierarchyKind::MixinPrepend => "mixin_prepend",
        HierarchyKind::MixinExtend => "mixin_extend",
    }
}

fn location(
    analyzer: &dyn IAnalyzer,
    shard: &ActiveSemanticModelShard,
    locator: &Locator,
    fallback_symbol: &str,
    record_kind: &str,
    record_id: &str,
) -> SemanticModelLocation {
    authored_anchor(analyzer, locator, fallback_symbol)
        .map(SemanticModelLocation::Authored)
        .unwrap_or_else(|| model_location(shard, record_kind, record_id))
}

fn authored_anchor(
    analyzer: &dyn IAnalyzer,
    locator: &Locator,
    fallback_symbol: &str,
) -> Option<SemanticModelAuthoredAnchor> {
    let Locator::Source { path, symbol } = locator else {
        return None;
    };
    let symbol = symbol.as_deref().unwrap_or(fallback_symbol);
    let path = Path::new(path);
    let file = if path.is_absolute() {
        analyzer.project().file_by_abs_path(path)
    } else {
        analyzer.project().file_by_rel_path(path)
    };
    if let Some(file) = file
        && let Some(unit) = analyzer.definitions(symbol).find(|unit| {
            unit.source() == &file && (unit.fq_name() == symbol || unit.identifier() == symbol)
        })
        && let Some(range) = analyzer
            .ranges(&unit)
            .into_iter()
            .min_by_key(|range| (range.start_line, range.start_byte))
    {
        return Some(SemanticModelAuthoredAnchor {
            path: file.rel_path().to_string_lossy().replace('\\', "/"),
            symbol: unit.fq_name(),
            range: range.into(),
        });
    }
    Some(SemanticModelAuthoredAnchor {
        path: path.to_string_lossy().replace('\\', "/"),
        symbol: symbol.to_owned(),
        range: SemanticModelRange {
            start_byte: 0,
            end_byte: 0,
            start_line: 0,
            end_line: 0,
        },
    })
}

fn model_location(
    shard: &ActiveSemanticModelShard,
    record_kind: &str,
    record_id: &str,
) -> SemanticModelLocation {
    let mut uri = Url::parse(MODEL_URI_BASE).expect("static Bifrost model URI base is valid");
    uri.path_segments_mut()
        .expect("Bifrost model URI base supports path segments")
        .extend([
            shard.manifest.semantic_sha256.as_str(),
            record_kind,
            record_id,
        ]);
    SemanticModelLocation::Model(SemanticModelVirtualLocation {
        uri: uri.to_string(),
        range: SemanticModelRange {
            start_byte: 0,
            end_byte: 0,
            start_line: 1,
            end_line: 1,
        },
    })
}

fn provenance(
    active: &ResolvedActiveSemanticModels,
    shard: &ActiveSemanticModelShard,
    record_id: &str,
    _location: &SemanticModelLocation,
    locator: Option<&Locator>,
    ambiguous: bool,
) -> SemanticModelProvenance {
    let activation = active
        .activation_report()
        .explanations
        .iter()
        .find(|explanation| {
            explanation.status == SemanticModelActivationStatus::Active
                && explanation.manifest_digest == shard.manifest.content_sha256
                && explanation.shard_id == shard.shard.shard_id()
                && explanation.source_kind == shard.source_kind
                && explanation.source_id == shard.source_id
        });
    SemanticModelProvenance {
        active_model_set_hash: active.active_model_set_hash().to_string(),
        pack_digest: shard.manifest.semantic_sha256.clone(),
        pack_id: shard.manifest.pack_id.clone(),
        pack_version: shard.manifest.version.clone(),
        producer: shard.manifest.producer.name.clone(),
        producer_version: shard.manifest.producer.version.clone(),
        record_id: record_id.to_string(),
        rule_id: None,
        origin: origin(shard, locator),
        activation: SemanticModelActivationProvenance {
            status: "active".to_string(),
            reason: activation
                .map(|explanation| explanation.reason.clone())
                .unwrap_or_else(|| "selected by active semantic-model resolution".to_string()),
            source_kind: source_kind(shard.source_kind).to_string(),
            source_id: shard.source_id.clone(),
            matched_evidence: matched_evidence(&shard.matched_evidence),
        },
        proof: if shard.matched_evidence.artifact_sha256.is_some() {
            SemanticModelProof::ExactArtifact
        } else {
            SemanticModelProof::PackFact
        },
        completeness: match shard.manifest.completeness {
            Completeness::Partial => SemanticModelCompleteness::Partial,
            Completeness::Complete => SemanticModelCompleteness::Complete,
        },
        ambiguous,
    }
}

fn origin(shard: &ActiveSemanticModelShard, locator: Option<&Locator>) -> SemanticModelOriginKind {
    match shard.source_kind {
        CatalogPackSourceKind::Generated | CatalogPackSourceKind::WorkspaceProduced => {
            SemanticModelOriginKind::ExactGeneratedOutput
        }
        CatalogPackSourceKind::Installed => match locator {
            Some(Locator::Source { .. }) => SemanticModelOriginKind::DependencySource,
            Some(Locator::Artifact { .. }) => SemanticModelOriginKind::DependencyBinary,
            None => SemanticModelOriginKind::PrebuiltApiIndex,
        },
        CatalogPackSourceKind::PreShipped => SemanticModelOriginKind::PrebuiltApiIndex,
        CatalogPackSourceKind::Embedded | CatalogPackSourceKind::EphemeralWorkspace => {
            SemanticModelOriginKind::DeclarativeModel
        }
    }
}

fn matched_evidence(
    evidence: &super::SemanticModelActivationEvidence,
) -> SemanticModelMatchedEvidence {
    SemanticModelMatchedEvidence {
        language: evidence.language.clone(),
        ecosystem: evidence.ecosystem.clone(),
        package: evidence.package.as_ref().map(matched_coordinate),
        module: evidence.module.as_ref().map(matched_coordinate),
        toolchain: evidence.toolchain.as_ref().map(matched_coordinate),
        target: evidence.target.clone(),
        configuration: evidence.configuration.clone(),
        artifact_sha256: evidence.artifact_sha256.clone(),
    }
}

fn matched_coordinate(coordinate: &super::CatalogCoordinate) -> SemanticModelMatchedCoordinate {
    SemanticModelMatchedCoordinate {
        name: coordinate.name.clone(),
        version: coordinate.version.as_ref().map(ToString::to_string),
    }
}

fn source_kind(kind: CatalogPackSourceKind) -> &'static str {
    match kind {
        CatalogPackSourceKind::Installed => "installed",
        CatalogPackSourceKind::Generated => "generated",
        CatalogPackSourceKind::PreShipped => "pre_shipped",
        CatalogPackSourceKind::WorkspaceProduced => "workspace_produced",
        CatalogPackSourceKind::Embedded => "embedded",
        CatalogPackSourceKind::EphemeralWorkspace => "ephemeral_workspace",
    }
}

fn type_kind(kind: TypeKind) -> SemanticModelSymbolKind {
    match kind {
        TypeKind::Class => SemanticModelSymbolKind::Class,
        TypeKind::Annotation => SemanticModelSymbolKind::Annotation,
        TypeKind::Delegate => SemanticModelSymbolKind::Delegate,
        TypeKind::Interface => SemanticModelSymbolKind::Interface,
        TypeKind::Trait => SemanticModelSymbolKind::Trait,
        TypeKind::Struct => SemanticModelSymbolKind::Struct,
        TypeKind::Union => SemanticModelSymbolKind::Union,
        TypeKind::Enum => SemanticModelSymbolKind::Enum,
        TypeKind::Record => SemanticModelSymbolKind::Record,
        TypeKind::Module => SemanticModelSymbolKind::Module,
        TypeKind::TypeAlias => SemanticModelSymbolKind::TypeAlias,
    }
}

fn member_kind(kind: MemberKind) -> SemanticModelSymbolKind {
    match kind {
        MemberKind::Constructor => SemanticModelSymbolKind::Constructor,
        MemberKind::Method => SemanticModelSymbolKind::Method,
        MemberKind::Function => SemanticModelSymbolKind::Function,
        MemberKind::Field => SemanticModelSymbolKind::Field,
        MemberKind::Property => SemanticModelSymbolKind::Property,
        MemberKind::Constant => SemanticModelSymbolKind::Constant,
        MemberKind::Static => SemanticModelSymbolKind::Static,
        MemberKind::Macro => SemanticModelSymbolKind::Macro,
        MemberKind::Event => SemanticModelSymbolKind::Event,
    }
}

fn terminal_name(name: &str) -> &str {
    name.rsplit(['.', ':', '$']) // fqname-M4: declarative model and AST trigger names have no CodeUnit/FqName at this boundary
        .find(|part| !part.is_empty())
        .unwrap_or(name)
}

fn render_signature(name: &str, signature: &super::Signature) -> String {
    let parameters = signature
        .parameters
        .iter()
        .map(|parameter| {
            let ty = render_type_ref(&parameter.r#type);
            parameter
                .name
                .as_deref()
                .map(|name| format!("{name}: {ty}"))
                .unwrap_or(ty)
        })
        .collect::<Vec<_>>()
        .join(", ");
    match &signature.returns {
        Some(result) => format!("{name}({parameters}) -> {}", render_type_ref(result)),
        None => format!("{name}({parameters})"),
    }
}

fn render_callable_shape(signature: &super::Signature) -> String {
    let parameters = signature
        .parameters
        .iter()
        .map(|parameter| {
            format!(
                "{}{}{}",
                render_type_ref(&parameter.r#type),
                if parameter.optional { "?" } else { "" },
                if parameter.variadic { "..." } else { "" },
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{}<{parameters}>", signature.type_parameters.len())
}

fn render_type_ref(reference: &TypeRef) -> String {
    match reference {
        TypeRef::Named {
            name,
            arguments,
            nullable,
        } => render_named_type(name, arguments, *nullable),
        TypeRef::Declared {
            id,
            arguments,
            nullable,
        } => render_named_type(id, arguments, *nullable),
        TypeRef::TypeParameter { name } => name.clone(),
        TypeRef::Array { element } => format!("{}[]", render_type_ref(element)),
        TypeRef::ByRef { element } => format!("ref {}", render_type_ref(element)),
        TypeRef::Pointer { element } => format!("*{}", render_type_ref(element)),
        TypeRef::Slice { element } => format!("[]{}", render_type_ref(element)),
        TypeRef::FixedArray { element, length } => {
            format!("[{length}]{}", render_type_ref(element))
        }
        TypeRef::Map { key, value } => {
            format!("map[{}]{}", render_type_ref(key), render_type_ref(value))
        }
        TypeRef::Channel { element, direction } => match direction {
            crate::analyzer::semantic_model::ChannelDirection::Bidirectional => {
                format!("chan {}", render_type_ref(element))
            }
            crate::analyzer::semantic_model::ChannelDirection::Receive => {
                format!("<-chan {}", render_type_ref(element))
            }
            crate::analyzer::semantic_model::ChannelDirection::Send => {
                format!("chan<- {}", render_type_ref(element))
            }
        },
        TypeRef::Wildcard { variance, bound } => match bound {
            Some(bound) => {
                format!("{:?} {}", variance, render_type_ref(bound)).to_ascii_lowercase()
            }
            None => "?".to_string(),
        },
        TypeRef::Tuple { elements } => format!(
            "({})",
            elements
                .iter()
                .map(render_type_ref)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        TypeRef::Function { parameters, result } => {
            let parameters = parameters
                .iter()
                .map(|parameter| {
                    let rendered = render_type_ref(&parameter.r#type);
                    if parameter.variadic {
                        format!("...{rendered}")
                    } else {
                        rendered
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            match result {
                Some(result) => format!("({parameters}) -> {}", render_type_ref(result)),
                None => format!("({parameters})"),
            }
        }
    }
}

fn render_named_type(name: &str, arguments: &[TypeRef], nullable: bool) -> String {
    let mut rendered = name.to_string();
    if !arguments.is_empty() {
        rendered.push('<');
        rendered.push_str(
            &arguments
                .iter()
                .map(render_type_ref)
                .collect::<Vec<_>>()
                .join(", "),
        );
        rendered.push('>');
    }
    if nullable {
        rendered.push('?');
    }
    rendered
}
