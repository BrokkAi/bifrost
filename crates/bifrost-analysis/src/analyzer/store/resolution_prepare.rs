//! Prepare storage-local bundle rows from caller-owned normalized source facts.
//!
//! Combined lowering and catalog completion are synchronous and unpolled.
//! The subsequent row preparation preserves the donor cancellation checks.
//! This module does no parsing, selected-workspace work, or database publication.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, ResolutionCallableReceiverOrigin, ResolutionGapKind, ResolutionNamespace,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    ResolutionCompletionKind, ResolutionCompletionReasonKind,
};

use crate::CancellationToken;
use crate::analyzer::resolution::{
    BindingFragmentId, BindingNodeId, BindingNodeKind, LoweredCandidateDirection,
    LoweredCoverageGap, LoweredResolutionFactsWithIdentityCatalog, LoweredSemanticRole,
    LoweringCoverageFrontier, PartialPath, ResolutionCompletion, ResolutionIdentityCatalog,
    ResolutionIncompleteReason, ResolutionSemanticIdentitySpace, ResolutionSlotValue, SemanticId,
    TypeTransferValueTransform, WitnessStep, lower_resolution_facts_with_identity_catalog,
};
use crate::hash::{HashMap, HashSet};

use super::resolution::{
    PreparedResolutionBundle, PreparedResolutionBundleRows, PreparedResolutionRow,
    PreparedResolutionValue,
};

/// A completed immutable bundle, or cancellation without a publishable value.
#[derive(Debug)]
pub enum ResolutionInteriorPreparation {
    Prepared(Box<PreparedResolutionBundle>),
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SemanticKey(i64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct NodeKey(i64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PathKey(i64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct VariableKey(i64);

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedNodeCoordinate {
    local_key: PreparedResolutionValue,
    boundary_key: PreparedResolutionValue,
}

impl PreparedNodeCoordinate {
    const fn absent() -> Self {
        Self {
            local_key: PreparedResolutionValue::Null,
            boundary_key: PreparedResolutionValue::Null,
        }
    }
}

struct ResolutionLocalKeys {
    semantics: HashMap<SemanticId, SemanticKey>,
    nodes: HashMap<BindingNodeId, NodeKey>,
    paths: HashMap<crate::analyzer::resolution::PartialPathId, PathKey>,
    variables: HashMap<crate::analyzer::resolution::StackVariableId, VariableKey>,
}

impl ResolutionLocalKeys {
    fn new(
        lowered: &LoweredResolutionFactsWithIdentityCatalog,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let identities = lowered.identities();
        let mut semantics = HashMap::default();
        for (index, (mounted, _)) in identities.semantics().iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            assert!(
                semantics
                    .insert(*mounted, SemanticKey(dense_key(index)))
                    .is_none(),
                "semantic catalog must be a bijection"
            );
        }
        let mut nodes = HashMap::default();
        for (index, (mounted, _)) in identities.nodes().iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            assert!(
                nodes.insert(*mounted, NodeKey(dense_key(index))).is_none(),
                "node catalog must be a bijection"
            );
        }
        let mut paths = HashMap::default();
        for (index, (mounted, _)) in identities.paths().iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            assert!(
                paths.insert(*mounted, PathKey(dense_key(index))).is_none(),
                "path catalog must be a bijection"
            );
        }
        let mut variables = HashMap::default();
        for (index, (mounted, _)) in identities.stack_variables().iter().enumerate() {
            if cancellation.is_cancelled() {
                return None;
            }
            assert!(
                variables
                    .insert(*mounted, VariableKey(dense_key(index)))
                    .is_none(),
                "stack-variable catalog must be a bijection"
            );
        }
        Some(Self {
            semantics,
            nodes,
            paths,
            variables,
        })
    }

    fn semantic(&self, semantic: SemanticId) -> i64 {
        self.semantics
            .get(&semantic)
            .unwrap_or_else(|| panic!("semantic {semantic} is missing from the identity catalog"))
            .0
    }

    fn node(&self, node: BindingNodeId) -> i64 {
        self.nodes
            .get(&node)
            .unwrap_or_else(|| panic!("node {node} is missing from the identity catalog"))
            .0
    }

    fn node_coordinate(&self, node: BindingNodeId) -> PreparedNodeCoordinate {
        if node == BindingNodeId::universal_root() {
            PreparedNodeCoordinate {
                local_key: PreparedResolutionValue::Null,
                boundary_key: BindingNodeId::UNIVERSAL_ROOT_BOUNDARY_KEY.into(),
            }
        } else {
            PreparedNodeCoordinate {
                local_key: self.node(node).into(),
                boundary_key: PreparedResolutionValue::Null,
            }
        }
    }

    fn optional_node_coordinate(&self, node: Option<BindingNodeId>) -> PreparedNodeCoordinate {
        node.map_or_else(PreparedNodeCoordinate::absent, |node| {
            self.node_coordinate(node)
        })
    }

    fn path(&self, path: crate::analyzer::resolution::PartialPathId) -> i64 {
        self.paths
            .get(&path)
            .unwrap_or_else(|| panic!("path {path} is missing from the identity catalog"))
            .0
    }

    fn variable(&self, variable: crate::analyzer::resolution::StackVariableId) -> i64 {
        self.variables
            .get(&variable)
            .unwrap_or_else(|| {
                panic!("stack variable {variable} is missing from the identity catalog")
            })
            .0
    }
}

fn catalog_identity_at<Mounted, Identity>(
    entries: &[(Mounted, Identity)],
    mounted: Mounted,
    key: i64,
    label: &str,
) -> Identity
where
    Mounted: Copy + std::fmt::Debug + Eq,
    Identity: Copy,
{
    let index = usize::try_from(key).expect("storage-local identity key cannot be negative");
    let &(catalog_mounted, identity) = entries
        .get(index)
        .unwrap_or_else(|| panic!("{label} key {key} is outside the identity catalog"));
    assert_eq!(
        catalog_mounted, mounted,
        "{label} key must index its mounted identity"
    );
    identity
}

macro_rules! row {
    ($($value:expr),* $(,)?) => {
        PreparedResolutionRow::new(vec![$(PreparedResolutionValue::from($value)),*])
    };
}

/// Prepare immutable storage-local content from one source owner's normalized facts.
///
/// `unit_keys` must use the exact `CodeUnit` keys and integer values assigned by
/// that same source owner's parsed-unit preparation for this blob. This function
/// checks nonnegative, distinct values and exact coverage of every definition
/// crosswalk; it cannot prove the caller's source provenance or store alignment.
/// Extra entries and sparse values are accepted and preserved without renumbering.
/// An empty map is valid only when no definition crosswalk needs a unit key.
///
/// Cancellation is checked before lowering and polled during key validation and
/// row preparation. Combined lowering and catalog completion are synchronous and
/// unpolled. A final cancellation check prevents returning a cancelled bundle.
/// No database is opened, no producer epoch is installed, and no rows are published.
///
/// # Panics
/// Panics on malformed normalized facts, negative or repeated unit keys, or a
/// definition crosswalk whose exact unit is absent from `unit_keys`.
pub fn prepare_resolution_bundle(
    fragment: BindingFragmentId,
    language: Language,
    facts: &FileResolutionFacts,
    unit_keys: &HashMap<CodeUnit, i64>,
    cancellation: &CancellationToken,
) -> ResolutionInteriorPreparation {
    if cancellation.is_cancelled() {
        return ResolutionInteriorPreparation::Cancelled;
    }
    let mut assigned = HashSet::default();
    for (unit, key) in unit_keys {
        if cancellation.is_cancelled() {
            return ResolutionInteriorPreparation::Cancelled;
        }
        assert!(
            *key >= 0,
            "parsed unit key must be nonnegative: {unit:?} -> {key}"
        );
        assert!(
            assigned.insert(*key),
            "parsed unit keys must be distinct: {unit_keys:?}"
        );
    }
    if cancellation.is_cancelled() {
        return ResolutionInteriorPreparation::Cancelled;
    }
    let lowered = lower_resolution_facts_with_identity_catalog(fragment, language, facts);
    prepare_resolution_bundle_with_unit_keys(&lowered, unit_keys, cancellation)
}

fn prepare_resolution_bundle_with_unit_keys(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    unit_keys: &HashMap<CodeUnit, i64>,
    cancellation: &CancellationToken,
) -> ResolutionInteriorPreparation {
    if cancellation.is_cancelled() {
        return ResolutionInteriorPreparation::Cancelled;
    }
    let lexical = lowered.lexical();
    let typed = lowered.typed();
    assert_eq!(lexical.fragment(), typed.fragment());
    assert_eq!(lexical.fragment(), lowered.identities().fragment());
    assert_eq!(lexical.language(), typed.language());
    assert_ne!(lexical.language(), Language::None);
    let semantic_language = lexical.language();
    let Some(keys) = ResolutionLocalKeys::new(lowered, cancellation) else {
        return ResolutionInteriorPreparation::Cancelled;
    };
    let mut rows = PreparedResolutionBundleRows::default();

    if !prepare_identity_rows(lowered, &keys, &mut rows, cancellation) {
        return ResolutionInteriorPreparation::Cancelled;
    }
    if !prepare_lexical_rows(lowered, &keys, &mut rows, cancellation) {
        return ResolutionInteriorPreparation::Cancelled;
    }
    if !prepare_common_rows(lowered, &keys, unit_keys, &mut rows, cancellation)
        || !prepare_typed_rows(lowered, &keys, &mut rows, cancellation)
        || cancellation.is_cancelled()
    {
        return ResolutionInteriorPreparation::Cancelled;
    }
    assert!(
        rows.reference_enumeration_impacts.is_empty(),
        "reference-enumeration impacts remain explicit-zero until their structured sidecar lands"
    );
    let Some(bundle) = PreparedResolutionBundle::new(semantic_language, rows, cancellation) else {
        return ResolutionInteriorPreparation::Cancelled;
    };
    if cancellation.is_cancelled() {
        return ResolutionInteriorPreparation::Cancelled;
    }
    ResolutionInteriorPreparation::Prepared(Box::new(bundle))
}

fn prepare_common_rows(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    keys: &ResolutionLocalKeys,
    unit_keys: &HashMap<CodeUnit, i64>,
    rows: &mut PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> bool {
    let common = lowered.common();
    for fact in &common.additional_definition_namespaces {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.additional_definition_namespaces.push(row![
            keys.semantic(fact.definition),
            fact.namespace.label(),
            fact.hoisting.label(),
        ]);
    }
    for fact in &common.definition_unit_crosswalks {
        if cancellation.is_cancelled() {
            return false;
        }
        let unit_key = unit_keys.get(&fact.unit).copied().unwrap_or_else(|| {
            panic!(
                "definition {:?} names parsed unit absent from combined blob preparation: {:?}",
                fact.definition, fact.unit
            )
        });
        rows.definition_unit_crosswalks
            .push(row![keys.semantic(fact.definition), unit_key]);
    }
    for fact in &common.deferred_member_owners {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.deferred_member_owner_properties.push(row![
            keys.semantic(fact.definition),
            keys.semantic(fact.owner_frontier),
            fact.kind.label(),
            fact.access.label(),
            fact.qualifier_compatibility.label(),
        ]);
    }
    for fact in &common.declared_type_relations {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.declared_type_relations.push(row![
            keys.semantic(fact.relation),
            keys.semantic(fact.subject_frontier),
            fact.kind.label(),
            fact.target_reference
                .map(|semantic| keys.semantic(semantic)),
            fact.target_frontier.map(|semantic| keys.semantic(semantic)),
        ]);
    }
    for fact in &common.relation_members {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.relation_members.push(row![
            keys.semantic(fact.relation),
            fact.position,
            keys.semantic(fact.definition),
            fact.kind.label(),
        ]);
    }
    for fact in &common.declared_root_routes {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.declared_root_routes.push(row![
            keys.node(fact.root_scope),
            fact.position,
            keys.semantic(fact.segment),
        ]);
    }
    true
}

fn prepare_identity_rows(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    keys: &ResolutionLocalKeys,
    rows: &mut PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> bool {
    use crate::analyzer::resolution::ResolutionSemanticIdentitySpace;

    for (mounted, identity) in lowered.identities().semantics() {
        if cancellation.is_cancelled() {
            return false;
        }
        let identity_space = match identity.space() {
            ResolutionSemanticIdentitySpace::FragmentLocal => "fragment_local",
            ResolutionSemanticIdentitySpace::Shared => "shared",
        };
        rows.semantic_terms.push(row![
            keys.semantic(*mounted),
            identity_space,
            identity.digest(),
        ]);
    }
    for (semantic, recipe) in lowered.identities().lookup_recipes() {
        if cancellation.is_cancelled() {
            return false;
        }
        assert_eq!(
            recipe.semantic_language(),
            lowered.lexical().language().config_label(),
            "lookup recipe language must equal the artifact semantic language"
        );
        rows.lookup_semantic_recipes.push(row![
            keys.semantic(*semantic),
            recipe.namespace().label(),
            recipe.spelling(),
        ]);
    }
    for (mounted, identity) in lowered.identities().stack_variables() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.stack_variables
            .push(row![keys.variable(*mounted), identity.digest()]);
    }
    true
}

fn prepare_lexical_rows(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    keys: &ResolutionLocalKeys,
    rows: &mut PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> bool {
    let lexical = lowered.lexical();
    let identities = lowered.identities();
    let mut sites_by_node = HashMap::default();
    for site in lexical.semantics() {
        if cancellation.is_cancelled() {
            return false;
        }
        assert!(
            sites_by_node.insert(site.node(), site).is_none(),
            "one lowered semantic site owns each semantic node"
        );
        rows.semantic_sites.push(row![
            i64::from(site.site().get()),
            site.namespace().label(),
            semantic_role_label(site.role()),
            keys.semantic(site.semantic()),
            keys.node(site.node()),
            site.definition_graph_domain().map(|domain| domain.label()),
        ]);
    }

    let mut reference_gaps =
        HashMap::<BindingNodeId, BTreeMap<i64, &LoweredCoverageGap>>::default();
    let mut provenance = HashMap::default();
    for gap in lexical.gaps() {
        if cancellation.is_cancelled() {
            return false;
        }
        let value = (gap.site(), gap.origin());
        if let Some(previous) = provenance.insert(gap.reason_semantic(), value) {
            assert_eq!(previous, value, "one reason semantic has one provenance");
        }
        if let LoweringCoverageFrontier::Reference { semantic, node } = gap.frontier() {
            assert_eq!(
                sites_by_node.get(&node).map(|site| site.semantic()),
                Some(semantic),
                "reference gap must name its exact semantic node"
            );
            assert!(
                reference_gaps
                    .entry(node)
                    .or_default()
                    .insert(keys.semantic(gap.reason_semantic()), gap)
                    .is_none(),
                "one reference node cannot repeat a storage-local completion reason"
            );
        }
    }
    for (reason, (site, origin)) in provenance {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.gap_reason_provenance.push(row![
            keys.semantic(reason),
            i64::from(site.get()),
            origin.kind().label(),
        ]);
    }

    for (node, kind) in lexical.nodes() {
        if cancellation.is_cancelled() {
            return false;
        }
        let node_key = keys.node(*node);
        let identity =
            catalog_identity_at(identities.nodes(), *node, node_key, "node identity catalog");
        let mut semantic_key = PreparedResolutionValue::Null;
        let mut jump_scope = PreparedNodeCoordinate::absent();
        let kind_label = match kind {
            BindingNodeKind::Root => {
                panic!("content-owned source lowering cannot persist a universal root node")
            }
            BindingNodeKind::Scope => "scope",
            BindingNodeKind::PushSymbol(semantic) => {
                semantic_key = keys.semantic(*semantic).into();
                "push_symbol"
            }
            BindingNodeKind::PopSymbol(semantic) => {
                semantic_key = keys.semantic(*semantic).into();
                "pop_symbol"
            }
            BindingNodeKind::PushScopedSymbol(semantic) => {
                semantic_key = keys.semantic(*semantic).into();
                "push_scoped_symbol"
            }
            BindingNodeKind::PopScopedSymbol(semantic) => {
                semantic_key = keys.semantic(*semantic).into();
                "pop_scoped_symbol"
            }
            BindingNodeKind::DropScopes => "drop_scopes",
            BindingNodeKind::JumpToScope(scope) => {
                jump_scope = keys.node_coordinate(*scope);
                "jump_to_scope"
            }
            BindingNodeKind::Reference(semantic) => {
                semantic_key = keys.semantic(*semantic).into();
                assert_eq!(
                    sites_by_node.get(node).map(|site| site.semantic()),
                    Some(*semantic),
                    "reference node semantic must match its source site"
                );
                "reference"
            }
            BindingNodeKind::Definition(semantic) => {
                semantic_key = keys.semantic(*semantic).into();
                assert_eq!(
                    sites_by_node.get(node).map(|site| site.semantic()),
                    Some(*semantic),
                    "definition node semantic must match its source site"
                );
                "definition"
            }
        };

        let metadata = matches!(kind, BindingNodeKind::Reference(_)).then(|| {
            sites_by_node
                .get(node)
                .and_then(|site| site.site_metadata())
                .expect("every lowered reference node has source metadata")
        });
        if let Some(metadata) = metadata {
            let (owner_known, owner) = match metadata.reference_owner() {
                None => (false, PreparedResolutionValue::Null),
                Some(owner) => (
                    true,
                    owner
                        .map(|semantic| keys.semantic(semantic))
                        .map_or(PreparedResolutionValue::Null, Into::into),
                ),
            };
            rows.reference_sites.push(row![
                node_key,
                i64::from(metadata.site().get()),
                metadata.namespace().label(),
                metadata.site_kind().label(),
                usize_i64(metadata.start_byte()),
                usize_i64(metadata.end_byte()),
                metadata.unqualified(),
                owner_known,
                owner,
                metadata
                    .callable_receiver_origin()
                    .map(ResolutionCallableReceiverOrigin::label)
            ]);
        }
        let gaps = reference_gaps.remove(node).unwrap_or_default();
        let completion_kind = if gaps.is_empty() {
            ResolutionCompletionKind::Complete.label()
        } else {
            ResolutionCompletionKind::Incomplete.label()
        };
        rows.nodes.push(PreparedResolutionRow::new(vec![
            node_key.into(),
            identity.digest().into(),
            kind_label.into(),
            semantic_key,
            jump_scope.local_key,
            jump_scope.boundary_key,
            completion_kind.into(),
            usize_i64(gaps.len()).into(),
        ]));
        for (position, (_, gap)) in gaps.into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return false;
            }
            rows.reference_completion_reasons.push(row![
                node_key,
                usize_i64(position),
                ResolutionCompletionReasonKind::UnsupportedSemantic.label(),
                PreparedResolutionValue::Null,
                keys.semantic(gap.reason_semantic()),
                PreparedResolutionValue::Null,
                i64::from(gap.site().get()),
                gap.origin().kind().label(),
            ]);
        }
    }
    assert!(
        reference_gaps.is_empty(),
        "every reference gap must name a persisted reference node"
    );

    for (path_id, path) in lexical.paths() {
        if cancellation.is_cancelled() {
            return false;
        }
        let path_key = keys.path(*path_id);
        let identity = catalog_identity_at(
            identities.paths(),
            *path_id,
            path_key,
            "path identity catalog",
        );
        if !prepare_partial_path(
            path_key,
            path,
            identity.digest(),
            identities,
            keys,
            rows,
            cancellation,
        ) {
            return false;
        }
    }

    prepare_gap_families(lowered, keys, rows, cancellation)
}

fn prepare_partial_path(
    path_key: i64,
    path: &PartialPath,
    local_digest: [u8; 32],
    identities: &ResolutionIdentityCatalog,
    keys: &ResolutionLocalKeys,
    rows: &mut PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> bool {
    let Some((body, completion_kind)) =
        prepare_partial_path_body(path, identities, keys, cancellation)
    else {
        return false;
    };
    let body_json = serde_json::to_string(&body).expect("partial-path body serializes to JSON");
    debug_assert_eq!(
        serde_json::from_str::<PersistedPartialPathBody>(&body_json)
            .expect("serialized partial-path body round trips"),
        body,
    );
    let start = keys.node_coordinate(path.start().node());
    let end = keys.node_coordinate(path.end().node());
    rows.partial_paths.push(row![
        path_key,
        local_digest,
        start.local_key,
        start.boundary_key,
        end.local_key,
        end.boundary_key,
        path.start()
            .symbols()
            .tail()
            .map(|value| keys.variable(value)),
        path.end()
            .symbols()
            .tail()
            .map(|value| keys.variable(value)),
        usize_i64(path.start().symbols().fixed().len()),
        usize_i64(path.end().symbols().fixed().len()),
        path.start()
            .symbols()
            .fixed()
            .first()
            .map(|symbol| keys.semantic(symbol.symbol())),
        path.end()
            .symbols()
            .fixed()
            .first()
            .map(|symbol| keys.semantic(symbol.symbol())),
        completion_kind,
        body_json,
    ]);
    true
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct PersistedPartialPathBody {
    start: PersistedPathEndpoint,
    end: PersistedPathEndpoint,
    precedence: Vec<PersistedPathPrecedence>,
    witness: Vec<PersistedPathWitness>,
    reasons: Vec<PersistedPathCompletionReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct PersistedPathEndpoint {
    symbols: Vec<PersistedPathSymbol>,
    scopes: Vec<PersistedPathNode>,
    scope_tail: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct PersistedPathSymbol {
    symbol: i64,
    scopes: Option<Vec<PersistedPathNode>>,
    scope_tail: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PersistedPathNode {
    Local { key: i64 },
    Boundary { key: i64 },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct PersistedPathPrecedence {
    tier: String,
    ordinal: u32,
    namespace: String,
    semantic: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct PersistedPathWitness {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<PersistedPathNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct PersistedPathCompletionReason {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
}

fn prepare_partial_path_body(
    path: &PartialPath,
    identities: &ResolutionIdentityCatalog,
    keys: &ResolutionLocalKeys,
    cancellation: &CancellationToken,
) -> Option<(PersistedPartialPathBody, &'static str)> {
    let start = prepare_path_endpoint(path.start(), keys, cancellation)?;
    let end = prepare_path_endpoint(path.end(), keys, cancellation)?;
    let mut precedence = Vec::with_capacity(path.precedence().len());
    for step in path.precedence() {
        if cancellation.is_cancelled() {
            return None;
        }
        let namespace = identities.precedence_namespace(*step).unwrap_or_else(|| {
            panic!("precedence step is missing its effective namespace: {step:?}")
        });
        precedence.push(PersistedPathPrecedence {
            tier: step.tier.label().to_owned(),
            ordinal: step.ordinal,
            namespace: namespace.label().to_owned(),
            semantic: keys.semantic(step.semantic),
        });
    }
    let mut witness = Vec::with_capacity(path.witness().len());
    for step in path.witness() {
        if cancellation.is_cancelled() {
            return None;
        }
        let (node, semantic, outcome, rejection, status) = match step {
            WitnessStep::Node(node) => (
                Some(persisted_path_node(*node, keys)),
                None,
                None,
                None,
                None,
            ),
            WitnessStep::Candidate { semantic, outcome } => (
                None,
                Some(keys.semantic(*semantic)),
                Some(outcome.kind().label().to_owned()),
                outcome.rejection().map(|reason| reason.label().to_owned()),
                None,
            ),
            WitnessStep::Boundary { semantic, status } => (
                None,
                Some(keys.semantic(*semantic)),
                None,
                None,
                Some(status.label().to_owned()),
            ),
        };
        witness.push(PersistedPathWitness {
            kind: (*step).kind().label().to_owned(),
            node,
            semantic,
            outcome,
            rejection,
            status,
        });
    }
    let (completion_kind, reasons) = match path.completion() {
        ResolutionCompletion::Complete => (path.completion().kind().label(), Vec::new()),
        ResolutionCompletion::Incomplete(reasons) => {
            let mut persisted = BTreeSet::new();
            for reason in reasons.iter() {
                if cancellation.is_cancelled() {
                    return None;
                }
                let (path, semantic, status) = match reason {
                    ResolutionIncompleteReason::Cancelled => {
                        panic!(
                            "operation-local cancellation is not persistable completion evidence"
                        )
                    }
                    ResolutionIncompleteReason::CyclicExpansion(path) => {
                        (Some(keys.path(*path)), None, None)
                    }
                    ResolutionIncompleteReason::InconsistentPrecedence(semantic) => {
                        (None, Some(keys.semantic(*semantic)), None)
                    }
                    ResolutionIncompleteReason::OpenBoundary { semantic, status } => (
                        None,
                        Some(keys.semantic(*semantic)),
                        Some(status.label().to_owned()),
                    ),
                    ResolutionIncompleteReason::UnsupportedSemantic(semantic) => {
                        (None, Some(keys.semantic(*semantic)), None)
                    }
                };
                let reason = PersistedPathCompletionReason {
                    kind: (*reason).kind().label().to_owned(),
                    path,
                    semantic,
                    status,
                };
                assert!(
                    persisted.insert(reason),
                    "lowered completion reasons must be unique after storage-local rebasing"
                );
            }
            assert_eq!(
                persisted.len(),
                reasons.len(),
                "lowered completion reasons must be unique after storage-local rebasing"
            );
            (
                path.completion().kind().label(),
                persisted.into_iter().collect(),
            )
        }
    };
    Some((
        PersistedPartialPathBody {
            start,
            end,
            precedence,
            witness,
            reasons,
        },
        completion_kind,
    ))
}

fn prepare_path_endpoint(
    endpoint: &crate::analyzer::resolution::EndpointSignature,
    keys: &ResolutionLocalKeys,
    cancellation: &CancellationToken,
) -> Option<PersistedPathEndpoint> {
    let mut symbols = Vec::with_capacity(endpoint.symbols().fixed().len());
    for symbol in endpoint.symbols().fixed() {
        if cancellation.is_cancelled() {
            return None;
        }
        let scopes = symbol.scopes().map(|scopes| {
            scopes
                .fixed()
                .iter()
                .map(|node| persisted_path_node(*node, keys))
                .collect::<Vec<_>>()
        });
        symbols.push(PersistedPathSymbol {
            symbol: keys.semantic(symbol.symbol()),
            scopes,
            scope_tail: symbol
                .scopes()
                .and_then(|scopes| scopes.tail())
                .map(|variable| keys.variable(variable)),
        });
    }
    let mut scopes = Vec::with_capacity(endpoint.scopes().fixed().len());
    for node in endpoint.scopes().fixed() {
        if cancellation.is_cancelled() {
            return None;
        }
        scopes.push(persisted_path_node(*node, keys));
    }
    Some(PersistedPathEndpoint {
        symbols,
        scopes,
        scope_tail: endpoint
            .scopes()
            .tail()
            .map(|variable| keys.variable(variable)),
    })
}

fn persisted_path_node(node: BindingNodeId, keys: &ResolutionLocalKeys) -> PersistedPathNode {
    if node == BindingNodeId::universal_root() {
        PersistedPathNode::Boundary {
            key: BindingNodeId::UNIVERSAL_ROOT_BOUNDARY_KEY,
        }
    } else {
        PersistedPathNode::Local {
            key: keys.node(node),
        }
    }
}

fn prepare_gap_families(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    keys: &ResolutionLocalKeys,
    rows: &mut PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> bool {
    let mut fragment = BTreeMap::new();
    let mut enumeration = BTreeMap::new();
    let mut candidates = BTreeMap::new();
    for gap in lowered.lexical().gaps() {
        if cancellation.is_cancelled() {
            return false;
        }
        let key = keys.semantic(gap.id());
        match gap.frontier() {
            LoweringCoverageFrontier::Fragment => {
                assert!(fragment.insert(key, gap).is_none())
            }
            LoweringCoverageFrontier::Enumeration => {
                assert!(enumeration.insert(key, gap).is_none())
            }
            LoweringCoverageFrontier::CandidateInventory { .. }
            | LoweringCoverageFrontier::Candidate { .. } => {
                assert!(candidates.insert(key, gap).is_none())
            }
            LoweringCoverageFrontier::Reference { .. } | LoweringCoverageFrontier::Type { .. } => {}
        }
    }
    for (gap_key, (semantic_key, gap)) in fragment.into_iter().enumerate() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.fragment_gaps.push(serialized_gap_row(
            dense_key(gap_key),
            semantic_key,
            gap,
            lowered,
            keys,
        ));
    }
    for (gap_key, (semantic_key, gap)) in enumeration.into_iter().enumerate() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.reference_enumeration_gaps.push(serialized_gap_row(
            dense_key(gap_key),
            semantic_key,
            gap,
            lowered,
            keys,
        ));
    }
    for (gap_key, (semantic_key, gap)) in candidates.into_iter().enumerate() {
        if cancellation.is_cancelled() {
            return false;
        }
        let gap_key = dense_key(gap_key);
        let (direction, coverage_scope, endpoint, lookup) = match gap.frontier() {
            LoweringCoverageFrontier::CandidateInventory { direction } => {
                (direction, "fragment", None, None)
            }
            LoweringCoverageFrontier::Candidate {
                direction,
                endpoint,
                lookup,
            } => (direction, "endpoint", Some(endpoint), lookup),
            _ => unreachable!(),
        };
        let identity = catalog_identity_at(
            lowered.identities().semantics(),
            gap.id(),
            semantic_key,
            "candidate-gap semantic catalog",
        );
        let endpoint = keys.optional_node_coordinate(endpoint);
        rows.candidate_gaps.push(row![
            candidate_direction_label(direction),
            gap_key,
            identity.digest(),
            coverage_scope,
            endpoint.local_key,
            endpoint.boundary_key,
            lookup.map(|semantic| keys.semantic(semantic)),
            ResolutionCompletionReasonKind::UnsupportedSemantic.label(),
            PreparedResolutionValue::Null,
            keys.semantic(gap.reason_semantic()),
            PreparedResolutionValue::Null,
        ]);
    }
    true
}

fn serialized_gap_row(
    gap_key: i64,
    semantic_key: i64,
    gap: &LoweredCoverageGap,
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    keys: &ResolutionLocalKeys,
) -> PreparedResolutionRow {
    let identity = catalog_identity_at(
        lowered.identities().semantics(),
        gap.id(),
        semantic_key,
        "coverage-gap semantic catalog",
    );
    row![
        gap_key,
        identity.digest(),
        ResolutionCompletionReasonKind::UnsupportedSemantic.label(),
        PreparedResolutionValue::Null,
        keys.semantic(gap.reason_semantic()),
        PreparedResolutionValue::Null,
    ]
}

fn prepare_typed_rows(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    keys: &ResolutionLocalKeys,
    rows: &mut PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> bool {
    let typed = lowered.typed();
    let mut typed_slots = HashSet::default();
    for frontier in typed.frontiers() {
        if cancellation.is_cancelled() {
            return false;
        }
        assert!(
            typed_slots.insert(frontier.slot()),
            "one persisted typed frontier per slot"
        );
        rows.type_frontiers.push(row![
            keys.semantic(frontier.slot()),
            "slot",
            frontier.role().label(),
            PreparedResolutionValue::Null,
        ]);
    }

    let mut synthetic_frontiers = BTreeMap::new();
    let mut type_gaps = BTreeMap::<i64, BTreeMap<i64, &LoweredCoverageGap>>::new();
    for gap in lowered.lexical().gaps() {
        if cancellation.is_cancelled() {
            return false;
        }
        let LoweringCoverageFrontier::Type { frontier } = gap.frontier() else {
            continue;
        };
        let frontier_key = keys.semantic(frontier);
        assert!(
            type_gaps
                .entry(frontier_key)
                .or_default()
                .insert(keys.semantic(gap.id()), gap)
                .is_none(),
            "one type frontier cannot repeat a persisted coverage-gap identity"
        );
        if typed_slots.contains(&frontier) {
            continue;
        }
        let identity = catalog_identity_at(
            lowered.identities().semantics(),
            frontier,
            frontier_key,
            "synthetic-frontier semantic catalog",
        );
        assert_eq!(
            identity.space(),
            ResolutionSemanticIdentitySpace::FragmentLocal,
            "a synthetic type frontier must remain fragment-local"
        );
        if let Some((previous_frontier, previous_site)) =
            synthetic_frontiers.insert(frontier_key, (frontier, gap.site()))
        {
            assert_eq!(previous_frontier, frontier);
            assert_eq!(
                previous_site,
                gap.site(),
                "one synthetic frontier has one source site"
            );
        }
    }
    for (frontier_key, (_, source_site)) in synthetic_frontiers {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.type_frontiers.push(row![
            frontier_key,
            "synthetic_site",
            PreparedResolutionValue::Null,
            i64::from(source_site.get()),
        ]);
    }
    for (frontier_key, gaps) in type_gaps {
        for (gap_key, (semantic_key, gap)) in gaps.into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return false;
            }
            let identity = catalog_identity_at(
                lowered.identities().semantics(),
                gap.id(),
                semantic_key,
                "type-gap semantic catalog",
            );
            rows.type_frontier_gaps.push(row![
                frontier_key,
                dense_key(gap_key),
                identity.digest(),
                ResolutionCompletionReasonKind::UnsupportedSemantic.label(),
                PreparedResolutionValue::Null,
                keys.semantic(gap.reason_semantic()),
                PreparedResolutionValue::Null,
                i64::from(gap.site().get()),
                gap.origin().kind().label(),
            ]);
        }
    }

    for transfer in typed.transfers() {
        if cancellation.is_cancelled() {
            return false;
        }
        let rule = transfer.rule();
        let (value_transform, runtime_addressable) = match rule.value_transform() {
            TypeTransferValueTransform::Preserve => ("preserve", PreparedResolutionValue::Null),
            TypeTransferValueTransform::ToRuntime { addressable } => {
                ("to_runtime", addressable.into())
            }
            TypeTransferValueTransform::ToNoValue => ("to_no_value", PreparedResolutionValue::Null),
        };
        let Some((completion_kind, completion_reasons)) =
            serialized_completion(rule.completion(), keys, cancellation)
        else {
            return false;
        };
        let rule_key = keys.semantic(rule.semantic());
        rows.type_transfer_rules.push(row![
            rule_key,
            keys.semantic(transfer.source_slot()),
            keys.semantic(rule.target_slot()),
            transfer.kind().label(),
            rule.indirection_delta(),
            value_transform,
            runtime_addressable,
            completion_kind,
            usize_i64(completion_reasons.len()),
        ]);
        for (position, reason) in completion_reasons.into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return false;
            }
            let mut values = Vec::with_capacity(6);
            values.push(rule_key.into());
            values.push(usize_i64(position).into());
            values.extend(reason);
            rows.type_transfer_rule_completion_reasons
                .push(PreparedResolutionRow::new(values));
        }
    }

    for seed in typed.intrinsic_seeds() {
        if cancellation.is_cancelled() {
            return false;
        }
        let frontier = seed.frontier();
        let frontier_key = keys.semantic(frontier.slot());
        let mut possible_values = BTreeSet::new();
        for value in frontier.possible_values() {
            if cancellation.is_cancelled() {
                return false;
            }
            let (category, ty, addressable) = match *value {
                ResolutionSlotValue::TypeObject(ty) => {
                    ("type_object", ty, PreparedResolutionValue::Null)
                }
                ResolutionSlotValue::Runtime { ty, addressable } => {
                    ("runtime", ty, addressable.into())
                }
            };
            assert!(
                possible_values.insert(
                    vec![
                        category.into(),
                        keys.semantic(ty.identity()).into(),
                        ty.indirection().into(),
                        addressable,
                    ]
                    .into_boxed_slice()
                ),
                "intrinsic values must remain unique after storage-local rebasing"
            );
        }
        let Some((completion_kind, completion_reasons)) =
            serialized_completion(frontier.completion(), keys, cancellation)
        else {
            return false;
        };
        rows.intrinsic_type_seeds.push(row![
            frontier_key,
            seed.kind().label(),
            completion_kind,
            usize_i64(possible_values.len()),
            usize_i64(completion_reasons.len()),
        ]);
        for (position, value) in possible_values.into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return false;
            }
            let mut values = Vec::with_capacity(6);
            values.push(frontier_key.into());
            values.push(usize_i64(position).into());
            values.extend(value);
            rows.intrinsic_type_seed_values
                .push(PreparedResolutionRow::new(values));
        }
        for (position, reason) in completion_reasons.into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return false;
            }
            let mut values = Vec::with_capacity(6);
            values.push(frontier_key.into());
            values.push(usize_i64(position).into());
            values.extend(reason);
            rows.intrinsic_type_seed_completion_reasons
                .push(PreparedResolutionRow::new(values));
        }
    }

    for projection in typed.projections() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.binding_projections.push(row![
            keys.semantic(projection.reference()),
            keys.semantic(projection.output_slot()),
            projection.kind().label(),
        ]);
    }
    for route in typed.qualified_routes() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.qualified_seeded_routes.push(row![
            keys.semantic(route.reference()),
            route.precedence_ordinal(),
            keys.semantic(route.qualifier_slot()),
            keys.semantic(route.lookup()),
            qualified_namespace_label(route.namespace()),
            keys.semantic(route.projection_output_slot()),
            route.projection_kind().label(),
            keys.semantic(route.coarse_gap_reason()),
        ]);
    }
    for property in typed.declaration_types() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.declaration_type_properties.push(row![
            keys.semantic(property.definition()),
            property.role().label(),
            keys.semantic(property.slot()),
        ]);
    }
    for property in typed.declaration_visibilities() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.declaration_visibility_properties.push(row![
            keys.semantic(property.definition()),
            property.visibility().label(),
        ]);
    }
    for property in typed.member_scopes() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.member_scope_properties.push(row![
            keys.semantic(property.definition()),
            keys.node(property.scope_head()),
        ]);
    }
    for property in typed.member_owners() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.member_owner_properties.push(row![
            keys.semantic(property.definition()),
            keys.semantic(property.owner_definition()),
            keys.node(property.owner_scope_head()),
            property.kind().label(),
            property.access().label(),
            property.qualifier_compatibility().label(),
        ]);
    }
    for property in typed.construction_requirements() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.construction_requirement_properties.push(row![
            keys.semantic(property.definition()),
            property.kind().label(),
            keys.semantic(property.required_owner_definition()),
        ]);
    }
    for property in typed.supertypes() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.supertype_properties.push(row![
            keys.semantic(property.definition()),
            property.kind().label(),
            keys.semantic(property.reference()),
            keys.semantic(property.frontier()),
        ]);
    }
    for gap in typed.property_gaps() {
        if cancellation.is_cancelled() {
            return false;
        }
        rows.definition_property_gaps.push(row![
            keys.semantic(gap.definition()),
            keys.semantic(gap.reason_semantic()),
            keys.semantic(gap.frontier()),
            i64::from(gap.source_site().get()),
            definition_gap_kind_label(gap.kind()),
        ]);
    }
    for obligation in typed.call_obligations() {
        if cancellation.is_cancelled() {
            return false;
        }
        let call_key = keys.semantic(obligation.call());
        let Some((completion_kind, completion_reasons)) =
            serialized_completion(obligation.completion(), keys, cancellation)
        else {
            return false;
        };
        rows.call_applicability_obligations.push(row![
            call_key,
            keys.semantic(obligation.callee_reference()),
            obligation.receiver_slot().map(|slot| keys.semantic(slot)),
            keys.semantic(obligation.result_slot()),
            obligation.explicit_type_argument_count(),
            keys.semantic(obligation.applicability_reason()),
            completion_kind,
            usize_i64(obligation.argument_slots().len()),
            usize_i64(completion_reasons.len()),
        ]);
        for (position, argument) in obligation.argument_slots().iter().enumerate() {
            if cancellation.is_cancelled() {
                return false;
            }
            rows.call_applicability_arguments.push(row![
                call_key,
                usize_i64(position),
                keys.semantic(*argument),
            ]);
        }
        for (position, reason) in completion_reasons.into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return false;
            }
            let mut values = Vec::with_capacity(6);
            values.push(call_key.into());
            values.push(usize_i64(position).into());
            values.extend(reason);
            rows.call_applicability_completion_reasons
                .push(PreparedResolutionRow::new(values));
        }
        for &rule in obligation.eligible_rules() {
            rows.engine_rule_eligibilities
                .push(row![call_key, rule.label()]);
        }
    }
    for signature in typed.callable_signatures() {
        if cancellation.is_cancelled() {
            return false;
        }
        let definition_key = keys.semantic(signature.definition());
        let Some((completion_kind, completion_reasons)) =
            serialized_completion(signature.completion(), keys, cancellation)
        else {
            return false;
        };
        rows.callable_signature_properties.push(row![
            definition_key,
            signature.type_parameter_count(),
            completion_kind,
            usize_i64(signature.parameters().len()),
            usize_i64(completion_reasons.len()),
        ]);
        for parameter in signature.parameters() {
            if cancellation.is_cancelled() {
                return false;
            }
            rows.callable_signature_parameters.push(row![
                definition_key,
                parameter.ordinal(),
                keys.semantic(parameter.definition()),
                keys.semantic(parameter.slot()),
                parameter.repeated(),
            ]);
        }
        for (position, reason) in completion_reasons.into_iter().enumerate() {
            if cancellation.is_cancelled() {
                return false;
            }
            let mut values = Vec::with_capacity(6);
            values.push(definition_key.into());
            values.push(usize_i64(position).into());
            values.extend(reason);
            rows.callable_signature_completion_reasons
                .push(PreparedResolutionRow::new(values));
        }
    }
    true
}

fn serialized_completion(
    completion: &ResolutionCompletion,
    keys: &ResolutionLocalKeys,
    cancellation: &CancellationToken,
) -> Option<(&'static str, Vec<Box<[PreparedResolutionValue]>>)> {
    match completion {
        ResolutionCompletion::Complete => Some((completion.kind().label(), Vec::new())),
        ResolutionCompletion::Incomplete(reasons) => {
            let mut canonical = BTreeSet::new();
            for reason in reasons.iter() {
                if cancellation.is_cancelled() {
                    return None;
                }
                assert!(
                    canonical.insert(serialized_completion_reason(*reason, keys)),
                    "lowered completion reasons must be unique after storage-local rebasing"
                );
            }
            let serialized = canonical.into_iter().collect::<Vec<_>>();
            assert_eq!(
                serialized.len(),
                reasons.len(),
                "lowered completion reasons must be unique after storage-local rebasing"
            );
            Some((completion.kind().label(), serialized))
        }
    }
}

fn serialized_completion_reason(
    reason: ResolutionIncompleteReason,
    keys: &ResolutionLocalKeys,
) -> Box<[PreparedResolutionValue]> {
    match reason {
        ResolutionIncompleteReason::Cancelled => {
            panic!("operation-local cancellation is not persistable completion evidence")
        }
        ResolutionIncompleteReason::CyclicExpansion(path) => vec![
            ResolutionCompletionReasonKind::CyclicExpansion
                .label()
                .into(),
            keys.path(path).into(),
            PreparedResolutionValue::Null,
            PreparedResolutionValue::Null,
        ]
        .into_boxed_slice(),
        ResolutionIncompleteReason::InconsistentPrecedence(semantic) => vec![
            ResolutionCompletionReasonKind::InconsistentPrecedence
                .label()
                .into(),
            PreparedResolutionValue::Null,
            keys.semantic(semantic).into(),
            PreparedResolutionValue::Null,
        ]
        .into_boxed_slice(),
        ResolutionIncompleteReason::OpenBoundary { semantic, status } => vec![
            ResolutionCompletionReasonKind::OpenBoundary.label().into(),
            PreparedResolutionValue::Null,
            keys.semantic(semantic).into(),
            status.label().into(),
        ]
        .into_boxed_slice(),
        ResolutionIncompleteReason::UnsupportedSemantic(semantic) => vec![
            ResolutionCompletionReasonKind::UnsupportedSemantic
                .label()
                .into(),
            PreparedResolutionValue::Null,
            keys.semantic(semantic).into(),
            PreparedResolutionValue::Null,
        ]
        .into_boxed_slice(),
    }
}

fn dense_key(index: usize) -> i64 {
    i64::try_from(index).expect("resolution family length fits SQLite INTEGER")
}

fn usize_i64(value: usize) -> i64 {
    i64::try_from(value).expect("resolution row count fits SQLite INTEGER")
}

const fn qualified_namespace_label(namespace: ResolutionNamespace) -> &'static str {
    if matches!(namespace, ResolutionNamespace::TypeOrValue) {
        panic!("a persisted qualified route must have an exact namespace")
    }
    namespace.label()
}

const fn semantic_role_label(role: LoweredSemanticRole) -> &'static str {
    match role {
        LoweredSemanticRole::Reference => "reference",
        LoweredSemanticRole::Definition => "definition",
    }
}

const fn candidate_direction_label(direction: LoweredCandidateDirection) -> &'static str {
    match direction {
        LoweredCandidateDirection::Forward => "forward",
        LoweredCandidateDirection::Reverse => "reverse",
    }
}

const fn definition_gap_kind_label(kind: ResolutionGapKind) -> &'static str {
    match kind {
        ResolutionGapKind::ImplicitConstructor
        | ResolutionGapKind::UnsupportedHierarchyTraversal
        | ResolutionGapKind::UnsupportedVisibility => kind.label(),
        _ => panic!("definition property gap kind is not persistable"),
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use brokk_bifrost_core::analyzer::resolution_facts::{
        FileResolutionFacts, ResolutionGapFact, ResolutionScopeFact, ResolutionScopeId,
        ResolutionScopeKind, ResolutionSiteFact, ResolutionSiteId, ResolutionSiteKind,
    };

    use crate::analyzer::resolution::{
        BindingFragmentId, lower_resolution_facts_with_identity_catalog,
        normalized_java_bundle_facts_for_test,
    };

    use super::*;

    fn gap_facts() -> FileResolutionFacts {
        FileResolutionFacts {
            scopes: vec![ResolutionScopeFact {
                id: ResolutionScopeId::new(0),
                parent: None,
                owner: None,
                kind: ResolutionScopeKind::CompilationUnit,
                start_byte: 0,
                end_byte: 100,
            }],
            sites: vec![ResolutionSiteFact {
                id: ResolutionSiteId::new(0),
                scope: ResolutionScopeId::new(0),
                kind: ResolutionSiteKind::UnsupportedExpression,
                start_byte: 20,
                end_byte: 21,
            }],
            gaps: vec![ResolutionGapFact {
                site: ResolutionSiteId::new(0),
                kind: ResolutionGapKind::UnsupportedExpression,
            }],
            ..FileResolutionFacts::default()
        }
    }

    fn prepared(
        fragment_byte: u8,
        cancellation: &CancellationToken,
    ) -> ResolutionInteriorPreparation {
        prepare_resolution_bundle(
            BindingFragmentId::from_digest([fragment_byte; 32]),
            Language::Rust,
            &gap_facts(),
            &HashMap::default(),
            cancellation,
        )
    }

    #[test]
    fn preparation_rebases_mounted_ids_to_equal_storage_local_bundles() {
        let ResolutionInteriorPreparation::Prepared(first) =
            prepared(1, &CancellationToken::default())
        else {
            panic!("uncancelled preparation must finish")
        };
        let ResolutionInteriorPreparation::Prepared(second) =
            prepared(2, &CancellationToken::default())
        else {
            panic!("uncancelled preparation must finish")
        };

        assert_eq!(first.semantic_language(), Language::Rust);
        assert_eq!(first, second);
        let counts = first.family_counts().collect::<HashMap<_, _>>();
        assert_eq!(
            counts["reference_enumeration_impacts"], 0,
            "enumeration impacts are explicit-zero"
        );
        assert!(
            counts["type_frontiers"] > 0,
            "the site type gap needs a frontier row"
        );
        assert!(
            counts["type_frontier_gaps"] > 0,
            "the site type gap needs a typed gap row"
        );
    }

    #[test]
    fn normalized_java_bundle_is_storage_local_across_a_to_b_to_a() {
        let facts = normalized_java_bundle_facts_for_test();
        assert_normalized_fixture_premises(&facts);
        let cancellation = CancellationToken::default();
        let bundles = [1_u8, 2, 1].map(|fragment_byte| {
            assert!(
                facts.definition_units.is_empty(),
                "normalized fixture has no unit crosswalk"
            );
            let ResolutionInteriorPreparation::Prepared(bundle) = prepare_resolution_bundle(
                BindingFragmentId::from_digest([fragment_byte; 32]),
                Language::Java,
                &facts,
                &HashMap::default(),
                &cancellation,
            ) else {
                panic!("uncancelled normalized Java preparation must finish")
            };
            *bundle
        });

        assert_eq!(bundles[0], bundles[1]);
        assert_eq!(bundles[0], bundles[2]);
        assert_eq!(bundles[0].producer_epoch(), "resolution-bundle-java-v11");
        assert!(
            bundles[0]
                .family_counts()
                .find(|(name, _)| *name == "partial_paths")
                .unwrap()
                .1
                > 1
        );
    }

    #[test]
    fn parsed_java_bundle_is_storage_local_across_a_to_b_to_a() {
        let facts = crate::analyzer::resolution::rich_java_resolution_facts_for_test();
        let cancellation = CancellationToken::default();
        let bundles = [1_u8, 2, 1].map(|fragment_byte| {
            assert!(
                facts.definition_units.is_empty(),
                "parser fixture has no native unit crosswalk yet"
            );
            let ResolutionInteriorPreparation::Prepared(bundle) = prepare_resolution_bundle(
                BindingFragmentId::from_digest([fragment_byte; 32]),
                Language::Java,
                &facts,
                &HashMap::default(),
                &cancellation,
            ) else {
                panic!("uncancelled parsed Java preparation must finish")
            };
            *bundle
        });

        assert_eq!(bundles[0], bundles[1]);
        assert_eq!(bundles[0], bundles[2]);
        assert_eq!(bundles[0].producer_epoch(), "resolution-bundle-java-v11");
        assert!(
            bundles[0]
                .family_counts()
                .find(|(name, _)| *name == "partial_paths")
                .unwrap()
                .1
                > 1
        );
    }

    fn assert_normalized_fixture_premises(facts: &FileResolutionFacts) {
        use brokk_bifrost_core::analyzer::resolution_facts::*;
        use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;
        assert_eq!(facts.packages[0].root_scope, ResolutionScopeId::new(0));
        assert_eq!(facts.package_segments[0].name, ResolutionNameId::new(0));
        assert_eq!(facts.names[0].spelling, "acme");
        assert_eq!(facts.root_exports[0].declaration, ResolutionSiteId::new(1));
        let parameter = &facts.binders[2];
        let local = &facts.binders[3];
        assert_eq!(parameter.scope, local.scope);
        assert_eq!(parameter.hoisting, HoistingClass::ScopeWide);
        assert_eq!(local.hoisting, HoistingClass::SourceOrder);
        assert_eq!(facts.identifiers[2].name, facts.identifiers[3].name);
        assert_ne!(parameter.declaration, local.declaration);
        assert!(facts.sites[5].start_byte < local.activation_start);
        assert!(local.activation_start < facts.sites[6].start_byte);
        assert_eq!(facts.scopes[1].owner, Some(ResolutionSiteId::new(1)));
        assert_eq!(facts.scopes[1].kind, ResolutionScopeKind::TypeBody);
        use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
        let supported = facts
            .scopes
            .iter()
            .filter(|scope| scope.kind == ResolutionScopeKind::TypeBody)
            .map(|scope| scope.owner.unwrap())
            .collect::<HashSet<_>>();
        assert_eq!(supported, HashSet::from_iter([ResolutionSiteId::new(1)]));
        assert!(facts.member_owners.is_empty());
        assert_eq!(
            facts.visibility_eligibilities,
            vec![ResolutionVisibilityEligibilityFact {
                declaration: ResolutionSiteId::new(1),
            }]
        );
        assert_eq!(
            facts.declaration_visibilities,
            vec![ResolutionDeclarationVisibilityFact {
                declaration: ResolutionSiteId::new(1),
                visibility: DeclaredVisibility::Public,
            }]
        );
        assert_eq!(
            facts
                .visibility_eligibilities
                .iter()
                .map(|fact| fact.declaration)
                .collect::<HashSet<_>>(),
            supported
        );
        assert_eq!(
            facts
                .declaration_visibilities
                .iter()
                .map(|fact| fact.declaration)
                .collect::<HashSet<_>>(),
            supported
        );
        assert!(
            !facts
                .gaps
                .iter()
                .any(|gap| gap.kind == ResolutionGapKind::UnsupportedVisibility)
        );
        assert_eq!(facts.type_slots[0].site, parameter.declaration);
        assert_eq!(facts.type_slots[1].site, local.declaration);
        assert_eq!(facts.type_slots[2].site, local.declaration);
        for (index, role) in [
            ResolutionTypeSlotRole::DeclaredValue,
            ResolutionTypeSlotRole::DeclaredValue,
            ResolutionTypeSlotRole::AssignmentValue,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                facts.type_slots[index].id,
                ResolutionTypeSlotId::try_from_index(index).unwrap()
            );
            assert_eq!(facts.type_slots[index].role, role);
        }
        assert_eq!(
            facts.declaration_type_slots[0].declaration,
            parameter.declaration
        );
        assert_eq!(
            facts.declaration_type_slots[0].slot,
            ResolutionTypeSlotId::new(0)
        );
        assert_eq!(
            facts.declaration_type_slots[0].role,
            DeclarationTypeRole::Parameter
        );
        assert_eq!(
            facts.declaration_type_slots[1].declaration,
            local.declaration
        );
        assert_eq!(
            facts.declaration_type_slots[1].slot,
            ResolutionTypeSlotId::new(1)
        );
        assert_eq!(
            facts.declaration_type_slots[1].role,
            DeclarationTypeRole::Value
        );
        assert_eq!(facts.type_transfers[0].input, ResolutionTypeSlotId::new(0));
        assert_eq!(facts.type_transfers[0].output, ResolutionTypeSlotId::new(2));
        assert_eq!(
            facts.type_transfers[0].kind,
            ResolutionTypeTransferKind::Assignment
        );
        assert_eq!(
            facts.callable_parameters[0].callable,
            facts.callable_signatures[0].callable
        );
        assert_eq!(
            facts.callable_parameters[0].parameter,
            parameter.declaration
        );
        assert_eq!(
            facts.callable_parameters[0].value_type,
            facts.type_slots[0].id
        );
    }

    #[test]
    fn normalized_java_preparation_preserves_explicit_typed_and_common_relations() {
        let facts = normalized_java_bundle_facts_for_test();
        assert_normalized_fixture_premises(&facts);
        let fragment = BindingFragmentId::from_digest([7; 32]);
        let lowered =
            lower_resolution_facts_with_identity_catalog(fragment, Language::Java, &facts);
        assert_eq!(lowered.common().declared_root_routes.len(), 1);
        assert_eq!(lowered.typed().frontiers().len(), 3);
        assert_eq!(lowered.typed().transfers().len(), 1);
        assert_eq!(lowered.typed().member_scopes().len(), 1);
        assert!(lowered.typed().member_owners().is_empty());
        let visibilities = lowered.typed().declaration_visibilities();
        assert_eq!(visibilities.len(), 1);
        assert_eq!(
            visibilities[0].definition(),
            lowered.typed().member_scopes()[0].definition()
        );
        assert_eq!(
            visibilities[0].visibility(),
            brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility::Public
        );
        assert_eq!(lowered.typed().callable_signatures().len(), 1);
        let signature = &lowered.typed().callable_signatures()[0];
        assert_eq!(signature.parameters().len(), 1);
        assert_eq!(signature.parameters()[0].ordinal(), 0);
        let property = lowered
            .typed()
            .declaration_types()
            .iter()
            .find(|property| property.definition() == signature.parameters()[0].definition())
            .unwrap();
        assert_eq!(property.slot(), signature.parameters()[0].slot());
        assert!(
            facts.definition_units.is_empty(),
            "normalized fixture has no unit crosswalk"
        );
        let ResolutionInteriorPreparation::Prepared(bundle) = prepare_resolution_bundle(
            BindingFragmentId::from_digest([7; 32]),
            Language::Java,
            &facts,
            &HashMap::default(),
            &CancellationToken::default(),
        ) else {
            panic!("uncancelled normalized Java preparation")
        };
        let counts = bundle.family_counts().collect::<HashMap<_, _>>();
        for family in [
            "type_frontiers",
            "type_transfer_rules",
            "member_scope_properties",
            "callable_signature_parameters",
            "declared_root_routes",
        ] {
            assert!(counts[family] > 0, "{family}");
        }
    }

    #[test]
    fn preparation_returns_explicit_cancellation_before_publication() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert!(matches!(
            prepared(1, &cancellation),
            ResolutionInteriorPreparation::Cancelled
        ));
    }

    #[test]
    fn local_keys_are_exact_indexes_into_descriptor_sorted_catalogs() {
        let lowered = lower_resolution_facts_with_identity_catalog(
            BindingFragmentId::from_digest([3; 32]),
            Language::Java,
            &normalized_java_bundle_facts_for_test(),
        );
        let keys = ResolutionLocalKeys::new(&lowered, &CancellationToken::default())
            .expect("uncancelled key construction");
        let catalog = lowered.identities();
        assert!(!catalog.semantics().is_empty());
        assert!(!catalog.nodes().is_empty());
        assert!(!catalog.paths().is_empty());
        assert!(!catalog.stack_variables().is_empty());

        for (index, &(mounted, expected)) in catalog.semantics().iter().enumerate() {
            let key = keys.semantic(mounted);
            assert_eq!(key, dense_key(index));
            assert_eq!(
                catalog_identity_at(catalog.semantics(), mounted, key, "semantic test catalog"),
                expected
            );
        }
        for (index, &(mounted, expected)) in catalog.nodes().iter().enumerate() {
            let key = keys.node(mounted);
            assert_eq!(key, dense_key(index));
            assert_eq!(
                catalog_identity_at(catalog.nodes(), mounted, key, "node test catalog"),
                expected
            );
        }
        for (index, &(mounted, expected)) in catalog.paths().iter().enumerate() {
            let key = keys.path(mounted);
            assert_eq!(key, dense_key(index));
            assert_eq!(
                catalog_identity_at(catalog.paths(), mounted, key, "path test catalog"),
                expected
            );
        }
        for (index, &(mounted, expected)) in catalog.stack_variables().iter().enumerate() {
            let key = keys.variable(mounted);
            assert_eq!(key, dense_key(index));
            assert_eq!(
                catalog_identity_at(
                    catalog.stack_variables(),
                    mounted,
                    key,
                    "stack-variable test catalog",
                ),
                expected
            );
        }

        assert_eq!(
            keys.node_coordinate(BindingNodeId::universal_root()),
            PreparedNodeCoordinate {
                local_key: PreparedResolutionValue::Null,
                boundary_key: BindingNodeId::UNIVERSAL_ROOT_BOUNDARY_KEY.into(),
            }
        );
        let local_node = lowered.lexical().nodes()[0].0;
        assert_eq!(
            keys.node_coordinate(local_node),
            PreparedNodeCoordinate {
                local_key: keys.node(local_node).into(),
                boundary_key: PreparedResolutionValue::Null,
            }
        );
        let unknown = BindingNodeId::hash_bytes(b"unknown-non-root-node");
        assert!(
            catch_unwind(AssertUnwindSafe(|| keys.node_coordinate(unknown))).is_err(),
            "only the exact universal root may bypass the local identity catalog"
        );
    }
    #[test]
    fn parsed_java_local_keys_are_exact_indexes_into_descriptor_sorted_catalogs() {
        let lowered = lower_resolution_facts_with_identity_catalog(
            BindingFragmentId::from_digest([3; 32]),
            Language::Java,
            &crate::analyzer::resolution::rich_java_resolution_facts_for_test(),
        );
        let keys = ResolutionLocalKeys::new(&lowered, &CancellationToken::default())
            .expect("uncancelled key construction");
        let catalog = lowered.identities();
        assert!(!catalog.semantics().is_empty());
        assert!(!catalog.nodes().is_empty());
        assert!(!catalog.paths().is_empty());
        assert!(!catalog.stack_variables().is_empty());

        for (index, &(mounted, expected)) in catalog.semantics().iter().enumerate() {
            let key = keys.semantic(mounted);
            assert_eq!(key, dense_key(index));
            assert_eq!(
                catalog_identity_at(catalog.semantics(), mounted, key, "semantic test catalog"),
                expected
            );
        }
        for (index, &(mounted, expected)) in catalog.nodes().iter().enumerate() {
            let key = keys.node(mounted);
            assert_eq!(key, dense_key(index));
            assert_eq!(
                catalog_identity_at(catalog.nodes(), mounted, key, "node test catalog"),
                expected
            );
        }
        for (index, &(mounted, expected)) in catalog.paths().iter().enumerate() {
            let key = keys.path(mounted);
            assert_eq!(key, dense_key(index));
            assert_eq!(
                catalog_identity_at(catalog.paths(), mounted, key, "path test catalog"),
                expected
            );
        }
        for (index, &(mounted, expected)) in catalog.stack_variables().iter().enumerate() {
            let key = keys.variable(mounted);
            assert_eq!(key, dense_key(index));
            assert_eq!(
                catalog_identity_at(
                    catalog.stack_variables(),
                    mounted,
                    key,
                    "stack-variable test catalog",
                ),
                expected
            );
        }

        assert_eq!(
            keys.node_coordinate(BindingNodeId::universal_root()),
            PreparedNodeCoordinate {
                local_key: PreparedResolutionValue::Null,
                boundary_key: BindingNodeId::UNIVERSAL_ROOT_BOUNDARY_KEY.into(),
            }
        );
        let local_node = lowered.lexical().nodes()[0].0;
        assert_eq!(
            keys.node_coordinate(local_node),
            PreparedNodeCoordinate {
                local_key: keys.node(local_node).into(),
                boundary_key: PreparedResolutionValue::Null,
            }
        );
        let unknown = BindingNodeId::hash_bytes(b"unknown-non-root-node");
        assert!(
            catch_unwind(AssertUnwindSafe(|| keys.node_coordinate(unknown))).is_err(),
            "only the exact universal root may bypass the local identity catalog"
        );
    }
    fn crosswalk_fixture() -> (FileResolutionFacts, CodeUnit) {
        use brokk_bifrost_core::analyzer::ProjectFile;
        use brokk_bifrost_core::analyzer::model::CodeUnitType;
        use brokk_bifrost_core::analyzer::resolution_facts::{
            PositionedIdentifierFact, ResolutionBinderFact, ResolutionBinderKind,
            ResolutionDefinitionUnitFact, ResolutionIdentifierRole, ResolutionNameFact,
            ResolutionNameId,
        };
        use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;
        let unit = CodeUnit::new(
            ProjectFile::new(std::env::temp_dir(), "prepared.rs"),
            CodeUnitType::Class,
            "crate",
            "Model",
        );
        let site = ResolutionSiteId::new(0);
        let scope = ResolutionScopeId::new(0);
        let facts = FileResolutionFacts {
            scopes: vec![ResolutionScopeFact {
                id: scope,
                parent: None,
                owner: None,
                kind: ResolutionScopeKind::CompilationUnit,
                start_byte: 0,
                end_byte: 100,
            }],
            sites: vec![ResolutionSiteFact {
                id: site,
                scope,
                kind: ResolutionSiteKind::TypeDeclaration,
                start_byte: 1,
                end_byte: 6,
            }],
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "Model".into(),
            }],
            identifiers: vec![PositionedIdentifierFact {
                site,
                name: ResolutionNameId::new(0),
                role: ResolutionIdentifierRole::Declaration,
                namespace: ResolutionNamespace::Type,
                qualifier: None,
            }],
            binders: vec![ResolutionBinderFact {
                declaration: site,
                scope,
                kind: ResolutionBinderKind::Type,
                hoisting: HoistingClass::ScopeWide,
                activation_start: 0,
                activation_end: 100,
            }],
            definition_units: vec![ResolutionDefinitionUnitFact {
                declaration: site,
                unit: unit.clone(),
            }],
            ..FileResolutionFacts::default()
        };
        (facts, unit)
    }

    fn extra_unit() -> CodeUnit {
        brokk_bifrost_core::analyzer::CodeUnit::new(
            brokk_bifrost_core::analyzer::ProjectFile::new(std::env::temp_dir(), "other.rs"),
            brokk_bifrost_core::analyzer::model::CodeUnitType::Class,
            "crate",
            "Model",
        )
    }

    #[test]
    fn prepared_crosswalk_preserves_exact_sparse_owner_keys_and_fragment_invariance() {
        let (facts, unit) = crosswalk_fixture();
        let map = HashMap::from_iter([(unit.clone(), 41), (extra_unit(), 900)]);
        let token = CancellationToken::default();
        let make = |fragment, keys| {
            let ResolutionInteriorPreparation::Prepared(bundle) = prepare_resolution_bundle(
                BindingFragmentId::from_digest([fragment; 32]),
                Language::Rust,
                &facts,
                keys,
                &token,
            ) else {
                panic!("uncancelled preparation")
            };
            bundle
        };
        let first = make(1, &map);
        assert_eq!(first, make(2, &map));
        let counts = first.family_counts().collect::<HashMap<_, _>>();
        assert_eq!(counts["definition_unit_crosswalks"], 1);
        // A changed caller assignment must affect content identity, never be renumbered away.
        let changed = HashMap::from_iter([(unit, 42), (extra_unit(), 900)]);
        assert_ne!(first.interior_digest(), make(1, &changed).interior_digest());
        // Inspect the actual normalized crosswalk produced with the same key map.
        let lowered = lower_resolution_facts_with_identity_catalog(
            BindingFragmentId::from_digest([1; 32]),
            Language::Rust,
            &facts,
        );
        let keys = ResolutionLocalKeys::new(&lowered, &token).unwrap();
        let mut rows = PreparedResolutionBundleRows::default();
        assert!(prepare_common_rows(
            &lowered, &keys, &map, &mut rows, &token
        ));
        assert_eq!(
            rows.definition_unit_crosswalks,
            vec![row![
                keys.semantic(lowered.common().definition_unit_crosswalks[0].definition),
                41_i64
            ]]
        );
    }

    #[test]
    fn invalid_unit_maps_fail_at_the_public_boundary() {
        let (facts, unit) = crosswalk_fixture();
        let maps = [
            HashMap::default(),
            HashMap::from_iter([(extra_unit(), 41)]),
            HashMap::from_iter([(unit.clone(), -1)]),
            HashMap::from_iter([(unit.clone(), 41), (extra_unit(), 41)]),
            HashMap::from_iter([(unit, 41), (extra_unit(), -1)]),
        ];
        for map in maps {
            assert!(
                catch_unwind(AssertUnwindSafe(|| prepare_resolution_bundle(
                    BindingFragmentId::from_digest([1; 32]),
                    Language::Rust,
                    &facts,
                    &map,
                    &CancellationToken::default()
                )))
                .is_err(),
                "accepted invalid map: {map:?}"
            );
        }
    }

    #[test]
    fn cancellation_during_unit_map_validation_returns_no_bundle() {
        let (facts, unit) = crosswalk_fixture();
        let map = HashMap::from_iter([(unit, 41), (extra_unit(), 900)]);
        let cancellation = CancellationToken::cancel_after_checks_for_test(2);
        assert!(matches!(
            prepare_resolution_bundle(
                BindingFragmentId::from_digest([1; 32]),
                Language::Rust,
                &facts,
                &map,
                &cancellation
            ),
            ResolutionInteriorPreparation::Cancelled
        ));
        assert!(cancellation.is_cancelled());
    }
}
