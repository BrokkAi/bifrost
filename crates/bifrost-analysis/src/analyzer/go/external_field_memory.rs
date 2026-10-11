//! Query-local field state for exact activated Go declarations.
//!
//! The public bridge starts from a retained root procedure and call argument.
//! It derives a bounded complete route set, binds the selected source
//! declaration to the exact activated artifact, and replays only those routes.
//! It does not establish callback invocation or retain workspace-sized state.

use super::package_identity::GoOverlayPackages;
use super::{GoOuterTypeShape, GoStructFieldIdentity};
use crate::CancellationToken;
use crate::analyzer::semantic::{
    CallSiteHandle, ControlEdgeKind, MemoryLocationKind, MemoryValueCopy, ProcedureHandle,
    ProgramPointHandle, SemanticEffect, SemanticLocator, SemanticValueKind, TransferKind,
    ValueFlowKind, ValueHandle, ValueId,
};
use crate::analyzer::semantic_model::{
    ExactArtifact, SemanticModelCompleteness, SemanticModelOverlay, SemanticModelProof,
    SemanticModelSymbol,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoExternalFieldGap {
    DeclarationUnresolved,
    ArtifactUnbound,
    StorageUnknown,
    Cancelled,
    BudgetExhausted,
    ValueOutsideProcedure,
    FieldUninitialized,
    AliasedDestination,
    SourceStateUnknown,
    PointOutsideProcedure,
    RouteNotFromEntry,
    RouteDiscontinuous,
    RouteRepeatedPoint,
    RouteEvidenceIncomplete,
    InitializerUnavailable,
    FieldLayoutIncomplete,
    EffectiveStateIncomplete,
    RouteSetIncomplete,
}

/// A borrowed declaration bound to the exact activated model and source bytes.
/// Location and full provenance remain on the selected symbol, not a fabricated
/// local anchor. Equality includes the active publication and pack record.
#[derive(Debug, Clone, Copy)]
pub struct GoExternalField<'a> {
    symbol: &'a SemanticModelSymbol,
    artifact_sha256: &'a str,
    copy: MemoryValueCopy,
}

/// A complete source/model crosswalk minted only by the exact artifact query.
/// The type is deliberately private: callers cannot claim complete aggregate
/// state by supplying a same-length list of rows.
#[derive(Debug, Clone)]
struct BoundGoExternalFieldLayout<'a> {
    owner: String,
    field_index: usize,
    fields: Box<[BoundGoExternalField<'a>]>,
}

#[derive(Debug, Clone)]
struct BoundGoExternalField<'a> {
    source: GoStructFieldIdentity,
    field: GoExternalField<'a>,
}

impl<'a> BoundGoExternalFieldLayout<'a> {
    fn field_named(&self, name: &str) -> Option<&BoundGoExternalField<'a>> {
        let mut selected = None;
        for field in &self.fields {
            if field.field.symbol().name == name {
                if selected.is_some() {
                    return None;
                }
                selected = Some(field);
            }
        }
        selected
    }

    fn field_for_source(
        &self,
        source: &GoStructFieldIdentity,
    ) -> Option<&BoundGoExternalField<'a>> {
        self.fields.iter().find(|field| field.source == *source)
    }
}

impl GoExternalField<'_> {
    pub fn symbol(&self) -> &SemanticModelSymbol {
        self.symbol
    }
    pub fn artifact_sha256(&self) -> &str {
        self.artifact_sha256
    }
    pub fn value_copy(&self) -> MemoryValueCopy {
        self.copy
    }

    /// Refine a model field with its exact selected-artifact source shape.
    ///
    /// In particular, a named Go function type is represented by a `Declared`
    /// model reference whose alias structure is intentionally not retained.
    /// Only the AST-backed source shape may recover that fact. An incomplete
    /// source shape never upgrades an unknown field to a reference.
    fn with_source_shape(self, source: &GoStructFieldIdentity) -> Result<Self, GoExternalFieldGap> {
        if source.embedded
            || source.name_anchors.len() != 1
            || source.name_anchors[0].text != self.symbol.name
        {
            return Err(GoExternalFieldGap::DeclarationUnresolved);
        }
        let source_copy = super::package_identity::go_field_value_copy_from_source(source);
        let copy = match &source.outer_type_shape {
            GoOuterTypeShape::Unknown { .. } => {
                return Err(GoExternalFieldGap::FieldLayoutIncomplete);
            }
            GoOuterTypeShape::Function(_) => MemoryValueCopy::Reference,
            GoOuterTypeShape::Other { .. } if self.copy != MemoryValueCopy::Unknown => self.copy,
            GoOuterTypeShape::Other { .. } => source_copy,
        };
        Ok(Self { copy, ..self })
    }
}

impl PartialEq for GoExternalField<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.artifact_sha256 == other.artifact_sha256
            && self.symbol.id == other.symbol.id
            && self.symbol.provenance.active_model_set_hash
                == other.symbol.provenance.active_model_set_hash
            && self.symbol.provenance.pack_digest == other.symbol.provenance.pack_digest
            && self.symbol.provenance.record_id == other.symbol.provenance.record_id
    }
}
impl Eq for GoExternalField<'_> {}

/// Resolve a field through the shared exact concrete-receiver resolver.
/// `owner` must come from the structured import/type binder. A matching name
/// does not establish source applicability: the activated artifact must match.
pub fn resolve_go_external_field<'a>(
    overlay: &'a SemanticModelOverlay,
    owner: &str,
    member: &str,
    artifact: &'a ExactArtifact,
) -> Result<GoExternalField<'a>, GoExternalFieldGap> {
    let artifact_sha256 = artifact.sha256();
    let packages = GoOverlayPackages::new(Some(overlay));
    let owner_symbol = packages
        .unique_symbol(owner)
        .ok_or(GoExternalFieldGap::DeclarationUnresolved)?;
    let field = packages
        .concrete_receiver_field(owner, member)
        .ok_or_else(|| {
            if owner_symbol.provenance.completeness == SemanticModelCompleteness::Partial {
                GoExternalFieldGap::EffectiveStateIncomplete
            } else {
                GoExternalFieldGap::DeclarationUnresolved
            }
        })?;
    let owner = owner_symbol;
    if owner.provenance.ambiguous
        || owner.provenance.proof != SemanticModelProof::ExactArtifact
        || field.provenance.active_model_set_hash != overlay.active_model_set_hash()
        || owner.provenance.active_model_set_hash != field.provenance.active_model_set_hash
        || owner.provenance.pack_digest != field.provenance.pack_digest
        || owner
            .provenance
            .activation
            .matched_evidence
            .artifact_sha256
            .as_deref()
            != Some(artifact_sha256)
        || field.provenance.proof != SemanticModelProof::ExactArtifact
        || field.provenance.ambiguous
        || artifact_sha256.is_empty()
        || field
            .provenance
            .activation
            .matched_evidence
            .artifact_sha256
            .as_deref()
            != Some(artifact_sha256)
    {
        return Err(GoExternalFieldGap::ArtifactUnbound);
    }
    // Classification is supplied by the same declaration resolver rather than
    // by signature text or by assuming imported fields are references.
    let copy = packages.concrete_receiver_field_value_copy(&owner.qualified_name, member);
    Ok(GoExternalField {
        symbol: field,
        artifact_sha256,
        copy,
    })
}

/// A bounded, source-materialization-scoped CFG route. This certifies topology
/// and retained edge evidence only; it does not certify branch feasibility,
/// path exhaustiveness, heap singleton identity, or source-to-field binding.
/// Repeated points are refused: a static allocation ID cannot stand for one
/// fresh object across several loop iterations without heap refinement.
#[derive(Debug)]
pub struct GoFieldReplayRoute<'a> {
    procedure: &'a ProcedureHandle,
    points: Vec<ProgramPointHandle>,
}

impl<'a> GoFieldReplayRoute<'a> {
    pub fn validate(
        procedure: &'a ProcedureHandle,
        points: &'a [ProgramPointHandle],
        max_work: usize,
        cancellation: &CancellationToken,
    ) -> Result<Self, GoExternalFieldGap> {
        let mut remaining = max_work;
        let mut seen = std::collections::HashSet::new();
        let mut previous = None;
        for point in points {
            charge_route_work(&mut remaining, cancellation)?;
            if point.procedure() != procedure {
                return Err(GoExternalFieldGap::PointOutsideProcedure);
            }
            if !seen.insert(point.id()) {
                return Err(GoExternalFieldGap::RouteRepeatedPoint);
            }
            if let Some(previous) = previous {
                let mut matching = None;
                for (_, edge) in procedure.semantics().successor_edges(previous) {
                    charge_route_work(&mut remaining, cancellation)?;
                    if edge.target_point == point.id() {
                        if matching.is_some() || edge.kind != ControlEdgeKind::Normal {
                            // Conditional, cleanup, async, exceptional and loop
                            // routes need their own semantic transfer proof.
                            return Err(GoExternalFieldGap::RouteEvidenceIncomplete);
                        }
                        matching = Some(edge);
                    }
                }
                let edge = matching.ok_or(GoExternalFieldGap::RouteDiscontinuous)?;
                let evidence = procedure
                    .semantics()
                    .evidence_row(edge.evidence)
                    .expect("validated CFG evidence row");
                if !evidence
                    .proof
                    .establishes_complete_evidence(&evidence.completeness)
                {
                    return Err(GoExternalFieldGap::RouteEvidenceIncomplete);
                }
            } else if point.id() != procedure.semantics().entry_point() {
                return Err(GoExternalFieldGap::RouteNotFromEntry);
            }
            previous = Some(point.id());
        }
        charge_route_work(&mut remaining, cancellation)?;
        if previous.is_none() {
            return Err(GoExternalFieldGap::RouteNotFromEntry);
        }
        Ok(Self {
            procedure,
            points: points.to_vec(),
        })
    }

    /// Recover an initializer from the retained event, never from a caller's
    /// freely constructed object/value IDs. The result remains an operand
    /// relation until the selector's AST/type owner and heap identity are proven.
    pub fn initializer_at(
        &self,
        route_index: usize,
        event_index: usize,
    ) -> Result<GoAggregateOperand<'a>, GoExternalFieldGap> {
        let point = self
            .points
            .get(route_index)
            .ok_or(GoExternalFieldGap::InitializerUnavailable)?;
        let event = self
            .procedure
            .semantics()
            .point(point.id())
            .expect("route points belong to validated procedure")
            .events
            .get(event_index)
            .ok_or(GoExternalFieldGap::InitializerUnavailable)?;
        let SemanticEffect::AggregateInitializer {
            aggregate,
            selector,
            value,
        } = &event.effect
        else {
            return Err(GoExternalFieldGap::InitializerUnavailable);
        };
        let evidence = self
            .procedure
            .semantics()
            .evidence_row(event.evidence)
            .expect("validated initializer evidence");
        if !evidence
            .proof
            .establishes_complete_evidence(&evidence.completeness)
        {
            return Err(GoExternalFieldGap::RouteEvidenceIncomplete);
        }
        Ok(GoAggregateOperand {
            aggregate: self
                .procedure
                .value_handle(*aggregate)
                .expect("validated initializer aggregate"),
            value: self
                .procedure
                .value_handle(*value)
                .expect("validated initializer operand"),
            selector,
            point: point.clone(),
            event_index,
        })
    }

    pub fn procedure(&self) -> &ProcedureHandle {
        self.procedure
    }

    pub fn points(&self) -> &[ProgramPointHandle] {
        &self.points
    }

    fn verified(procedure: &'a ProcedureHandle, points: Vec<ProgramPointHandle>) -> Self {
        Self { procedure, points }
    }
}

/// One producer-authored aggregate operand on a validated CFG route. Private
/// fields prevent manufacturing a relation from matching source spellings.
#[derive(Debug)]
pub struct GoAggregateOperand<'a> {
    aggregate: ValueHandle,
    value: ValueHandle,
    selector: &'a SemanticLocator,
    point: ProgramPointHandle,
    event_index: usize,
}

impl GoAggregateOperand<'_> {
    pub fn aggregate(&self) -> &ValueHandle {
        &self.aggregate
    }
    pub fn value(&self) -> &ValueHandle {
        &self.value
    }
    pub fn selector(&self) -> &SemanticLocator {
        self.selector
    }
    pub fn point(&self) -> &ProgramPointHandle {
        &self.point
    }
    pub fn event_index(&self) -> usize {
        self.event_index
    }
}

/// Source correspondence for one retained operand. It identifies syntax, not
/// an imported owner or a heap field. The caller must still run the structured
/// import/type binder and exact declaration crosswalk before replay.
#[derive(Debug, Clone)]
pub enum GoAggregateSourceBinding {
    Bound {
        file: crate::analyzer::ProjectFile,
        literal: super::GoSourceByteRange,
        type_syntax: super::GoSourceByteRange,
        member: String,
        /// Structured resolver candidate; exact overlay/artifact binding is still required.
        owner: Option<String>,
    },
    Incomplete(GoExternalFieldGap),
}

/// Validate against the exact current source snapshot of the owning procedure.
/// No caller-supplied source string can bypass the artifact validity check.
pub fn bind_go_aggregate_operand_source(
    workspace: &crate::analyzer::WorkspaceAnalyzer,
    operand: &GoAggregateOperand<'_>,
    max_source_bytes: usize,
    max_nodes: usize,
    cancellation: &CancellationToken,
) -> Result<GoAggregateSourceBinding, crate::analyzer::semantic::SemanticProviderError> {
    use crate::analyzer::semantic::workspace_oracle::exact_source_for_procedure;
    let incomplete = |gap| GoAggregateSourceBinding::Incomplete(gap);
    if cancellation.is_cancelled() {
        return Ok(incomplete(GoExternalFieldGap::Cancelled));
    }
    let procedure = operand.aggregate.procedure();
    if procedure.artifact().key().language()
        != crate::analyzer::LanguageDialect::Standard(crate::analyzer::Language::Go)
    {
        return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
    }
    let Some((file, source)) =
        exact_source_for_procedure(workspace, procedure, max_source_bytes.min(1024 * 1024))?
    else {
        return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
    };
    let Some(tree) =
        brokk_bifrost_go::parse::parse_go_with_cancellation(&source, Some(cancellation))
    else {
        return Ok(incomplete(if cancellation.is_cancelled() {
            GoExternalFieldGap::Cancelled
        } else {
            GoExternalFieldGap::SourceStateUnknown
        }));
    };
    if tree.root_node().has_error() {
        return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
    }
    if operand.selector.mount() != procedure.artifact().key().mount()
        || operand.selector.language() != procedure.artifact().key().language()
        || !operand
            .selector
            .belongs_to_procedure(procedure.semantics().locator())
    {
        return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
    }
    let selector_span = operand.selector.anchor().span();
    let mut remaining = max_nodes;
    let mut stack = vec![tree.root_node()];
    let mut selected = None;
    while let Some(node) = stack.pop() {
        if let Err(gap) = charge_route_work(&mut remaining, cancellation) {
            return Ok(incomplete(gap));
        }
        if matches!(node.kind(), "identifier" | "field_identifier")
            && node.start_byte() == selector_span.start_byte() as usize
            && node.end_byte() == selector_span.end_byte() as usize
            && selected.replace(node).is_some()
        {
            return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Err(gap) = charge_route_work(&mut remaining, cancellation) {
                return Ok(incomplete(gap));
            }
            stack.push(child);
        }
    }
    let Some(key) = selected else {
        return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
    };
    let mut element = key;
    while element.kind() != "keyed_element" {
        if let Err(gap) = charge_route_work(&mut remaining, cancellation) {
            return Ok(incomplete(gap));
        }
        let Some(parent) = element.parent() else {
            return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
        };
        if !matches!(parent.kind(), "literal_element" | "keyed_element") {
            return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
        }
        element = parent;
    }
    let Some(key_operand) = element.child_by_field_name("key") else {
        return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
    };
    let key_operand =
        super::semantic::transparent_runtime_wrapper_child(key_operand).unwrap_or(key_operand);
    if key_operand != key {
        return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
    }
    let Some(rhs) = element.child_by_field_name("value") else {
        return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
    };
    let rhs = super::semantic::transparent_runtime_wrapper_child(rhs).unwrap_or(rhs);
    let Some(body) = element
        .parent()
        .filter(|node| node.kind() == "literal_value")
    else {
        return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
    };
    let Some(literal) = body
        .parent()
        .filter(|node| node.kind() == "composite_literal")
    else {
        return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
    };
    let Some(type_node) = literal.child_by_field_name("type") else {
        return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
    };
    let semantics = procedure.semantics();
    let point = semantics
        .point(operand.point.id())
        .expect("retained operand point");
    let event = &point.events[operand.event_index];
    let event_source = semantics
        .source_mapping(event.source)
        .expect("validated event source");
    let rhs_value = semantics
        .value(operand.value.id())
        .expect("validated operand value");
    let rhs_source = semantics
        .source_mapping(rhs_value.source)
        .expect("validated value source");
    let rhs_evidence = semantics
        .evidence_row(rhs_value.evidence)
        .expect("validated operand evidence");
    if !rhs_evidence
        .proof
        .establishes_complete_evidence(&rhs_evidence.completeness)
    {
        return Ok(incomplete(GoExternalFieldGap::RouteEvidenceIncomplete));
    }
    let same_span = |locator: &SemanticLocator, node: tree_sitter::Node<'_>| {
        locator.mount() == procedure.artifact().key().mount()
            && locator.language() == procedure.artifact().key().language()
            && locator.path() == procedure.artifact().key().path()
            && locator.anchor().span().start_byte() as usize == node.start_byte()
            && locator.anchor().span().end_byte() as usize == node.end_byte()
    };
    if event_source.kind != crate::analyzer::semantic::SourceMappingKind::Exact
        || rhs_source.kind != crate::analyzer::semantic::SourceMappingKind::Exact
        || !same_span(&event_source.locator, literal)
        || !same_span(&rhs_source.locator, rhs)
    {
        return Ok(incomplete(GoExternalFieldGap::SourceStateUnknown));
    }
    let mut allocation = None;
    for candidate in semantics.allocations() {
        if let Err(gap) = charge_route_work(&mut remaining, cancellation) {
            return Ok(incomplete(gap));
        }
        if candidate.result == operand.aggregate.id() && allocation.replace(candidate).is_some() {
            return Ok(incomplete(GoExternalFieldGap::StorageUnknown));
        }
    }
    let Some(allocation) = allocation else {
        return Ok(incomplete(GoExternalFieldGap::StorageUnknown));
    };
    let allocation_evidence = semantics
        .evidence_row(allocation.evidence)
        .expect("validated allocation evidence");
    if !allocation_evidence
        .proof
        .establishes_complete_evidence(&allocation_evidence.completeness)
    {
        return Ok(incomplete(GoExternalFieldGap::RouteEvidenceIncomplete));
    }
    let allocation_source = semantics
        .source_mapping(allocation.source)
        .expect("validated allocation source");
    let aggregate_source = semantics
        .source_mapping(
            semantics
                .value(operand.aggregate.id())
                .expect("retained aggregate value")
                .source,
        )
        .expect("validated aggregate source");
    if allocation_source.kind != crate::analyzer::semantic::SourceMappingKind::Exact
        || aggregate_source.kind != crate::analyzer::semantic::SourceMappingKind::Exact
        || !same_span(&aggregate_source.locator, literal)
    {
        return Ok(incomplete(GoExternalFieldGap::StorageUnknown));
    }
    let mut allocation_node = literal;
    while !same_span(&allocation_source.locator, allocation_node) {
        if let Err(gap) = charge_route_work(&mut remaining, cancellation) {
            return Ok(incomplete(gap));
        }
        let Some(parent) = allocation_node.parent() else {
            return Ok(incomplete(GoExternalFieldGap::StorageUnknown));
        };
        let transparent =
            super::semantic::transparent_runtime_wrapper_child(parent) == Some(allocation_node);
        let address_of = parent.kind() == "unary_expression"
            && parent.child_by_field_name("operand") == Some(allocation_node)
            && (0..parent.child_count())
                .filter_map(|index| parent.child(index))
                .any(|child| !child.is_named() && child.kind() == "&");
        if !transparent && !address_of {
            return Ok(incomplete(GoExternalFieldGap::StorageUnknown));
        }
        allocation_node = parent;
    }
    let owner = match crate::analyzer::usages::get_definition::go_type_owner_at_node_bounded(
        workspace.analyzer(),
        &file,
        &source,
        type_node,
        crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
            max_scope_nodes: remaining,
            ..Default::default()
        },
        cancellation,
    ) {
        crate::analyzer::usages::get_definition::BoundedResolution::Complete { value, .. } => value,
        crate::analyzer::usages::get_definition::BoundedResolution::Exceeded { .. } => {
            return Ok(incomplete(GoExternalFieldGap::BudgetExhausted));
        }
        crate::analyzer::usages::get_definition::BoundedResolution::Cancelled { .. } => {
            return Ok(incomplete(GoExternalFieldGap::Cancelled));
        }
    };
    // The parser owns these ranges; no delimiter or rendered-name parser is used.
    Ok(GoAggregateSourceBinding::Bound {
        file,
        literal: super::GoSourceByteRange {
            start: literal.start_byte(),
            end: literal.end_byte(),
        },
        type_syntax: super::GoSourceByteRange {
            start: type_node.start_byte(),
            end: type_node.end_byte(),
        },
        member: source[key.start_byte()..key.end_byte()].to_owned(),
        owner,
    })
}

/// Bind an activated direct field to its exact parsed declaration and owner
/// in the same selected source set. Symbol locators are producer identities;
/// display names never establish this source crosswalk.
pub fn bind_go_external_field_source(
    field: &GoExternalField<'_>,
    overlay: &SemanticModelOverlay,
    artifact: &ExactArtifact,
    package: &super::GoPinnedPackage,
    max_nodes: usize,
    cancellation: &CancellationToken,
) -> Result<super::GoStructFieldIdentity, GoExternalFieldGap> {
    if field.artifact_sha256() != artifact.sha256() {
        return Err(GoExternalFieldGap::ArtifactUnbound);
    }
    let mut remaining = max_nodes;
    charge_route_work(&mut remaining, cancellation)?;
    let owner_id = field
        .symbol()
        .owner_id
        .as_deref()
        .ok_or(GoExternalFieldGap::DeclarationUnresolved)?;
    let mut selected_owner = None;
    for symbol in overlay.symbols() {
        charge_route_work(&mut remaining, cancellation)?;
        if symbol.id == owner_id && selected_owner.replace(symbol).is_some() {
            return Err(GoExternalFieldGap::DeclarationUnresolved);
        }
    }
    let owner = selected_owner.ok_or(GoExternalFieldGap::DeclarationUnresolved)?;
    if owner.provenance.ambiguous
        || owner.provenance.pack_digest != field.symbol().provenance.pack_digest
        || owner.provenance.active_model_set_hash != field.symbol().provenance.active_model_set_hash
        || owner.provenance.proof != SemanticModelProof::ExactArtifact
        || owner
            .provenance
            .activation
            .matched_evidence
            .artifact_sha256
            .as_deref()
            != Some(artifact.sha256())
    {
        return Err(GoExternalFieldGap::ArtifactUnbound);
    }
    let identities = super::analyze_go_package_source_identities(
        artifact,
        package,
        remaining,
        Some(cancellation),
    );
    // Gaps in unrelated declarations do not invalidate a proven direct field.
    remaining = remaining.saturating_sub(identities.visited_nodes);
    let mut selected = None;
    for declaration in &identities.identities {
        charge_route_work(&mut remaining, cancellation)?;
        let (Some(name), Some(super::GoDeclaredTypeShape::Struct { fields, .. })) =
            (&declaration.name, &declaration.declared_type_shape)
        else {
            continue;
        };
        if !declaration.lexical_owner_chain.is_empty()
            || declaration.anchor.kind != super::GoSourceDeclarationKind::Type
        {
            continue;
        }
        let owner_symbol = format!("{}.{}", declaration.package_import_path, name.text);
        if !owner.has_exact_artifact_locator(&declaration.anchor.file, &owner_symbol) {
            continue;
        }
        for candidate in fields {
            charge_route_work(&mut remaining, cancellation)?;
            if candidate.embedded || candidate.owner != declaration.anchor {
                continue;
            }
            for name in &candidate.name_anchors {
                charge_route_work(&mut remaining, cancellation)?;
                let symbol = format!("{owner_symbol}.{}", name.text);
                if field
                    .symbol()
                    .has_exact_artifact_locator(&candidate.anchor.file, &symbol)
                    && selected
                        .replace(GoStructFieldIdentity {
                            name_anchors: vec![name.clone()],
                            ..candidate.clone()
                        })
                        .is_some()
                {
                    return Err(GoExternalFieldGap::DeclarationUnresolved);
                }
            }
        }
    }
    selected.ok_or_else(|| {
        if cancellation.is_cancelled() {
            GoExternalFieldGap::Cancelled
        } else if identities
            .gaps
            .iter()
            .any(|gap| gap.kind == super::GoSourceIdentityGapKind::NodeBudgetExhausted)
        {
            GoExternalFieldGap::BudgetExhausted
        } else {
            GoExternalFieldGap::DeclarationUnresolved
        }
    })
}

/// Mint the only layout token accepted by aggregate-copy replay. The source
/// declaration is selected by its structured `Struct` identity and exact
/// artifact locator. This is a target-field projection: proving the requested
/// field does not claim that unrelated fields, embedded fields, or the whole
/// aggregate are modeled.
fn bind_go_external_field_layout<'a>(
    overlay: &'a SemanticModelOverlay,
    owner_fqn: &str,
    member: &str,
    artifact: &'a ExactArtifact,
    package: &super::GoPinnedPackage,
    max_nodes: usize,
    cancellation: &CancellationToken,
) -> Result<BoundGoExternalFieldLayout<'a>, GoExternalFieldGap> {
    let mut remaining = max_nodes;
    charge_route_work(&mut remaining, cancellation)?;
    let packages = GoOverlayPackages::new(Some(overlay));
    let owner = packages
        .unique_symbol(owner_fqn)
        .ok_or(GoExternalFieldGap::DeclarationUnresolved)?;
    if owner.language != "go"
        || owner.owner_id.is_some()
        || owner.kind != crate::analyzer::semantic_model::SemanticModelSymbolKind::Struct
    {
        return Err(GoExternalFieldGap::DeclarationUnresolved);
    }
    if owner.provenance.completeness != SemanticModelCompleteness::Complete {
        return Err(GoExternalFieldGap::FieldLayoutIncomplete);
    }
    if owner.provenance.proof != SemanticModelProof::ExactArtifact
        || owner.provenance.ambiguous
        || owner.provenance.active_model_set_hash != overlay.active_model_set_hash()
        || owner
            .provenance
            .activation
            .matched_evidence
            .artifact_sha256
            .as_deref()
            != Some(artifact.sha256())
    {
        return Err(GoExternalFieldGap::ArtifactUnbound);
    }

    let identities = super::analyze_go_package_source_identities(
        artifact,
        package,
        remaining,
        Some(cancellation),
    );
    remaining = remaining.saturating_sub(identities.visited_nodes);
    if identities.artifact_sha256 != artifact.sha256() {
        return Err(GoExternalFieldGap::ArtifactUnbound);
    }
    let mut declarations = Vec::new();
    for declaration in &identities.identities {
        charge_route_work(&mut remaining, cancellation)?;
        let Some(name) = declaration.name.as_ref() else {
            continue;
        };
        let Some(super::GoDeclaredTypeShape::Struct { fields, .. }) =
            declaration.declared_type_shape.as_ref()
        else {
            continue;
        };
        if declaration.lexical_owner_chain.is_empty()
            && declaration.anchor.kind == super::GoSourceDeclarationKind::Type
            && declaration.package_import_path == package.import_path
            && owner.qualified_name == format!("{}.{}", declaration.package_import_path, name.text)
            && owner.has_exact_artifact_locator(&declaration.anchor.file, &owner.qualified_name)
        {
            declarations.push((declaration.anchor.clone(), fields));
        }
    }
    let [(declaration_anchor, source_fields)] = declarations.as_slice() else {
        return Err(
            if identities
                .gaps
                .iter()
                .any(|gap| gap.kind == super::GoSourceIdentityGapKind::NodeBudgetExhausted)
            {
                GoExternalFieldGap::BudgetExhausted
            } else {
                GoExternalFieldGap::FieldLayoutIncomplete
            },
        );
    };
    if source_fields.is_empty() {
        return Err(GoExternalFieldGap::FieldLayoutIncomplete);
    }

    let mut selected = None;
    for (field_index, source_field) in source_fields.iter().enumerate() {
        charge_route_work(&mut remaining, cancellation)?;
        if source_field.embedded
            || source_field.owner != *declaration_anchor
            || source_field.name_anchors.is_empty()
        {
            continue;
        }
        for name in &source_field.name_anchors {
            charge_route_work(&mut remaining, cancellation)?;
            if name.text != member {
                continue;
            }
            if selected
                .replace((field_index, source_field.clone(), name.clone()))
                .is_some()
            {
                return Err(GoExternalFieldGap::FieldLayoutIncomplete);
            }
        }
    }
    let (field_index, mut source, name) =
        selected.ok_or(GoExternalFieldGap::FieldLayoutIncomplete)?;
    source.name_anchors = vec![name];
    let field = packages
        .concrete_receiver_field(owner_fqn, member)
        .ok_or(GoExternalFieldGap::FieldLayoutIncomplete)?;
    let field = GoExternalField {
        symbol: field,
        artifact_sha256: artifact.sha256(),
        copy: packages.concrete_receiver_field_value_copy(owner_fqn, member),
    };
    if field.symbol().provenance.completeness != SemanticModelCompleteness::Complete {
        return Err(GoExternalFieldGap::FieldLayoutIncomplete);
    }
    let actual =
        bind_go_external_field_source(&field, overlay, artifact, package, remaining, cancellation)?;
    if actual != source {
        return Err(GoExternalFieldGap::FieldLayoutIncomplete);
    }
    let field = field.with_source_shape(&source)?;
    Ok(BoundGoExternalFieldLayout {
        owner: owner_fqn.to_owned(),
        field_index,
        fields: vec![BoundGoExternalField { source, field }].into_boxed_slice(),
    })
}

/// Observe the initializer allocation through the heap oracle at its actual
/// event point. Only a closed, proven single allocation may authorize replay.
/// The retained outcome includes its scoped query and relation provenance.
pub fn observe_go_aggregate_object(
    oracle: &impl crate::analyzer::semantic::HeapOracle,
    operand: &GoAggregateOperand<'_>,
    request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
) -> Result<
    crate::analyzer::semantic::SemanticOutcome<crate::analyzer::semantic::PointsToResult>,
    crate::analyzer::semantic::SemanticProviderError,
> {
    use crate::analyzer::semantic::{ObservationPhase, OracleCallContext, ValueAtPoint};
    let query = ValueAtPoint::new(
        operand.aggregate.clone(),
        operand.point.clone(),
        ObservationPhase::AfterEffects,
        OracleCallContext::empty(),
    )
    .map_err(|error| {
        crate::analyzer::semantic::SemanticProviderError::internal(format!(
            "invalid retained aggregate observation: {error}"
        ))
    })?;
    oracle.pointees(&query, request)
}

/// Join the heap observation to the exact retained operand, without treating
/// a partial result or a static allocation ID as singleton evidence.
pub fn go_aggregate_object_is_singleton(
    operand: &GoAggregateOperand<'_>,
    outcome: &crate::analyzer::semantic::SemanticOutcome<crate::analyzer::semantic::PointsToResult>,
) -> bool {
    use crate::analyzer::semantic::{
        AbstractObjectIdentity, ObjectCardinality, ObservationPhase, SemanticOutcome,
    };
    let SemanticOutcome::Complete { value, .. } = outcome else {
        return false;
    };
    if value.query().value() != operand.aggregate()
        || value.query().point() != operand.point()
        || value.query().phase() != ObservationPhase::AfterEffects
        || !value.objects().is_closed()
    {
        return false;
    }
    let [candidate] = value.objects().candidates() else {
        return false;
    };
    let AbstractObjectIdentity::Allocation(allocation) = candidate.value().identity() else {
        return false;
    };
    candidate.is_proven_complete()
        && candidate.value().cardinality() == ObjectCardinality::Singleton
        && allocation.procedure() == operand.aggregate().procedure()
        && allocation
            .procedure()
            .semantics()
            .allocation(allocation.id())
            .is_some_and(|row| row.result == operand.aggregate().id())
}

fn charge_route_work(
    remaining: &mut usize,
    cancellation: &CancellationToken,
) -> Result<(), GoExternalFieldGap> {
    if cancellation.is_cancelled() {
        return Err(GoExternalFieldGap::Cancelled);
    }
    *remaining = remaining
        .checked_sub(1)
        .ok_or(GoExternalFieldGap::BudgetExhausted)?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct FieldSlot<'a> {
    object: ValueId,
    field: GoExternalField<'a>,
    value: ValueId,
}

#[derive(Debug, Clone)]
struct TrackedAggregate<'a> {
    object: ValueId,
    layout: BoundGoExternalFieldLayout<'a>,
}

/// State for one selected ordered path in one procedure. The work cap includes
/// every examined slot so sparse copy/read operations cannot evade the budget.
/// No state is cached or retained on a workspace/selection.
#[derive(Debug)]
pub struct GoExternalFieldMemory<'a> {
    procedure: &'a ProcedureHandle,
    slots: Vec<FieldSlot<'a>>,
    tracked: Vec<TrackedAggregate<'a>>,
    aliases: Vec<(ValueId, ValueId)>,
    layout: Option<BoundGoExternalFieldLayout<'a>>,
    remaining: usize,
    gap: Option<GoExternalFieldGap>,
}

impl<'a> GoExternalFieldMemory<'a> {
    pub fn new(procedure: &'a ProcedureHandle, max_work: usize) -> Self {
        Self {
            procedure,
            slots: Vec::new(),
            tracked: Vec::new(),
            aliases: Vec::new(),
            layout: None,
            remaining: max_work,
            gap: None,
        }
    }

    fn scoped(&mut self, value: &ValueHandle) -> Result<ValueId, GoExternalFieldGap> {
        if value.procedure() == self.procedure {
            return Ok(value.id());
        }
        self.gap = Some(GoExternalFieldGap::ValueOutsideProcedure);
        Err(GoExternalFieldGap::ValueOutsideProcedure)
    }

    pub fn store(
        &mut self,
        object: &ValueHandle,
        field: GoExternalField<'a>,
        value: &ValueHandle,
        cancellation: &CancellationToken,
    ) -> Result<(), GoExternalFieldGap> {
        let object = self.scoped(object)?;
        let value = self.scoped(value)?;
        self.store_ids(object, field, value, cancellation)
    }

    pub fn read(
        &mut self,
        object: &ValueHandle,
        field: GoExternalField<'a>,
        cancellation: &CancellationToken,
    ) -> Result<ValueHandle, GoExternalFieldGap> {
        let object = self.scoped(object)?;
        let object = self.canonical_object(object, cancellation)?;
        let value = self.read_ids(object, field, cancellation)?;
        Ok(self
            .procedure
            .value_handle(value)
            .expect("stored values belong to this procedure"))
    }

    pub fn copy_struct(
        &mut self,
        source: &ValueHandle,
        destination: &ValueHandle,
        cancellation: &CancellationToken,
    ) -> Result<(), GoExternalFieldGap> {
        let source = self.scoped(source)?;
        let destination = self.scoped(destination)?;
        self.copy_ids(source, destination, cancellation)
    }

    /// Read the requested field from a state produced by
    /// `effective_argument_field_value`. The layout and source/model proof are
    /// retained privately by that query; a caller can choose a member name but
    /// cannot inject a field identity or same-length layout.
    pub fn read_bound_field(
        &mut self,
        object: &ValueHandle,
        member: &str,
        cancellation: &CancellationToken,
    ) -> Result<ValueHandle, GoExternalFieldGap> {
        let object = self.scoped(object)?;
        self.charge(cancellation)?;
        let field = self
            .layout
            .as_ref()
            .and_then(|layout| layout.field_named(member))
            .ok_or(GoExternalFieldGap::FieldLayoutIncomplete)?
            .field;
        let value = self.read_ids(object, field, cancellation)?;
        Ok(self
            .procedure
            .value_handle(value)
            .expect("stored values belong to this procedure"))
    }

    fn tracked_layout(
        &mut self,
        object: ValueId,
        cancellation: &CancellationToken,
    ) -> Result<Option<BoundGoExternalFieldLayout<'a>>, GoExternalFieldGap> {
        let object = self.canonical_object(object, cancellation)?;
        Ok(self
            .tracked
            .iter()
            .find(|tracked| tracked.object == object)
            .map(|tracked| tracked.layout.clone()))
    }

    fn track_layout(
        &mut self,
        object: ValueId,
        layout: &BoundGoExternalFieldLayout<'a>,
        cancellation: &CancellationToken,
    ) -> Result<(), GoExternalFieldGap> {
        self.charge(cancellation)?;
        let object = self.canonical_object(object, cancellation)?;
        if let Some(existing) = self.tracked.iter().find(|tracked| tracked.object == object) {
            if existing.layout.owner != layout.owner {
                self.gap = Some(GoExternalFieldGap::EffectiveStateIncomplete);
                return Err(GoExternalFieldGap::EffectiveStateIncomplete);
            }
            return Ok(());
        }
        self.tracked.push(TrackedAggregate {
            object,
            layout: layout.clone(),
        });
        Ok(())
    }

    fn alias_object(
        &mut self,
        target: ValueId,
        source: ValueId,
        cancellation: &CancellationToken,
    ) -> Result<(), GoExternalFieldGap> {
        self.charge(cancellation)?;
        self.check_value(target)?;
        if self.slots.iter().any(|slot| slot.object == target) {
            self.gap = Some(GoExternalFieldGap::EffectiveStateIncomplete);
            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
        }
        let source = self.canonical_object(source, cancellation)?;
        if target == source {
            self.gap = Some(GoExternalFieldGap::EffectiveStateIncomplete);
            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
        }
        if let Some(existing) = self
            .aliases
            .iter()
            .find_map(|(alias, object)| (*alias == target).then_some(*object))
        {
            if existing != source {
                self.gap = Some(GoExternalFieldGap::EffectiveStateIncomplete);
                return Err(GoExternalFieldGap::EffectiveStateIncomplete);
            }
            return Ok(());
        }
        self.aliases.push((target, source));
        Ok(())
    }

    fn field_slot_value(
        &mut self,
        object: ValueId,
        field: GoExternalField<'a>,
        cancellation: &CancellationToken,
    ) -> Result<Option<ValueId>, GoExternalFieldGap> {
        let object = self.canonical_object(object, cancellation)?;
        Ok(self
            .slots
            .iter()
            .find(|slot| slot.object == object && slot.field == field)
            .map(|slot| slot.value))
    }

    /// Store one retained `AggregateInitializer` after its source declaration
    /// has been crosswalked to the exact activated field. The initializer's
    /// aggregate and RHS handles are the only identities accepted here; a
    /// caller cannot replace them with equal-looking value IDs from another
    /// materialization.
    fn store_initializer(
        &mut self,
        operand: &GoAggregateOperand<'_>,
        source: &GoStructFieldIdentity,
        field: GoExternalField<'a>,
        cancellation: &CancellationToken,
    ) -> Result<(), GoExternalFieldGap> {
        if operand.aggregate.procedure() != self.procedure
            || operand.value.procedure() != self.procedure
        {
            self.gap = Some(GoExternalFieldGap::ValueOutsideProcedure);
            return Err(GoExternalFieldGap::ValueOutsideProcedure);
        }
        let field = field.with_source_shape(source)?;
        self.store(&operand.aggregate, field, &operand.value, cancellation)
    }

    /// Copy the privately bound target projection into distinct destination
    /// storage. This is deliberately a one-field operation and does not claim
    /// that unrelated aggregate fields are modeled.
    fn copy_bound_layout(
        &mut self,
        source: &ValueHandle,
        destination: &ValueHandle,
        layout: &BoundGoExternalFieldLayout<'a>,
        cancellation: &CancellationToken,
    ) -> Result<(), GoExternalFieldGap> {
        assert_eq!(
            layout.fields.len(),
            1,
            "field projection has one target slot"
        );
        let source = self.scoped(source)?;
        let source = self.canonical_object(source, cancellation)?;
        let destination = self.scoped(destination)?;
        self.charge(cancellation)?;
        self.check_value(destination)?;
        if self
            .aliases
            .iter()
            .any(|(alias, object)| *alias == destination || *object == destination)
        {
            self.gap = Some(GoExternalFieldGap::EffectiveStateIncomplete);
            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
        }
        if source == destination {
            self.gap = Some(GoExternalFieldGap::AliasedDestination);
            return Err(GoExternalFieldGap::AliasedDestination);
        }
        let field = layout.fields[0].field;
        if matches!(
            field.copy,
            MemoryValueCopy::Unknown | MemoryValueCopy::Value
        ) {
            self.gap = Some(GoExternalFieldGap::StorageUnknown);
            return Err(GoExternalFieldGap::StorageUnknown);
        }
        let Some(value) = self
            .slots
            .iter()
            .find(|slot| slot.object == source && slot.field == field)
            .map(|slot| slot.value)
        else {
            self.gap = Some(GoExternalFieldGap::EffectiveStateIncomplete);
            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
        };
        if self.slots.iter().any(|slot| slot.object == destination) {
            self.gap = Some(GoExternalFieldGap::AliasedDestination);
            return Err(GoExternalFieldGap::AliasedDestination);
        }
        self.slots.push(FieldSlot {
            object: destination,
            field,
            value,
        });
        Ok(())
    }

    fn charge(&mut self, cancellation: &CancellationToken) -> Result<(), GoExternalFieldGap> {
        if let Some(gap) = self.gap {
            return Err(gap);
        }
        if cancellation.is_cancelled() {
            self.gap = Some(GoExternalFieldGap::Cancelled);
        } else if self.remaining == 0 {
            self.gap = Some(GoExternalFieldGap::BudgetExhausted);
        } else {
            self.remaining -= 1;
            return Ok(());
        }
        Err(self.gap.expect("an interrupted query retains its gap"))
    }

    fn check_value(&mut self, value: ValueId) -> Result<(), GoExternalFieldGap> {
        if self.procedure.semantics().value(value).is_some() {
            return Ok(());
        }
        self.gap = Some(GoExternalFieldGap::ValueOutsideProcedure);
        Err(GoExternalFieldGap::ValueOutsideProcedure)
    }

    fn canonical_object(
        &mut self,
        object: ValueId,
        cancellation: &CancellationToken,
    ) -> Result<ValueId, GoExternalFieldGap> {
        self.check_value(object)?;
        let mut current = object;
        let mut seen = std::collections::HashSet::new();
        loop {
            self.charge(cancellation)?;
            if !seen.insert(current) {
                self.gap = Some(GoExternalFieldGap::EffectiveStateIncomplete);
                return Err(GoExternalFieldGap::EffectiveStateIncomplete);
            }
            let next = self
                .aliases
                .iter()
                .find_map(|(alias, target)| (*alias == current).then_some(*target));
            let Some(next) = next else {
                return Ok(current);
            };
            current = next;
        }
    }

    /// Apply a caller-proven ordered store at an exact abstract object slot.
    /// This replaces that field while values saved by earlier reads remain
    /// ordinary immutable ValueIds. It is not a strong-update certificate.
    fn store_ids(
        &mut self,
        object: ValueId,
        field: GoExternalField<'a>,
        value: ValueId,
        cancellation: &CancellationToken,
    ) -> Result<(), GoExternalFieldGap> {
        self.charge(cancellation)?;
        let object = self.canonical_object(object, cancellation)?;
        self.check_value(value)?;
        if field.copy == MemoryValueCopy::Unknown {
            self.gap = Some(GoExternalFieldGap::StorageUnknown);
            return Err(GoExternalFieldGap::StorageUnknown);
        }
        for index in 0..self.slots.len() {
            self.charge(cancellation)?;
            if self.slots[index].object == object && self.slots[index].field == field {
                self.slots[index].value = value;
                return Ok(());
            }
        }
        self.slots.push(FieldSlot {
            object,
            field,
            value,
        });
        Ok(())
    }

    fn read_ids(
        &mut self,
        object: ValueId,
        field: GoExternalField<'a>,
        cancellation: &CancellationToken,
    ) -> Result<ValueId, GoExternalFieldGap> {
        self.charge(cancellation)?;
        let object = self.canonical_object(object, cancellation)?;
        for index in 0..self.slots.len() {
            self.charge(cancellation)?;
            if self.slots[index].object == object && self.slots[index].field == field {
                return Ok(self.slots[index].value);
            }
        }
        Err(GoExternalFieldGap::FieldUninitialized)
    }

    /// Duplicate known field slots into separate struct destination storage.
    /// Reference and backing-store field values retain the same source ValueId;
    /// inline nested aggregates need their own copy relation and remain open.
    /// Returns StorageUnknown for Value fields instead of aliasing aggregates.
    fn copy_ids(
        &mut self,
        source: ValueId,
        destination: ValueId,
        cancellation: &CancellationToken,
    ) -> Result<(), GoExternalFieldGap> {
        self.charge(cancellation)?;
        let source = self.canonical_object(source, cancellation)?;
        self.check_value(destination)?;
        if source == destination {
            self.gap = Some(GoExternalFieldGap::AliasedDestination);
            return Err(GoExternalFieldGap::AliasedDestination);
        }
        let mut copied = Vec::new();
        for index in 0..self.slots.len() {
            self.charge(cancellation)?;
            let slot = self.slots[index];
            if slot.object == destination {
                self.gap = Some(GoExternalFieldGap::AliasedDestination);
                return Err(GoExternalFieldGap::AliasedDestination);
            }
            if slot.object != source {
                continue;
            }
            if matches!(
                slot.field.copy,
                MemoryValueCopy::Unknown | MemoryValueCopy::Value
            ) {
                self.gap = Some(GoExternalFieldGap::StorageUnknown);
                return Err(GoExternalFieldGap::StorageUnknown);
            }
            copied.push(FieldSlot {
                object: destination,
                ..slot
            });
        }
        // Commit atomically after all budget and storage checks. No partial
        // successful copy can hide the failure to copy another field.
        if copied.is_empty() {
            self.gap = Some(GoExternalFieldGap::SourceStateUnknown);
            return Err(GoExternalFieldGap::SourceStateUnknown);
        }
        self.slots.extend(copied);
        Ok(())
    }
}

/// One query's selected dependency source, activation and bounded request.
/// Every refinement uses this same exact source and cancellation token.
pub struct GoExternalFieldQuery<'a> {
    workspace: &'a crate::analyzer::WorkspaceAnalyzer,
    overlay: &'a SemanticModelOverlay,
    artifact: &'a ExactArtifact,
    package: &'a super::GoPinnedPackage,
    max_source_bytes: usize,
    max_source_nodes: usize,
    max_work: usize,
    cancellation: &'a CancellationToken,
}

impl<'a> GoExternalFieldQuery<'a> {
    pub fn new(
        workspace: &'a crate::analyzer::WorkspaceAnalyzer,
        overlay: &'a SemanticModelOverlay,
        artifact: &'a ExactArtifact,
        package: &'a super::GoPinnedPackage,
        cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            workspace,
            overlay,
            artifact,
            package,
            cancellation,
            max_source_bytes: 1024 * 1024,
            max_source_nodes: 100_000,
            max_work: 100_000,
        }
    }

    pub fn with_limits(
        mut self,
        max_source_bytes: usize,
        max_source_nodes: usize,
        max_work: usize,
    ) -> Self {
        self.max_source_bytes = max_source_bytes;
        self.max_source_nodes = max_source_nodes;
        self.max_work = max_work;
        self
    }

    /// Establish the effective value of one imported aggregate field at the
    /// actual consumer call. The argument, initializer events, aggregate-copy
    /// transfers, field stores, and call point all come from the retained root
    /// procedure. The query rejects loops and incomplete route sets; it does
    /// not establish that the callee invokes or uses the callback.
    pub fn effective_argument_field_value(
        &self,
        procedure: &'a ProcedureHandle,
        call_site: &CallSiteHandle,
        argument_index: usize,
        member: &str,
    ) -> Result<ValueHandle, GoExternalFieldGap> {
        let Self {
            max_work,
            cancellation,
            ..
        } = *self;

        if call_site.procedure() != procedure {
            return Err(GoExternalFieldGap::PointOutsideProcedure);
        }
        let call = procedure
            .semantics()
            .call_site(call_site.id())
            .ok_or(GoExternalFieldGap::PointOutsideProcedure)?;
        let argument = call
            .arguments
            .get(argument_index)
            .ok_or(GoExternalFieldGap::EffectiveStateIncomplete)?;
        if !matches!(
            argument.expansion,
            crate::analyzer::semantic::CallArgumentExpansion::Direct(_)
        ) {
            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
        }
        let mut remaining = max_work;
        let routes =
            enumerate_complete_routes(procedure, call.point, &mut remaining, cancellation)?;
        if routes.is_empty() {
            return Err(GoExternalFieldGap::RouteSetIncomplete);
        }

        let mut selected_memory = None;
        let mut selected_layout = None;
        let mut selected_value = None;
        let mut selected_object = None;
        for route in routes {
            let mut memory = GoExternalFieldMemory::new(procedure, max_work.saturating_add(1));
            let layout =
                self.discover_route_layout(&route, argument.value, member, &mut remaining)?;
            memory.layout = Some(layout.clone());
            self.replay_complete_route(
                &mut memory,
                &route,
                call_site.id(),
                argument.value,
                &mut remaining,
            )?;
            let field = layout
                .field_named(member)
                .ok_or(GoExternalFieldGap::FieldLayoutIncomplete)?
                .field;
            let related = route_related_values(
                &route,
                argument.value,
                &mut memory,
                &mut remaining,
                cancellation,
            )?;
            let value = memory
                .field_slot_value(related.object, field, cancellation)?
                .ok_or(GoExternalFieldGap::EffectiveStateIncomplete)?;
            if let Some(previous) = selected_value
                && previous != value
            {
                return Err(GoExternalFieldGap::EffectiveStateIncomplete);
            }
            if let Some(previous) = selected_layout.as_ref()
                && !same_bound_layout(previous, &layout)
            {
                return Err(GoExternalFieldGap::FieldLayoutIncomplete);
            }
            selected_value = Some(value);
            if selected_memory.is_none() {
                selected_memory = Some(memory);
                selected_layout = Some(layout);
                selected_object = Some(related.object);
            }
        }
        let mut memory = selected_memory.ok_or(GoExternalFieldGap::RouteSetIncomplete)?;
        memory.layout = selected_layout;
        let object = procedure
            .value_handle(selected_object.ok_or(GoExternalFieldGap::RouteSetIncomplete)?)
            .ok_or(GoExternalFieldGap::ValueOutsideProcedure)?;
        charge_route_work(&mut remaining, cancellation)?;
        memory.read_bound_field(&object, member, cancellation)
    }
}

fn same_bound_layout(
    left: &BoundGoExternalFieldLayout<'_>,
    right: &BoundGoExternalFieldLayout<'_>,
) -> bool {
    left.owner == right.owner
        && left.field_index == right.field_index
        && left.fields.len() == right.fields.len()
        && left
            .fields
            .iter()
            .zip(&right.fields)
            .all(|(left, right)| left.source == right.source && left.field == right.field)
}

fn enumerate_complete_routes<'a>(
    procedure: &'a ProcedureHandle,
    target: crate::analyzer::semantic::ProgramPointId,
    remaining: &mut usize,
    cancellation: &CancellationToken,
) -> Result<Vec<GoFieldReplayRoute<'a>>, GoExternalFieldGap> {
    let semantics = procedure.semantics();
    let mut can_reach = std::collections::HashSet::new();
    let mut reverse = vec![target];
    while let Some(point) = reverse.pop() {
        charge_route_work(remaining, cancellation)?;
        if !can_reach.insert(point) {
            continue;
        }
        for (_, edge) in semantics.predecessor_edges(point) {
            charge_route_work(remaining, cancellation)?;
            reverse.push(edge.source_point);
        }
    }
    for (_, edge) in semantics.successor_edges(target) {
        charge_route_work(remaining, cancellation)?;
        if can_reach.contains(&edge.target_point) {
            return Err(GoExternalFieldGap::RouteSetIncomplete);
        }
    }
    let entry = semantics.entry_point();
    if !can_reach.contains(&entry) {
        return Err(GoExternalFieldGap::RouteNotFromEntry);
    }

    let mut pending = vec![(entry, vec![entry])];
    let mut routes = Vec::new();
    while let Some((point, path)) = pending.pop() {
        charge_route_work(remaining, cancellation)?;
        if point == target {
            let points = path
                .into_iter()
                .map(|id| {
                    procedure
                        .point_handle(id)
                        .ok_or(GoExternalFieldGap::PointOutsideProcedure)
                })
                .collect::<Result<Vec<_>, _>>()?;
            routes.push(GoFieldReplayRoute::verified(procedure, points));
            continue;
        }
        let mut outgoing = 0usize;
        for (_, edge) in semantics.successor_edges(point) {
            charge_route_work(remaining, cancellation)?;
            if !can_reach.contains(&edge.target_point) {
                continue;
            }
            outgoing += 1;
            if !matches!(
                edge.kind,
                ControlEdgeKind::Normal
                    | ControlEdgeKind::ConditionalTrue
                    | ControlEdgeKind::ConditionalFalse
                    | ControlEdgeKind::SwitchCase
            ) {
                return Err(GoExternalFieldGap::RouteSetIncomplete);
            }
            let evidence = semantics
                .evidence_row(edge.evidence)
                .ok_or(GoExternalFieldGap::RouteEvidenceIncomplete)?;
            if !evidence
                .proof
                .establishes_complete_evidence(&evidence.completeness)
            {
                return Err(GoExternalFieldGap::RouteEvidenceIncomplete);
            }
            if path.contains(&edge.target_point) {
                return Err(GoExternalFieldGap::RouteSetIncomplete);
            }
            let mut next = path.clone();
            next.push(edge.target_point);
            pending.push((edge.target_point, next));
        }
        if outgoing == 0 {
            return Err(GoExternalFieldGap::RouteSetIncomplete);
        }
    }
    Ok(routes)
}

struct RelatedRouteValues {
    values: std::collections::HashSet<ValueId>,
    fresh_local_bindings: std::collections::HashSet<(ValueId, ValueId)>,
    object: ValueId,
}

fn route_related_values(
    route: &GoFieldReplayRoute<'_>,
    argument: ValueId,
    memory: &mut GoExternalFieldMemory<'_>,
    remaining: &mut usize,
    cancellation: &CancellationToken,
) -> Result<RelatedRouteValues, GoExternalFieldGap> {
    let mut related = std::collections::HashSet::from([argument]);
    let mut initializer_values = std::collections::HashSet::new();
    let mut fresh_local_bindings = std::collections::HashSet::new();
    let mut object = argument;

    // The Go lowerer deliberately keeps an aggregate literal in its own
    // result value and then emits an identity-preserving conversion flow and
    // Local flow into a fresh binding. Recognize only those exact flow edges
    // when anchored by the retained AggregateInitializer and binding
    // Assignment. Local reads preserve that storage identity; arbitrary
    // LanguageDefined computations do not establish an aggregate alias.
    let mut assignments = std::collections::HashSet::new();
    let mut assignment_values = std::collections::HashSet::new();
    let mut local_flows = Vec::new();
    let mut reference_flows = Vec::new();
    let mut references = std::collections::HashSet::new();
    for value in route.procedure().semantics().values() {
        charge_route_work(remaining, cancellation)?;
        memory.charge(cancellation)?;
        if matches!(value.kind, SemanticValueKind::Address) {
            references.insert(value.id);
        }
    }
    for point in route.points() {
        let events = point_events(route.procedure(), point.id())?;
        for event in events {
            charge_route_work(remaining, cancellation)?;
            memory.charge(cancellation)?;
            if let SemanticEffect::AggregateInitializer { aggregate, .. } = &event.effect {
                initializer_values.insert(*aggregate);
            }
            if let SemanticEffect::Assignment { target, value } = &event.effect {
                assignments.insert((*target, *value));
                assignment_values.insert(*value);
            }
            if let SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Transfer(transfer),
                source,
                target,
            } = &event.effect
                && transfer.kind == TransferKind::Copy
            {
                reference_flows.push((*source, *target));
            }
            if let SemanticEffect::ValueFlow {
                kind: ValueFlowKind::Local | ValueFlowKind::LanguageDefined,
                source,
                target,
            } = &event.effect
            {
                local_flows.push((
                    *source,
                    *target,
                    matches!(
                        event.effect,
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Local,
                            ..
                        }
                    ),
                ));
            }
        }
    }
    let mut reachable = initializer_values.clone();
    loop {
        let mut added = false;
        for (source, target, local_read) in &local_flows {
            charge_route_work(remaining, cancellation)?;
            memory.charge(cancellation)?;
            if (*local_read
                || reachable.contains(source)
                    && (assignment_values.contains(target)
                        || assignments.contains(&(*target, *source))))
                && fresh_local_bindings.insert((*source, *target))
            {
                reachable.insert(*target);
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    reference_flows.extend(
        local_flows
            .iter()
            .filter_map(|(source, target, local)| local.then_some((*source, *target))),
    );
    loop {
        let mut added = false;
        for (source, target) in &reference_flows {
            charge_route_work(remaining, cancellation)?;
            memory.charge(cancellation)?;
            if references.contains(source) {
                added |= references.insert(*target);
            }
        }
        if !added {
            break;
        }
    }
    for point in route.points().iter().rev() {
        for event in point_events(route.procedure(), point.id())?.iter().rev() {
            charge_route_work(remaining, cancellation)?;
            memory.charge(cancellation)?;
            match &event.effect {
                SemanticEffect::Assignment { target, value }
                    if related.contains(target)
                        && route
                            .procedure()
                            .semantics()
                            .value(*target)
                            .is_some_and(|value| {
                                matches!(&value.kind, SemanticValueKind::Address)
                            }) =>
                {
                    related.insert(*value);
                    if object == *target {
                        object = *value;
                    }
                }
                SemanticEffect::MemoryLoad {
                    location, result, ..
                } if related.contains(result) => {
                    if let Some(location) = route.procedure().semantics().memory_location(*location)
                    {
                        match location.kind {
                            MemoryLocationKind::Dereference { address } => {
                                related.insert(address);
                            }
                            MemoryLocationKind::LexicalCell { binding } => {
                                related.insert(binding);
                            }
                            _ => {}
                        }
                    }
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Transfer(transfer),
                    source,
                    target,
                } if matches!(
                    transfer.kind,
                    TransferKind::AggregateCopy | TransferKind::Copy
                ) && related.contains(target) =>
                {
                    related.insert(*source);
                }
                SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local | ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } if fresh_local_bindings.contains(&(*source, *target))
                    && related.contains(target) =>
                {
                    related.insert(*source);
                }
                _ => {}
            }
        }
    }
    // Close address aliases in forward order. A call may receive `&object`
    // through an intermediate assignment; without this closure an invoke
    // carrying that address would be mistaken for an unrelated call. Only
    // producer-authored address assignments and retained Local reads are
    // propagated here. Copy transfers remain distinct storage identities.
    loop {
        let mut added = false;
        for point in route.points() {
            for event in point_events(route.procedure(), point.id())? {
                charge_route_work(remaining, cancellation)?;
                memory.charge(cancellation)?;
                if let SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Local | ValueFlowKind::LanguageDefined,
                    source,
                    target,
                } = &event.effect
                    && related.contains(source)
                    && fresh_local_bindings.contains(&(*source, *target))
                {
                    added |= related.insert(*target);
                }
                if let SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Transfer(transfer),
                    source,
                    target,
                } = &event.effect
                    && transfer.kind == TransferKind::Copy
                    && references.contains(source)
                    && related.contains(source)
                {
                    added |= related.insert(*target);
                }
                if let SemanticEffect::MemoryLoad {
                    location, result, ..
                } = &event.effect
                    && let Some(location) = route.procedure().semantics().memory_location(*location)
                    && let MemoryLocationKind::LexicalCell { binding } = location.kind
                    && related.contains(&binding)
                {
                    added |= related.insert(*result);
                }
                let SemanticEffect::Assignment { target, value } = &event.effect else {
                    continue;
                };
                if related.contains(value)
                    && route
                        .procedure()
                        .semantics()
                        .value(*target)
                        .is_some_and(|value| matches!(&value.kind, SemanticValueKind::Address))
                {
                    added |= related.insert(*target);
                }
            }
        }
        if !added {
            break;
        }
    }
    Ok(RelatedRouteValues {
        values: related,
        fresh_local_bindings,
        object,
    })
}

impl<'a> GoExternalFieldQuery<'a> {
    fn discover_route_layout(
        &self,
        route: &GoFieldReplayRoute<'a>,
        argument: ValueId,
        member: &str,
        remaining: &mut usize,
    ) -> Result<BoundGoExternalFieldLayout<'a>, GoExternalFieldGap> {
        let Self {
            workspace,
            overlay,
            artifact,
            package,
            max_source_bytes,
            max_source_nodes,
            cancellation,
            ..
        } = *self;
        let mut probe = GoExternalFieldMemory::new(route.procedure(), max_source_nodes.max(1));
        let related =
            route_related_values(route, argument, &mut probe, remaining, cancellation)?.values;
        let mut layout: Option<BoundGoExternalFieldLayout<'a>> = None;
        for (point_index, point) in route.points().iter().enumerate() {
            for (event_index, event) in point_events(route.procedure(), point.id())?
                .iter()
                .enumerate()
            {
                charge_route_work(remaining, cancellation)?;
                let SemanticEffect::AggregateInitializer { aggregate, .. } = &event.effect else {
                    continue;
                };
                if !related.contains(aggregate) {
                    continue;
                }
                let operand = route.initializer_at(point_index, event_index)?;
                let binding = bind_go_aggregate_operand_source(
                    workspace,
                    &operand,
                    max_source_bytes,
                    max_source_nodes,
                    cancellation,
                )
                .map_err(|_| GoExternalFieldGap::SourceStateUnknown)?;
                if let GoAggregateSourceBinding::Incomplete(gap) = binding {
                    return Err(gap);
                }
                let GoAggregateSourceBinding::Bound {
                    member: source_member,
                    owner: Some(owner),
                    ..
                } = binding
                else {
                    return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                };
                if source_member != member {
                    continue;
                }
                if let Some(existing) = layout.as_ref()
                    && existing.owner != owner
                {
                    return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                }
                if layout.is_none() {
                    layout = Some(bind_go_external_field_layout(
                        overlay,
                        &owner,
                        member,
                        artifact,
                        package,
                        max_source_nodes,
                        cancellation,
                    )?);
                }
                let next = layout.as_ref().expect("layout was just initialized");
                if next.field_named(member).is_none() {
                    return Err(GoExternalFieldGap::FieldLayoutIncomplete);
                }
            }
        }
        layout.ok_or(GoExternalFieldGap::EffectiveStateIncomplete)
    }

    fn replay_complete_route(
        &self,
        memory: &mut GoExternalFieldMemory<'a>,
        route: &GoFieldReplayRoute<'a>,
        call_site: crate::analyzer::semantic::CallSiteId,
        argument: ValueId,
        remaining: &mut usize,
    ) -> Result<(), GoExternalFieldGap> {
        let Self {
            workspace,
            overlay,
            artifact,
            package,
            max_source_bytes,
            max_source_nodes,
            cancellation,
            ..
        } = *self;
        let layout = memory
            .layout
            .clone()
            .ok_or(GoExternalFieldGap::FieldLayoutIncomplete)?;
        let related_info = route_related_values(route, argument, memory, remaining, cancellation)?;
        let related = &related_info.values;
        // A captured lexical cell can be mutated by a call without appearing
        // among its operands. Until invocation-specific capture writes are
        // resolved, keep such state incomplete rather than reuse an old field.
        let mut captured_state = false;
        for capture in route.procedure().semantics().captures() {
            charge_route_work(remaining, cancellation)?;
            memory.charge(cancellation)?;
            use crate::analyzer::semantic::CaptureSource;
            captured_state |= match capture.captured {
                CaptureSource::Value(value) => related.contains(&value),
                CaptureSource::Location(location) => route
                    .procedure()
                    .semantics()
                    .memory_location(location)
                    .is_some_and(|location| {
                        related.iter().any(|value| location.kind.uses_value(*value))
                    }),
            };
        }
        let mut references = std::collections::HashSet::new();
        let mut reached_call = false;
        for (point_index, point) in route.points().iter().enumerate() {
            let events = point_events(route.procedure(), point.id())?;
            let mut aggregate_copy_bindings = std::collections::HashSet::new();
            for event in events {
                charge_route_work(remaining, cancellation)?;
                if let SemanticEffect::ValueFlow {
                    kind: ValueFlowKind::Transfer(transfer),
                    source,
                    target,
                } = &event.effect
                    && matches!(
                        transfer.kind,
                        TransferKind::AggregateCopy | TransferKind::Copy
                    )
                {
                    aggregate_copy_bindings.insert((*source, *target));
                }
            }
            for (event_index, event) in events.iter().enumerate() {
                charge_route_work(remaining, cancellation)?;
                memory.charge(cancellation)?;
                if let SemanticEffect::Invoke { call_site: actual } = &event.effect {
                    if *actual == call_site {
                        reached_call = true;
                        break;
                    }
                    let invoked = route
                        .procedure()
                        .semantics()
                        .call_site(*actual)
                        .ok_or(GoExternalFieldGap::RouteEvidenceIncomplete)?;
                    if captured_state
                        || invoked
                            .receiver
                            .is_some_and(|receiver| related.contains(&receiver))
                        || invoked
                            .arguments
                            .iter()
                            .any(|argument| related.contains(&argument.value))
                    {
                        // An arbitrary call may mutate an aggregate or an address
                        // derived from it. The retained IR has no no-write proof
                        // for this operation, so the field state is incomplete.
                        return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                    }
                    continue;
                }
                let evidence = route
                    .procedure()
                    .semantics()
                    .evidence_row(event.evidence)
                    .ok_or(GoExternalFieldGap::RouteEvidenceIncomplete)?;
                if !evidence
                    .proof
                    .establishes_complete_evidence(&evidence.completeness)
                {
                    return Err(GoExternalFieldGap::RouteEvidenceIncomplete);
                }
                match &event.effect {
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Local | ValueFlowKind::LanguageDefined,
                        source,
                        target,
                    } if related_info
                        .fresh_local_bindings
                        .contains(&(*source, *target))
                        && related.contains(target) =>
                    {
                        memory.alias_object(*target, *source, cancellation)?;
                        if references.contains(source) {
                            references.insert(*target);
                        }
                    }
                    SemanticEffect::MemoryLoad {
                        location, result, ..
                    } if related.contains(result) => {
                        let location = route
                            .procedure()
                            .semantics()
                            .memory_location(*location)
                            .ok_or(GoExternalFieldGap::StorageUnknown)?;
                        if let MemoryLocationKind::LexicalCell { binding } = location.kind {
                            memory.alias_object(*result, binding, cancellation)?;
                            if references.contains(&binding) {
                                references.insert(*result);
                            }
                            continue;
                        }
                        let MemoryLocationKind::Dereference { address } = location.kind else {
                            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                        };
                        if !references.contains(&address) {
                            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                        }
                        let source_layout = memory
                            .tracked_layout(address, cancellation)?
                            .ok_or(GoExternalFieldGap::EffectiveStateIncomplete)?;
                        if !same_bound_layout(&source_layout, &layout) {
                            return Err(GoExternalFieldGap::FieldLayoutIncomplete);
                        }
                        let source = route
                            .procedure()
                            .value_handle(address)
                            .ok_or(GoExternalFieldGap::ValueOutsideProcedure)?;
                        let target = route
                            .procedure()
                            .value_handle(*result)
                            .ok_or(GoExternalFieldGap::ValueOutsideProcedure)?;
                        memory.copy_bound_layout(&source, &target, &layout, cancellation)?;
                        memory.track_layout(*result, &layout, cancellation)?;
                    }
                    SemanticEffect::AggregateInitializer { aggregate, .. }
                        if related.contains(aggregate) =>
                    {
                        let operand = route.initializer_at(point_index, event_index)?;
                        let binding = bind_go_aggregate_operand_source(
                            workspace,
                            &operand,
                            max_source_bytes,
                            max_source_nodes,
                            cancellation,
                        )
                        .map_err(|_| GoExternalFieldGap::SourceStateUnknown)?;
                        if let GoAggregateSourceBinding::Incomplete(gap) = binding {
                            return Err(gap);
                        }
                        let GoAggregateSourceBinding::Bound {
                            member: source_member,
                            owner: Some(owner),
                            ..
                        } = binding
                        else {
                            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                        };
                        if source_member != layout.fields[0].field.symbol().name {
                            continue;
                        }
                        if owner != layout.owner {
                            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                        }
                        let field =
                            resolve_go_external_field(overlay, &owner, &source_member, artifact)?;
                        let source = bind_go_external_field_source(
                            &field,
                            overlay,
                            artifact,
                            package,
                            max_source_nodes,
                            cancellation,
                        )?;
                        let bound = layout
                            .field_for_source(&source)
                            .ok_or(GoExternalFieldGap::FieldLayoutIncomplete)?;
                        memory.track_layout(*aggregate, &layout, cancellation)?;
                        memory.store_initializer(&operand, &source, bound.field, cancellation)?;
                    }
                    SemanticEffect::ValueFlow {
                        kind: ValueFlowKind::Transfer(transfer),
                        source,
                        target,
                    } if matches!(
                        transfer.kind,
                        TransferKind::AggregateCopy | TransferKind::Copy
                    ) && related.contains(target) =>
                    {
                        if references.contains(source) {
                            memory.alias_object(*target, *source, cancellation)?;
                            references.insert(*target);
                            continue;
                        }
                        let source_layout = memory.tracked_layout(*source, cancellation)?;
                        let source_layout =
                            source_layout.ok_or(GoExternalFieldGap::EffectiveStateIncomplete)?;
                        if !same_bound_layout(&source_layout, &layout) {
                            return Err(GoExternalFieldGap::FieldLayoutIncomplete);
                        }
                        let source_handle = route
                            .procedure()
                            .value_handle(*source)
                            .ok_or(GoExternalFieldGap::ValueOutsideProcedure)?;
                        let target_handle = route
                            .procedure()
                            .value_handle(*target)
                            .ok_or(GoExternalFieldGap::ValueOutsideProcedure)?;
                        memory.copy_bound_layout(
                            &source_handle,
                            &target_handle,
                            &layout,
                            cancellation,
                        )?;
                        memory.track_layout(*target, &layout, cancellation)?;
                    }
                    SemanticEffect::ValueFlow { kind, source, .. }
                        if related.contains(source)
                            && !matches!(
                                kind,
                                ValueFlowKind::Local
                                    | ValueFlowKind::Transfer(
                                        crate::analyzer::semantic::ValueTransfer {
                                            kind: TransferKind::Copy | TransferKind::AggregateCopy,
                                            ..
                                        }
                                    )
                            ) =>
                    {
                        // An unbound conversion or wrapper can carry an address
                        // out of this singleton state. Keep it open until the
                        // structured transfer has its own identity proof.
                        return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                    }
                    SemanticEffect::Assignment { target, value }
                        if related.contains(target)
                            && route.procedure().semantics().value(*target).is_some_and(
                                |value| matches!(&value.kind, SemanticValueKind::Address),
                            ) =>
                    {
                        if references.contains(value) {
                            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                        }
                        memory
                            .tracked_layout(*value, cancellation)?
                            .ok_or(GoExternalFieldGap::EffectiveStateIncomplete)?;
                        memory.alias_object(*target, *value, cancellation)?;
                        references.insert(*target);
                    }
                    SemanticEffect::Assignment { target, value }
                        if related.contains(target)
                            && !related_info
                                .fresh_local_bindings
                                .contains(&(*value, *target))
                            && !aggregate_copy_bindings.contains(&(*value, *target)) =>
                    {
                        return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                    }
                    SemanticEffect::MemoryStore {
                        location, value, ..
                    } => {
                        let location = route
                            .procedure()
                            .semantics()
                            .memory_location(*location)
                            .ok_or(GoExternalFieldGap::StorageUnknown)?;
                        let MemoryLocationKind::Field { base, member } = &location.kind else {
                            if let MemoryLocationKind::LexicalCell { binding } = location.kind
                                && (binding == *value
                                    || related_info
                                        .fresh_local_bindings
                                        .contains(&(*value, binding)))
                            {
                                continue;
                            }
                            if related.contains(value)
                                || related.iter().any(|value| location.kind.uses_value(*value))
                            {
                                return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                            }
                            continue;
                        };
                        if !related.contains(base) {
                            if related.contains(value) {
                                return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                            }
                            continue;
                        }
                        let (owner, field, source) =
                            self.bind_go_field_access_source(route.procedure(), member, &layout)?;
                        if owner != layout.owner {
                            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                        }
                        let expected = layout
                            .field_for_source(&source)
                            .ok_or(GoExternalFieldGap::FieldLayoutIncomplete)?;
                        if expected.field != field {
                            return Err(GoExternalFieldGap::ArtifactUnbound);
                        }
                        memory.track_layout(*base, &layout, cancellation)?;
                        memory.store_ids(*base, expected.field, *value, cancellation)?;
                    }
                    SemanticEffect::Gap { gap } => {
                        let resolved = self.exact_field_gap_is_resolved(
                            route, *gap, related, &layout, remaining,
                        )?;
                        if !resolved
                            && gap_affects_related(
                                route.procedure(),
                                *gap,
                                related,
                                argument,
                                call_site,
                            )
                        {
                            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
                        }
                    }
                    _ => {}
                }
            }
            if reached_call {
                break;
            }
        }
        if reached_call {
            Ok(())
        } else {
            Err(GoExternalFieldGap::RouteSetIncomplete)
        }
    }

    fn exact_field_gap_is_resolved(
        &self,
        route: &GoFieldReplayRoute<'a>,
        gap_id: crate::analyzer::semantic::SemanticGapId,
        related: &std::collections::HashSet<ValueId>,
        layout: &BoundGoExternalFieldLayout<'a>,
        remaining: &mut usize,
    ) -> Result<bool, GoExternalFieldGap> {
        let Self {
            workspace,
            max_source_bytes,
            max_source_nodes,
            cancellation,
            ..
        } = *self;
        use crate::analyzer::semantic::{
            SemanticCapability, SemanticGapDischarge, SemanticGapSubject,
        };
        let procedure = route.procedure();
        let Some(gap) = procedure.semantics().gap(gap_id) else {
            return Ok(false);
        };
        if gap.discharge == SemanticGapDischarge::RetainedEvaluationOrder {
            let mapping = procedure
                .semantics()
                .source_mapping(gap.source)
                .ok_or(GoExternalFieldGap::SourceStateUnknown)?;
            if mapping.kind != crate::analyzer::semantic::SourceMappingKind::Exact {
                return Ok(false);
            }
            let span = mapping.locator.anchor().span();
            // The enclosing operation's terminal writes run after every
            // operand. Only competing operand writes make this field state
            // depend on the producer's arbitrary operand ordering. Calls are
            // checked separately for related operands, capture mutation and
            // prior escape; this proof does not claim those calls are inert.
            for point in route.points() {
                if point.id() == gap.point {
                    continue;
                }
                for event in point_events(procedure, point.id())? {
                    charge_route_work(remaining, cancellation)?;
                    let affects_state = match event.effect {
                        SemanticEffect::Assignment { target, .. } => related.contains(&target),
                        SemanticEffect::AggregateInitializer { aggregate, .. } => {
                            related.contains(&aggregate)
                        }
                        SemanticEffect::ValueFlow {
                            kind: ValueFlowKind::Transfer(_),
                            target,
                            ..
                        } => related.contains(&target),
                        SemanticEffect::MemoryStore {
                            location, value, ..
                        } => {
                            related.contains(&value)
                                || procedure.semantics().memory_location(location).is_some_and(
                                    |location| {
                                        related.iter().any(|value| location.kind.uses_value(*value))
                                    },
                                )
                        }
                        _ => false,
                    };
                    if !affects_state {
                        continue;
                    }
                    let source = procedure
                        .semantics()
                        .source_mapping(event.source)
                        .ok_or(GoExternalFieldGap::SourceStateUnknown)?;
                    if source.kind != crate::analyzer::semantic::SourceMappingKind::Exact {
                        return Ok(false);
                    }
                    let event_span = source.locator.anchor().span();
                    if event_span.start_byte() >= span.start_byte()
                        && event_span.end_byte() <= span.end_byte()
                    {
                        return Ok(false);
                    }
                }
            }
            return Ok(true);
        }
        if gap.discharge != SemanticGapDischarge::ExactFieldLayout {
            return Ok(false);
        }
        if gap.capability == SemanticCapability::Values {
            let SemanticGapSubject::Value(aggregate) = gap.subject else {
                return Ok(false);
            };
            if !related.contains(&aggregate) {
                return Ok(false);
            }
            for (point_index, point) in route.points().iter().enumerate() {
                for (event_index, event) in point_events(procedure, point.id())?.iter().enumerate()
                {
                    let SemanticEffect::AggregateInitializer {
                        aggregate: actual, ..
                    } = event.effect
                    else {
                        continue;
                    };
                    if actual != aggregate {
                        continue;
                    }
                    let operand = route.initializer_at(point_index, event_index)?;
                    let binding = bind_go_aggregate_operand_source(
                        workspace,
                        &operand,
                        max_source_bytes,
                        max_source_nodes,
                        cancellation,
                    )
                    .map_err(|_| GoExternalFieldGap::SourceStateUnknown)?;
                    if let GoAggregateSourceBinding::Incomplete(gap) = binding {
                        return Err(gap);
                    }
                    if let GoAggregateSourceBinding::Bound {
                        owner: Some(owner),
                        member,
                        ..
                    } = binding
                        && owner == layout.owner
                        && layout.field_named(&member).is_some()
                    {
                        return Ok(true);
                    }
                }
            }
            return Ok(false);
        }
        if gap.capability != SemanticCapability::FieldMemory {
            return Ok(false);
        }
        let SemanticGapSubject::MemoryLocation(location_id) = gap.subject else {
            return Ok(false);
        };
        let Some(location) = procedure.semantics().memory_location(location_id) else {
            return Err(GoExternalFieldGap::StorageUnknown);
        };
        let MemoryLocationKind::Field { base, member } = &location.kind else {
            return Ok(false);
        };
        if !related.contains(base) {
            return Ok(false);
        }
        let (owner, field, source) = self.bind_go_field_access_source(procedure, member, layout)?;
        if owner != layout.owner {
            return Err(GoExternalFieldGap::EffectiveStateIncomplete);
        }
        let expected = layout
            .field_for_source(&source)
            .ok_or(GoExternalFieldGap::FieldLayoutIncomplete)?;
        if expected.field != field {
            return Err(GoExternalFieldGap::ArtifactUnbound);
        }
        Ok(true)
    }
}

fn point_events(
    procedure: &ProcedureHandle,
    point: crate::analyzer::semantic::ProgramPointId,
) -> Result<&[crate::analyzer::semantic::SemanticEvent], GoExternalFieldGap> {
    procedure
        .semantics()
        .point(point)
        .map(|point| point.events.as_ref())
        .ok_or(GoExternalFieldGap::PointOutsideProcedure)
}

fn gap_affects_related(
    procedure: &ProcedureHandle,
    gap_id: crate::analyzer::semantic::SemanticGapId,
    related: &std::collections::HashSet<ValueId>,
    argument: ValueId,
    call_site: crate::analyzer::semantic::CallSiteId,
) -> bool {
    use crate::analyzer::semantic::{SemanticCapability, SemanticGapSubject};
    let Some(gap) = procedure.semantics().gap(gap_id) else {
        return true;
    };
    if gap.discharge == crate::analyzer::semantic::SemanticGapDischarge::NonRejoiningExceptionalExit
    {
        // This query is conditional on reaching the consumer along a complete
        // normal route. A non-rejoining panic route never reaches that point.
        return false;
    }
    if gap.capability == SemanticCapability::FieldMemory
        && matches!(gap.subject, SemanticGapSubject::Procedure)
    {
        return true;
    }
    match gap.subject {
        SemanticGapSubject::Value(value) => related.contains(&value),
        SemanticGapSubject::MemoryLocation(location) => procedure
            .semantics()
            .memory_location(location)
            .is_some_and(|location| related.iter().any(|value| location.kind.uses_value(*value))),
        SemanticGapSubject::CallSite(call) => call == call_site,
        SemanticGapSubject::Point => related.contains(&argument),
        _ => false,
    }
}

impl<'a> GoExternalFieldQuery<'a> {
    fn bind_go_field_access_source(
        &self,
        procedure: &ProcedureHandle,
        locator: &SemanticLocator,
        layout: &BoundGoExternalFieldLayout<'a>,
    ) -> Result<(String, GoExternalField<'a>, GoStructFieldIdentity), GoExternalFieldGap> {
        let Self {
            workspace,
            overlay,
            artifact,
            package,
            max_source_bytes,
            max_source_nodes,
            cancellation,
            ..
        } = *self;
        use crate::analyzer::semantic::workspace_oracle::exact_source_for_procedure;
        if locator.mount() != procedure.artifact().key().mount()
            || locator.language() != procedure.artifact().key().language()
            || locator.path() != procedure.artifact().key().path()
            || !locator.belongs_to_procedure(procedure.semantics().locator())
        {
            return Err(GoExternalFieldGap::SourceStateUnknown);
        }
        let Some((_file, source)) =
            exact_source_for_procedure(workspace, procedure, max_source_bytes.min(1024 * 1024))
                .map_err(|_| GoExternalFieldGap::SourceStateUnknown)?
        else {
            return Err(GoExternalFieldGap::SourceStateUnknown);
        };
        let Some(tree) =
            brokk_bifrost_go::parse::parse_go_with_cancellation(&source, Some(cancellation))
        else {
            return Err(if cancellation.is_cancelled() {
                GoExternalFieldGap::Cancelled
            } else {
                GoExternalFieldGap::SourceStateUnknown
            });
        };
        let span = locator.anchor().span();
        let mut remaining = max_source_nodes;
        let mut stack = vec![tree.root_node()];
        let mut selected = None;
        while let Some(node) = stack.pop() {
            charge_route_work(&mut remaining, cancellation)?;
            if matches!(node.kind(), "identifier" | "field_identifier")
                && node.start_byte() == span.start_byte() as usize
                && node.end_byte() == span.end_byte() as usize
                && selected.replace(node).is_some()
            {
                return Err(GoExternalFieldGap::SourceStateUnknown);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
        let key = selected.ok_or(GoExternalFieldGap::SourceStateUnknown)?;
        let member = source
            .get(key.start_byte()..key.end_byte())
            .ok_or(GoExternalFieldGap::SourceStateUnknown)?
            .to_owned();
        let selector = key
            .parent()
            .filter(|node| node.kind() == "selector_expression")
            .ok_or(GoExternalFieldGap::SourceStateUnknown)?;
        selector
            .child_by_field_name("operand")
            .ok_or(GoExternalFieldGap::SourceStateUnknown)?;
        // The replay binds this base to exact imported aggregate storage.
        // A member occurrence supplies its AST name; the retained layout,
        // not an expression interpreted as type syntax, supplies its owner.
        let owner = layout.owner.clone();
        if layout.field_named(&member).is_none() {
            return Err(GoExternalFieldGap::FieldLayoutIncomplete);
        }
        let field = resolve_go_external_field(overlay, &owner, &member, artifact)?;
        let source_identity = bind_go_external_field_source(
            &field,
            overlay,
            artifact,
            package,
            remaining,
            cancellation,
        )?;
        Ok((owner, field, source_identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::ir::tests::{capabilities, key, minimal_procedure};
    use crate::analyzer::semantic::{
        EvidenceId, IndexedLocationIdentity, ProcedureId, SemanticArtifact, SemanticValue,
        SemanticValueKind, SourceMappingId,
    };

    fn artifact() -> SemanticArtifact {
        let key = key();
        let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
        for id in 0..5 {
            parts.values.push(SemanticValue {
                id: ValueId::new(id),
                kind: SemanticValueKind::Local,
                source: SourceMappingId::new(0),
                evidence: EvidenceId::new(0),
            });
        }
        SemanticArtifact::try_new(
            key,
            capabilities(&[crate::analyzer::semantic::SemanticCapability::Values]),
            vec![parts],
        )
        .unwrap()
    }

    #[test]
    fn external_field_memory_route_checks_actual_cfg_and_materialization() {
        use crate::analyzer::semantic::ProgramPointId;
        let source = std::sync::Arc::new(artifact());
        let foreign = std::sync::Arc::new(artifact());
        let procedure = source.procedure_handle(ProcedureId::new(0)).unwrap();
        let foreign = foreign.procedure_handle(ProcedureId::new(0)).unwrap();
        let entry = procedure.point_handle(ProgramPointId::new(0)).unwrap();
        let exit = procedure.point_handle(ProgramPointId::new(1)).unwrap();
        let exceptional = procedure.point_handle(ProgramPointId::new(2)).unwrap();
        let foreign_exit = foreign.point_handle(ProgramPointId::new(1)).unwrap();
        let cancellation = CancellationToken::new();
        let points = [entry.clone(), exit.clone()];
        let route = GoFieldReplayRoute::validate(&procedure, &points, 100, &cancellation).unwrap();
        assert_eq!(route.procedure(), &procedure);
        assert_eq!(route.points(), points.as_slice());
        for (points, expected) in [
            (vec![], GoExternalFieldGap::RouteNotFromEntry),
            (vec![exit.clone()], GoExternalFieldGap::RouteNotFromEntry),
            (
                vec![entry.clone(), exit.clone(), exceptional.clone()],
                GoExternalFieldGap::RouteDiscontinuous,
            ),
            (
                vec![entry.clone(), entry.clone()],
                GoExternalFieldGap::RouteRepeatedPoint,
            ),
            (
                vec![entry.clone(), exceptional],
                GoExternalFieldGap::RouteEvidenceIncomplete,
            ),
            (
                vec![entry, foreign_exit],
                GoExternalFieldGap::PointOutsideProcedure,
            ),
        ] {
            assert_eq!(
                GoFieldReplayRoute::validate(&procedure, &points, 100, &cancellation).unwrap_err(),
                expected
            );
        }
        assert_eq!(
            GoFieldReplayRoute::validate(&procedure, &points, 1, &cancellation).unwrap_err(),
            GoExternalFieldGap::BudgetExhausted
        );
        cancellation.cancel();
        assert_eq!(
            GoFieldReplayRoute::validate(&procedure, &points, 100, &cancellation).unwrap_err(),
            GoExternalFieldGap::Cancelled
        );
    }

    #[test]
    fn external_field_memory_operand_comes_from_retained_event_and_keeps_quality() {
        use crate::analyzer::semantic::{
            EvidenceCompleteness, ProgramPointId, SemanticEvent, SemanticRole,
        };
        let fixture = |partial| {
            let key = key();
            let mut parts = minimal_procedure(&key, ProcedureId::new(0), "main", 1);
            for id in 0..2 {
                parts.values.push(SemanticValue {
                    id: ValueId::new(id),
                    kind: SemanticValueKind::Temporary,
                    source: SourceMappingId::new(0),
                    evidence: EvidenceId::new(0),
                });
            }
            let locator = &parts.source_mappings[0].locator;
            let selector = SemanticLocator::new(
                key.mount(),
                key.path().clone(),
                key.language(),
                locator.declaration().clone(),
                SemanticRole::MemoryLocation,
                locator.anchor(),
            );
            let mut events = parts.points[0].events.to_vec();
            events.push(SemanticEvent::new(
                SemanticEffect::AggregateInitializer {
                    aggregate: ValueId::new(0),
                    selector,
                    value: ValueId::new(1),
                },
                SourceMappingId::new(0),
                EvidenceId::new(0),
            ));
            parts.points[0].events = events.into_boxed_slice();
            if partial {
                parts.evidence_rows[0].completeness =
                    EvidenceCompleteness::Partial("missing field layout".into());
            }
            std::sync::Arc::new(
                SemanticArtifact::try_new(
                    key,
                    capabilities(&[crate::analyzer::semantic::SemanticCapability::Values]),
                    vec![parts],
                )
                .unwrap(),
            )
        };
        let cancellation = CancellationToken::new();
        for partial in [false, true] {
            let artifact = fixture(partial);
            let procedure = artifact.procedure_handle(ProcedureId::new(0)).unwrap();
            let points = [procedure.point_handle(ProgramPointId::new(0)).unwrap()];
            let route =
                GoFieldReplayRoute::validate(&procedure, &points, 100, &cancellation).unwrap();
            assert_eq!(
                route.initializer_at(0, 0).unwrap_err(),
                GoExternalFieldGap::InitializerUnavailable
            );
            assert_eq!(
                route.initializer_at(1, 1).unwrap_err(),
                GoExternalFieldGap::InitializerUnavailable
            );
            if partial {
                assert_eq!(
                    route.initializer_at(0, 1).unwrap_err(),
                    GoExternalFieldGap::RouteEvidenceIncomplete
                );
            } else {
                let operand = route.initializer_at(0, 1).unwrap();
                assert_eq!(
                    operand.aggregate(),
                    &procedure.value_handle(ValueId::new(0)).unwrap()
                );
                assert_eq!(
                    operand.value(),
                    &procedure.value_handle(ValueId::new(1)).unwrap()
                );
                assert_eq!(operand.point(), &points[0]);
                assert_eq!(operand.event_index(), 1);
                assert_eq!(operand.selector().role(), SemanticRole::MemoryLocation);
            }
        }
    }

    #[test]
    fn external_field_memory_source_binding_uses_current_go_snapshot() {
        use crate::analyzer::semantic::{SemanticBudget, SemanticRequest};
        use crate::analyzer::{AnalyzerConfig, Language};
        use crate::inline_project::InlineTestProject;
        const SOURCE: &str = "package main\nimport ext \"example.test/dep\"\nfunc build() { _ = ext.Config{Callback: func() {}} }\n";
        let project = InlineTestProject::with_language(Language::Go)
            .file("go.mod", "module example.test/app\n")
            .file("main.go", SOURCE)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let file = project.file("main.go");
        let cancellation = CancellationToken::new();
        let mut budget = SemanticBudget::default();
        let outcome = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .unwrap();
        let artifact = outcome.available_value().expect("Go fixture materializes");
        let (procedure, target, event_index) = artifact
            .procedures()
            .iter()
            .find_map(|semantics| {
                semantics.points().iter().find_map(|point| {
                    point
                        .events
                        .iter()
                        .position(|event| {
                            matches!(event.effect, SemanticEffect::AggregateInitializer { .. })
                        })
                        .map(|index| {
                            (
                                artifact.procedure_handle(semantics.id()).unwrap(),
                                point.id,
                                index,
                            )
                        })
                })
            })
            .expect("unresolved keyed literal retains operand");
        let mut queue =
            std::collections::VecDeque::from([(procedure.semantics().entry_point(), Vec::new())]);
        let mut visited = std::collections::HashSet::new();
        let path = loop {
            let (point, mut prefix) = queue
                .pop_front()
                .expect("initializer reachable on normal route");
            if !visited.insert(point) {
                continue;
            }
            prefix.push(procedure.point_handle(point).unwrap());
            if point == target {
                break prefix;
            }
            for (_, edge) in procedure.semantics().successor_edges(point) {
                if edge.kind == ControlEdgeKind::Normal {
                    queue.push_back((edge.target_point, prefix.clone()));
                }
            }
        };
        let route =
            GoFieldReplayRoute::validate(&procedure, &path, 100_000, &cancellation).unwrap();
        let operand = route.initializer_at(path.len() - 1, event_index).unwrap();
        let oracle = crate::analyzer::semantic::WorkspaceSemanticOracle::with_limits(
            &workspace,
            crate::analyzer::semantic::OracleLimits::default(),
        );
        let mut heap_budget = SemanticBudget::default();
        let object = observe_go_aggregate_object(
            &oracle,
            &operand,
            &mut SemanticRequest::new(&mut heap_budget, &cancellation),
        )
        .unwrap();
        // The imported aggregate has a proven allocation, but unresolved
        // field semantics keep the oracle's coverage open. Retain that gap;
        // a single favorable candidate cannot authorize exact field replay.
        assert!(matches!(
            object,
            crate::analyzer::semantic::SemanticOutcome::Unknown { .. }
        ));
        let observed = object
            .available_value()
            .expect("partial allocation evidence survives");
        assert!(!observed.objects().is_closed());
        assert_eq!(observed.objects().candidates().len(), 1);
        assert!(observed.objects().candidates()[0].is_proven_complete());
        assert!(!go_aggregate_object_is_singleton(&operand, &object));
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let mut heap_budget = SemanticBudget::default();
        let interrupted = observe_go_aggregate_object(
            &oracle,
            &operand,
            &mut SemanticRequest::new(&mut heap_budget, &cancelled),
        )
        .unwrap();
        assert!(!go_aggregate_object_is_singleton(&operand, &interrupted));
        let binding = bind_go_aggregate_operand_source(
            &workspace,
            &operand,
            1024 * 1024,
            100_000,
            &cancellation,
        )
        .unwrap();
        let GoAggregateSourceBinding::Bound {
            file: bound_file,
            literal,
            type_syntax,
            member,
            owner,
        } = binding
        else {
            panic!("exact event/AST/value/allocation correspondence expected: {binding:?}");
        };
        assert_eq!(bound_file, file);
        assert_eq!(&SOURCE[type_syntax.start..type_syntax.end], "ext.Config");
        assert_eq!(
            &SOURCE[literal.start..literal.end],
            "ext.Config{Callback: func() {}}"
        );
        assert_eq!(member, "Callback");
        assert_eq!(owner.as_deref(), Some("example.test/dep.Config"));
        assert!(matches!(
            bind_go_aggregate_operand_source(&workspace, &operand, 1024 * 1024, 0, &cancellation)
                .unwrap(),
            GoAggregateSourceBinding::Incomplete(GoExternalFieldGap::BudgetExhausted)
        ));
        file.write(SOURCE.replace("Callback", "Different")).unwrap();
        let stale = bind_go_aggregate_operand_source(
            &workspace,
            &operand,
            1024 * 1024,
            100_000,
            &cancellation,
        );
        assert!(
            matches!(
                stale,
                Err(crate::analyzer::semantic::SemanticProviderError::InvalidIdentity(_))
            ),
            "stale source must not reuse old selector: {stale:?}"
        );
    }

    #[test]
    fn external_field_memory_copy_separates_slots_and_saved_read_survives_overwrite() {
        let artifact = std::sync::Arc::new(artifact());
        let procedure = artifact.procedure_handle(ProcedureId::new(0)).unwrap();
        let overlay = crate::analyzer::semantic_model::go_external_receiver_test_overlay();
        let symbol = &overlay.symbols()[0];
        // The state engine receives a resolved field; resolver provenance is
        // tested separately. This test checks ordered state rather than names.
        let field = GoExternalField {
            symbol,
            artifact_sha256: "bytes",
            copy: MemoryValueCopy::Reference,
        };
        let cancellation = CancellationToken::new();
        let mut memory = GoExternalFieldMemory::new(&procedure, 100);
        memory
            .store_ids(ValueId::new(0), field, ValueId::new(2), &cancellation)
            .unwrap();
        let saved = memory
            .read_ids(ValueId::new(0), field, &cancellation)
            .unwrap();
        memory
            .copy_ids(ValueId::new(0), ValueId::new(1), &cancellation)
            .unwrap();
        memory
            .store_ids(ValueId::new(0), field, ValueId::new(3), &cancellation)
            .unwrap();
        assert_eq!(
            memory
                .read_ids(ValueId::new(0), field, &cancellation)
                .unwrap(),
            ValueId::new(3)
        );
        assert_eq!(
            memory
                .read_ids(ValueId::new(1), field, &cancellation)
                .unwrap(),
            saved
        );
        assert_eq!(saved, ValueId::new(2));
        let mut other_symbol = symbol.clone();
        other_symbol.provenance.pack_digest = "other pack".to_owned();
        let other = GoExternalField {
            symbol: &other_symbol,
            ..field
        };
        assert_eq!(
            memory.read_ids(ValueId::new(0), other, &cancellation),
            Err(GoExternalFieldGap::FieldUninitialized)
        );
    }

    #[test]
    fn external_field_memory_preserves_backing_store_and_refuses_inline_alias() {
        let artifact = std::sync::Arc::new(artifact());
        let procedure = artifact.procedure_handle(ProcedureId::new(0)).unwrap();
        let overlay = crate::analyzer::semantic_model::go_external_receiver_test_overlay();
        let cancellation = CancellationToken::new();
        for copy in [
            MemoryValueCopy::Reference,
            MemoryValueCopy::BackingStore {
                identity: IndexedLocationIdentity::Element,
            },
        ] {
            let field = GoExternalField {
                symbol: &overlay.symbols()[0],
                artifact_sha256: "bytes",
                copy,
            };
            let mut memory = GoExternalFieldMemory::new(&procedure, 100);
            memory
                .store_ids(ValueId::new(0), field, ValueId::new(2), &cancellation)
                .unwrap();
            memory
                .copy_ids(ValueId::new(0), ValueId::new(1), &cancellation)
                .unwrap();
            assert_eq!(
                memory
                    .read_ids(ValueId::new(1), field, &cancellation)
                    .unwrap(),
                ValueId::new(2)
            );
            assert_eq!(field.value_copy(), copy);
        }
        let field = GoExternalField {
            symbol: &overlay.symbols()[0],
            artifact_sha256: "bytes",
            copy: MemoryValueCopy::Value,
        };
        let mut memory = GoExternalFieldMemory::new(&procedure, 100);
        memory
            .store_ids(ValueId::new(0), field, ValueId::new(2), &cancellation)
            .unwrap();
        assert_eq!(
            memory.copy_ids(ValueId::new(0), ValueId::new(1), &cancellation),
            Err(GoExternalFieldGap::StorageUnknown)
        );
        assert_eq!(
            memory.read_ids(ValueId::new(1), field, &cancellation),
            Err(GoExternalFieldGap::StorageUnknown)
        );
    }

    #[test]
    fn external_field_memory_interruption_cannot_return_successful_empty_state() {
        let artifact = std::sync::Arc::new(artifact());
        let procedure = artifact.procedure_handle(ProcedureId::new(0)).unwrap();
        let overlay = crate::analyzer::semantic_model::go_external_receiver_test_overlay();
        let field = GoExternalField {
            symbol: &overlay.symbols()[0],
            artifact_sha256: "bytes",
            copy: MemoryValueCopy::Reference,
        };
        let cancellation = CancellationToken::new();
        let mut memory = GoExternalFieldMemory::new(&procedure, 0);
        assert_eq!(
            memory.store_ids(ValueId::new(0), field, ValueId::new(2), &cancellation),
            Err(GoExternalFieldGap::BudgetExhausted)
        );
        assert_eq!(
            memory.read_ids(ValueId::new(0), field, &cancellation),
            Err(GoExternalFieldGap::BudgetExhausted)
        );
        let mut memory = GoExternalFieldMemory::new(&procedure, 100);
        cancellation.cancel();
        assert_eq!(
            memory.read_ids(ValueId::new(0), field, &cancellation),
            Err(GoExternalFieldGap::Cancelled)
        );
    }

    #[test]
    fn external_field_memory_rejects_foreign_materialization_with_equal_value_ids() {
        let source = std::sync::Arc::new(artifact());
        let foreign = std::sync::Arc::new(artifact());
        let procedure = source.procedure_handle(ProcedureId::new(0)).unwrap();
        let foreign = foreign.procedure_handle(ProcedureId::new(0)).unwrap();
        let overlay = crate::analyzer::semantic_model::go_external_receiver_test_overlay();
        let field = GoExternalField {
            symbol: &overlay.symbols()[0],
            artifact_sha256: "bytes",
            copy: MemoryValueCopy::Reference,
        };
        let cancellation = CancellationToken::new();
        let mut memory = GoExternalFieldMemory::new(&procedure, 100);
        let object = procedure.value_handle(ValueId::new(0)).unwrap();
        let value = procedure.value_handle(ValueId::new(2)).unwrap();
        memory.store(&object, field, &value, &cancellation).unwrap();
        assert_eq!(memory.read(&object, field, &cancellation).unwrap(), value);
        let foreign_object = foreign.value_handle(ValueId::new(0)).unwrap();
        assert_eq!(
            memory.read(&foreign_object, field, &cancellation),
            Err(GoExternalFieldGap::ValueOutsideProcedure)
        );
        assert_eq!(
            memory.read(&object, field, &cancellation),
            Err(GoExternalFieldGap::ValueOutsideProcedure)
        );
    }

    #[test]
    fn external_field_memory_source_crosswalk_requires_actual_owner_locator() {
        use crate::analyzer::semantic_model::{
            ArtifactProducerLimits, Visibility, go_callback_source_field_test_overlay,
            read_exact_source_set,
        };
        let project =
            crate::inline_project::InlineTestProject::with_language(crate::analyzer::Language::Go)
                .file(
                    "api.go",
                    "package ssh\ntype Config struct { Callback func() }\n",
                )
                .build();
        let artifact = read_exact_source_set(
            project.file("api.go").root(),
            &[std::path::PathBuf::from("api.go")],
            1,
            1,
            &ArtifactProducerLimits::default(),
        )
        .unwrap();
        let overlay = go_callback_source_field_test_overlay(artifact.sha256());
        let field =
            resolve_go_external_field(&overlay, "example.test/ssh.Config", "Callback", &artifact)
                .unwrap();
        let package = super::super::GoPinnedPackage {
            import_path: "example.test/ssh".to_owned(),
            name: "ssh".to_owned(),
            files: vec!["api.go".to_owned()],
        };
        let cancellation = CancellationToken::new();
        let anchor = bind_go_external_field_source(
            &field,
            &overlay,
            &artifact,
            &package,
            100_000,
            &cancellation,
        )
        .unwrap();
        assert_eq!(anchor.name_anchors[0].text, "Callback");
        assert!(matches!(
            anchor.outer_type_shape,
            super::super::GoOuterTypeShape::Function(_)
        ));
        let wrong_locator = crate::analyzer::semantic_model::go_callback_field_test_overlay(
            artifact.sha256(),
            Visibility::Public,
            false,
        );
        let wrong_field = resolve_go_external_field(
            &wrong_locator,
            "example.test/ssh.Config",
            "Callback",
            &artifact,
        )
        .unwrap();
        assert_eq!(
            bind_go_external_field_source(
                &wrong_field,
                &wrong_locator,
                &artifact,
                &package,
                100_000,
                &cancellation
            ),
            Err(GoExternalFieldGap::DeclarationUnresolved)
        );
        assert_eq!(
            bind_go_external_field_source(&field, &overlay, &artifact, &package, 0, &cancellation),
            Err(GoExternalFieldGap::BudgetExhausted)
        );
        cancellation.cancel();
        assert_eq!(
            bind_go_external_field_source(
                &field,
                &overlay,
                &artifact,
                &package,
                100_000,
                &cancellation
            ),
            Err(GoExternalFieldGap::Cancelled)
        );
    }

    #[test]
    fn external_field_memory_binds_exact_artifact_and_abstains_on_private_conflict_and_lookalike() {
        use crate::analyzer::semantic_model::{
            ArtifactProducerLimits, Visibility, go_callback_field_test_overlay,
            read_exact_source_set,
        };
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("api.go"),
            "package ssh\ntype Config struct { Callback func() }\n",
        )
        .unwrap();
        let limits = ArtifactProducerLimits::default();
        let artifact = read_exact_source_set(
            root.path(),
            &[std::path::PathBuf::from("api.go")],
            1,
            1,
            &limits,
        )
        .unwrap();
        let overlay = go_callback_field_test_overlay(artifact.sha256(), Visibility::Public, false);
        let field =
            resolve_go_external_field(&overlay, "example.test/ssh.Config", "Callback", &artifact)
                .unwrap();
        assert_eq!(field.value_copy(), MemoryValueCopy::Reference);
        assert_eq!(field.artifact_sha256(), artifact.sha256());
        assert_eq!(field.symbol().id, "field.callback");
        let wrong = go_callback_field_test_overlay("different bytes", Visibility::Public, false);
        assert_eq!(
            resolve_go_external_field(&wrong, "example.test/ssh.Config", "Callback", &artifact)
                .unwrap_err(),
            GoExternalFieldGap::ArtifactUnbound
        );
        for (visibility, conflict) in [(Visibility::Private, false), (Visibility::Public, true)] {
            let overlay = go_callback_field_test_overlay(artifact.sha256(), visibility, conflict);
            assert_eq!(
                resolve_go_external_field(
                    &overlay,
                    "example.test/ssh.Config",
                    "Callback",
                    &artifact
                )
                .unwrap_err(),
                GoExternalFieldGap::DeclarationUnresolved
            );
        }
        assert_eq!(
            resolve_go_external_field(&overlay, "local.ssh.Config", "Callback", &artifact)
                .unwrap_err(),
            GoExternalFieldGap::DeclarationUnresolved
        );
    }
}
