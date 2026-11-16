//! Activation-owned checks for schema-35 transfer component paths.
//!
//! Decode admits syntax only. The selected overlay supplies each declaration's
//! authoritative signature; summaries never supply a second signature copy.

use std::sync::Arc;

use crate::CancellationToken;
use crate::analyzer::semantic::PatternProjectionStep;
use crate::analyzer::semantic_model::alias_resolution::{
    AliasCursorContext, AliasCursorValue, AliasExpansionRefusal, AliasTypeCursor,
    normalize_alias_cursor,
};
use crate::analyzer::semantic_model::overlay::{
    ModelProvider, ModelProviderSelection, ModelTypeOwnerAnswer, SemanticModelCallableKey,
    SemanticModelSymbol, SemanticModelSymbolKind, owner_declaration,
};
use crate::analyzer::semantic_model::{
    AuthoredSummaryInput, AuthoredSummaryOutput, CompiledProcedureSummary, Completeness, Parameter,
    PayloadKind, ResolvedActiveSemanticModels, SUMMARY_ENDPOINT_PROJECTION_MIN_SCHEMA_VERSION,
    SemanticModelOverlay, SemanticModelOverlayBuildError, SummaryEndpointPath, TupleFieldSlot,
    TypeKind, TypeRef,
};
use crate::analyzer::store::active_models::{ActiveSemanticModelShard, ProcedureSummaryMatch};
use crate::hash::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SummaryEndpointProjectionSide {
    Input,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SummaryEndpointProjectionRefusal {
    UnboundDeclaration,
    UnavailableType,
    UnsupportedLanguage,
    InvalidPath,
    TypeExpansionLimit,
    AliasMissingTarget,
    AliasUnresolvableTarget,
    AliasCycle,
    AliasArityMismatch,
}

/// A refused transfer keeps the identities of its author, record and endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryEndpointProjectionDiagnostic {
    pub pack_id: String,
    pub record_id: String,
    pub transfer_ordinal: u32,
    pub endpoint: SummaryEndpointProjectionSide,
    pub reason: SummaryEndpointProjectionRefusal,
    pub step: Option<u32>,
    pub detail: String,
}

/// One immutable overlay publication's admission. Empty rejection lists are
/// positive checks, distinct from a record that was never checked.
#[derive(Debug, Default)]
pub(crate) struct SummaryEndpointAdmission {
    records: HashMap<String, HashMap<String, Box<[u32]>>>,
    diagnostics: Vec<SummaryEndpointProjectionDiagnostic>,
    endpoint_projections_enabled: bool,
}

impl SummaryEndpointAdmission {
    pub(crate) const fn endpoint_projections_enabled(&self) -> bool {
        self.endpoint_projections_enabled
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty() && self.diagnostics.is_empty()
    }

    pub(crate) fn build(
        overlay: &SemanticModelOverlay,
        active: &ResolvedActiveSemanticModels,
        cancellation: &CancellationToken,
    ) -> Result<Self, SemanticModelOverlayBuildError> {
        let mut admission = Self::default();
        for shard in active.shards() {
            if shard.manifest.schema_version < SUMMARY_ENDPOINT_PROJECTION_MIN_SCHEMA_VERSION
                || shard.descriptor.payload_kind != PayloadKind::ProcedureSummaries
            {
                continue;
            }
            if cancellation.is_cancelled() {
                return Err(SemanticModelOverlayBuildError::Cancelled);
            }
            let mut roots = Vec::new();
            if let Some(decoded) = &shard.decoded {
                if let Some(summaries) = decoded.payload().procedure_summaries() {
                    roots.extend(summaries.iter().map(|record| record.id.clone()));
                }
            } else {
                active.visit_procedure_summary_targets(|digest, _, targets| {
                    if digest == shard.manifest.content_sha256 {
                        roots.extend(targets.map(|(id, _)| id.to_owned()));
                    }
                })?;
            }
            let records =
                active.procedure_summary_family(&shard, roots.iter().map(String::as_str))?;
            for record in records.iter() {
                if !has_projected_transfers(record) {
                    continue;
                }
                let binding = if shard.manifest.language == "rust" {
                    crate::analyzer::semantic::authored_procedure_target_identity(
                        &record.target.path,
                        &record.target.symbol,
                    )
                    .map(|(owner, member)| {
                        overlay.callable_for_target(SemanticModelCallableKey::new(
                            &shard.manifest.language,
                            &owner,
                            member,
                            record.target.has_receiver,
                            record.target.parameter_count,
                        ))
                    })
                } else {
                    None
                };
                let bound = binding.as_ref().and_then(|binding| binding.unique());
                let mut rejected = Vec::new();
                for (ordinal, transfer) in record.transfers.iter().enumerate() {
                    let endpoints = [
                        (SummaryEndpointProjectionSide::Input, transfer.input.path()),
                        (
                            SummaryEndpointProjectionSide::Output,
                            transfer.output.path(),
                        ),
                    ];
                    let projected = endpoints.iter().any(|(_, path)| path.is_some());
                    let rejected_before = rejected.len();
                    for (side, path) in endpoints {
                        let Some(path) = path else {
                            continue;
                        };
                        if cancellation.is_cancelled() {
                            return Err(SemanticModelOverlayBuildError::Cancelled);
                        }
                        let failure = if shard.manifest.language != "rust" {
                            Some(SummaryEndpointProjectionFailure::new(
                                SummaryEndpointProjectionRefusal::UnsupportedLanguage,
                                "this activation has no language-owned projection check",
                            ))
                        } else if let Some(bound) = &bound {
                            let base = match side {
                                SummaryEndpointProjectionSide::Input => {
                                    input_type(overlay, active, bound, &transfer.input)
                                }
                                SummaryEndpointProjectionSide::Output => output_type(
                                    overlay,
                                    active,
                                    bound,
                                    &transfer.output,
                                    record.normal_result_count,
                                ),
                            };
                            match base {
                                Some(base) => check_path(
                                    overlay,
                                    active,
                                    &shard.manifest.language,
                                    base,
                                    ModelProvider::from(&bound.provenance),
                                    path,
                                    cancellation,
                                )?,
                                None => Some(SummaryEndpointProjectionFailure::new(
                                    SummaryEndpointProjectionRefusal::UnavailableType,
                                    "the bound declaration does not establish this endpoint's type",
                                )),
                            }
                        } else {
                            Some(SummaryEndpointProjectionFailure::new(
                                SummaryEndpointProjectionRefusal::UnboundDeclaration,
                                format!(
                                    "no unique authoritative declaration binds {:?}",
                                    record.target
                                ),
                            ))
                        };
                        if let Some(failure) = failure {
                            rejected.push(ordinal as u32);
                            admission
                                .diagnostics
                                .push(SummaryEndpointProjectionDiagnostic {
                                    pack_id: shard.manifest.pack_id.clone(),
                                    record_id: record.id.clone(),
                                    transfer_ordinal: ordinal as u32,
                                    endpoint: side,
                                    reason: failure.reason,
                                    step: failure.step,
                                    detail: failure.detail,
                                });
                        }
                    }
                    admission.endpoint_projections_enabled |=
                        projected && rejected.len() == rejected_before;
                }
                rejected.sort_unstable();
                rejected.dedup();
                admission
                    .records
                    .entry(shard.manifest.semantic_sha256.clone())
                    .or_default()
                    .insert(record.id.clone(), rejected.into_boxed_slice());
            }
        }
        Ok(admission)
    }

    pub(crate) fn diagnostics(&self) -> &[SummaryEndpointProjectionDiagnostic] {
        &self.diagnostics
    }

    pub(crate) fn retained_bytes(&self) -> u64 {
        let map_bytes = self.records.capacity()
            * std::mem::size_of::<(String, HashMap<String, Box<[u32]>>)>()
            + self
                .records
                .iter()
                .map(|(digest, records)| {
                    digest.capacity()
                        + records.capacity() * std::mem::size_of::<(String, Box<[u32]>)>()
                        + records
                            .iter()
                            .map(|(id, rejected)| {
                                id.capacity() + std::mem::size_of_val(rejected.as_ref())
                            })
                            .sum::<usize>()
                })
                .sum::<usize>();
        let diagnostics = self.diagnostics.capacity()
            * std::mem::size_of::<SummaryEndpointProjectionDiagnostic>()
            + self
                .diagnostics
                .iter()
                .map(|diagnostic| {
                    diagnostic.pack_id.capacity()
                        + diagnostic.record_id.capacity()
                        + diagnostic.detail.capacity()
                })
                .sum::<usize>();
        std::mem::size_of::<Self>()
            .saturating_add(map_bytes)
            .saturating_add(diagnostics) as u64
    }

    pub(crate) fn apply_match(&self, mut matched: ProcedureSummaryMatch) -> ProcedureSummaryMatch {
        for selected in &mut matched.records {
            selected.record = self.apply_record(&selected.shard, &selected.record);
        }
        matched
    }

    pub(crate) fn apply_record(
        &self,
        shard: &ActiveSemanticModelShard,
        record: &Arc<CompiledProcedureSummary>,
    ) -> Arc<CompiledProcedureSummary> {
        if !has_projected_transfers(record) {
            return Arc::clone(record);
        }
        let checked = self
            .records
            .get(&shard.manifest.semantic_sha256)
            .and_then(|records| records.get(&record.id));
        if checked.is_some_and(|rejected| rejected.is_empty()) {
            return Arc::clone(record);
        }
        let mut filtered = (**record).clone();
        filtered.transfers = record
            .transfers
            .iter()
            .enumerate()
            .filter(|(ordinal, transfer)| match checked {
                Some(rejected) => rejected.binary_search(&(*ordinal as u32)).is_err(),
                None => transfer.input.path().is_none() && transfer.output.path().is_none(),
            })
            .map(|(_, transfer)| transfer.clone())
            .collect();
        // A refused positive claim cannot become a complete negative summary.
        filtered.completeness = Completeness::Partial;
        Arc::new(filtered)
    }
}

fn has_projected_transfers(record: &CompiledProcedureSummary) -> bool {
    record
        .transfers
        .iter()
        .any(|transfer| transfer.input.path().is_some() || transfer.output.path().is_some())
}

fn receiver_type(
    overlay: &SemanticModelOverlay,
    active: &ResolvedActiveSemanticModels,
    member: &SemanticModelSymbol,
) -> Option<TypeRef> {
    let candidates = overlay.symbols_with_id_for(member.owner_id.as_deref()?, &member.language);
    let mut owners = candidates
        .records
        .iter()
        .filter(|owner| owner.provenance.pack_digest == member.provenance.pack_digest);
    let owner = owners.next()?;
    if owners.next().is_some() {
        return None;
    }
    let declaration = owner_declaration(active, owner)?;
    Some(TypeRef::Declared {
        id: owner.id.clone(),
        arguments: declaration
            .type_parameters
            .iter()
            .map(|name| TypeRef::TypeParameter { name: name.clone() })
            .collect(),
        nullable: false,
    })
}

fn input_type(
    overlay: &SemanticModelOverlay,
    active: &ResolvedActiveSemanticModels,
    member: &SemanticModelSymbol,
    input: &AuthoredSummaryInput,
) -> Option<TypeRef> {
    match input {
        AuthoredSummaryInput::Receiver { .. } => receiver_type(overlay, active, member),
        AuthoredSummaryInput::Parameter { ordinal, .. } => member
            .structured_signature
            .as_ref()?
            .parameters
            .get(*ordinal as usize)
            .map(|parameter| parameter.r#type.clone()),
    }
}

fn output_type(
    overlay: &SemanticModelOverlay,
    active: &ResolvedActiveSemanticModels,
    member: &SemanticModelSymbol,
    output: &AuthoredSummaryOutput,
    count: Option<u32>,
) -> Option<TypeRef> {
    match output {
        AuthoredSummaryOutput::NormalReturn { .. } => {
            member.structured_signature.as_ref()?.returns.clone()
        }
        AuthoredSummaryOutput::IndexedNormalReturn { ordinal, .. } => {
            let returns = member.structured_signature.as_ref()?.returns.as_ref()?;
            if count == Some(1) && *ordinal == 0 {
                Some(returns.clone())
            } else if let TypeRef::Tuple { elements } = returns {
                elements.get(*ordinal as usize).cloned()
            } else {
                None
            }
        }
        AuthoredSummaryOutput::Receiver { .. } => receiver_type(overlay, active, member),
        _ => None,
    }
}

#[derive(Debug)]
pub struct SummaryEndpointProjectionFailure {
    pub reason: SummaryEndpointProjectionRefusal,
    pub step: Option<u32>,
    pub detail: String,
}

impl SummaryEndpointProjectionFailure {
    fn new(reason: SummaryEndpointProjectionRefusal, detail: impl Into<String>) -> Self {
        Self {
            reason,
            step: None,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug)]
enum ProjectionValue {
    Type(TypeRef),
    VariantPayload {
        fields: Vec<Parameter>,
        layout: VariantPayloadLayout,
    },
}

#[derive(Clone, Copy, Debug)]
enum VariantPayloadLayout {
    Tuple,
    Named,
}

fn variant_payload(fields: Vec<Parameter>) -> Option<ProjectionValue> {
    let layout = if fields.iter().enumerate().all(|(ordinal, field)| {
        field
            .name
            .as_deref()
            .is_none_or(|name| name == ordinal.to_string())
    }) {
        VariantPayloadLayout::Tuple
    } else {
        let mut names = HashSet::default();
        if !fields.iter().all(|field| {
            field.name.as_deref().is_some_and(|name| {
                !name.is_empty()
                    && !name.bytes().all(|byte| byte.is_ascii_digit())
                    && names.insert(name)
            })
        }) {
            return None;
        }
        VariantPayloadLayout::Named
    };
    Some(ProjectionValue::VariantPayload { fields, layout })
}

type TypeCursor = AliasTypeCursor<ProjectionValue>;

impl AliasCursorValue for ProjectionValue {
    fn type_ref(&self) -> Option<&TypeRef> {
        match self {
            Self::Type(value) => Some(value),
            Self::VariantPayload { .. } => None,
        }
    }

    fn from_type_ref(value: TypeRef) -> Self {
        Self::Type(value)
    }
}

impl From<AliasExpansionRefusal> for SummaryEndpointProjectionRefusal {
    fn from(value: AliasExpansionRefusal) -> Self {
        match value {
            AliasExpansionRefusal::AliasMissingTarget => Self::AliasMissingTarget,
            AliasExpansionRefusal::AliasUnresolvableTarget => Self::AliasUnresolvableTarget,
            AliasExpansionRefusal::AliasCycle => Self::AliasCycle,
            AliasExpansionRefusal::AliasArityMismatch => Self::AliasArityMismatch,
        }
    }
}

/// Observe the endpoint wrapper's expansion for cross-consumer contract tests.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn endpoint_alias_expansion_for_test(
    overlay: &SemanticModelOverlay,
    active: &ResolvedActiveSemanticModels,
    base: TypeRef,
    provider: ModelProvider,
    cancellation: &CancellationToken,
) -> Result<
    (
        Option<super::alias_resolution::AliasExpansionFailure>,
        TypeRef,
        Option<TypeRef>,
    ),
    SemanticModelOverlayBuildError,
> {
    let mut current = TypeCursor::new(ProjectionValue::Type(base), provider);
    let mut context = AliasCursorContext::default();
    let selection = active.model_provider_selection();
    context.begin_normalization();
    let failure = normalize_alias_cursor(
        overlay,
        active,
        "rust",
        &selection,
        &mut current,
        &mut context,
        cancellation,
        |_| false,
    )?;
    let root = current
        .value
        .type_ref()
        .expect("test starts with a type")
        .clone();
    if failure.is_some() {
        return Ok((failure, root, None));
    }
    let first = match &root {
        TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
            arguments.first().cloned()
        }
        TypeRef::ByRef { element, .. } => Some((**element).clone()),
        _ => None,
    };
    if let Some(first) = first {
        current.value = ProjectionValue::Type(first);
        context.begin_normalization();
        let failure = normalize_alias_cursor(
            overlay,
            active,
            "rust",
            &selection,
            &mut current,
            &mut context,
            cancellation,
            |_| false,
        )?;
        return Ok((failure, root, current.value.type_ref().cloned()));
    }
    Ok((None, root, None))
}

/// Validate a policy source path against the selected declaration's return type.
/// The selected member supplies both type authority and defining provider.
pub fn validate_return_projection(
    overlay: &SemanticModelOverlay,
    active: &ResolvedActiveSemanticModels,
    member: &SemanticModelSymbol,
    path: &SummaryEndpointPath,
    cancellation: &CancellationToken,
) -> Result<Option<SummaryEndpointProjectionFailure>, SemanticModelOverlayBuildError> {
    if member.language != "rust" {
        return Ok(Some(SummaryEndpointProjectionFailure::new(
            SummaryEndpointProjectionRefusal::UnsupportedLanguage,
            "this activation has no language-owned projection check",
        )));
    }
    if path.is_empty() {
        return Ok(Some(SummaryEndpointProjectionFailure::new(
            SummaryEndpointProjectionRefusal::InvalidPath,
            "a present return projection must select a component",
        )));
    }
    let Some(base) = member
        .structured_signature
        .as_ref()
        .and_then(|signature| signature.returns.clone())
        .filter(|ty| !matches!(ty, TypeRef::Unknown))
    else {
        return Ok(Some(SummaryEndpointProjectionFailure::new(
            SummaryEndpointProjectionRefusal::UnavailableType,
            "the selected declaration does not establish its return type",
        )));
    };
    check_path(
        overlay,
        active,
        &member.language,
        base,
        ModelProvider::from(&member.provenance),
        path,
        cancellation,
    )
}

/// Environments point only to older environments. Binding an inner owner's T
/// cannot overwrite the outer owner's T, even when both names are identical.
fn check_path(
    overlay: &SemanticModelOverlay,
    active: &ResolvedActiveSemanticModels,
    language: &str,
    base: TypeRef,
    provider: ModelProvider,
    path: &SummaryEndpointPath,
    cancellation: &CancellationToken,
) -> Result<Option<SummaryEndpointProjectionFailure>, SemanticModelOverlayBuildError> {
    let mut normalization = AliasCursorContext::default();
    let mut current = TypeCursor {
        value: ProjectionValue::Type(base),
        environment: None,
        provider,
        alias_context: None,
    };
    let selection = active.model_provider_selection();
    for (index, step) in path.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Err(SemanticModelOverlayBuildError::Cancelled);
        }
        normalization.begin_normalization();
        let next = 'projection: {
            loop {
                if let Some(failure) = normalize_alias_cursor(
                    overlay,
                    active,
                    language,
                    &selection,
                    &mut current,
                    &mut normalization,
                    cancellation,
                    |_| false,
                )? {
                    return Ok(Some(SummaryEndpointProjectionFailure {
                        reason: failure.reason.into(),
                        step: Some(index as u32),
                        detail: failure.detail.into(),
                    }));
                }
                let ProjectionValue::Type(TypeRef::ByRef { element, .. }) = &current.value else {
                    break;
                };
                // Dereferencing belongs to component projection, not alias
                // expansion. Keep this normalization step's refusal history.
                current.value = ProjectionValue::Type((**element).clone());
            }
            match &current.value {
                ProjectionValue::VariantPayload { fields, layout } => match (layout, step) {
                    (VariantPayloadLayout::Tuple, PatternProjectionStep::Tuple(ordinal)) => fields
                        .get(*ordinal as usize)
                        .map(|field| field.r#type.clone()),
                    (VariantPayloadLayout::Named, PatternProjectionStep::Named(name)) => fields
                        .iter()
                        .find(|field| field.name.as_deref() == Some(name.as_ref()))
                        .map(|field| field.r#type.clone()),
                    _ => None,
                }
                .map(|ty| TypeCursor {
                    value: ProjectionValue::Type(ty),
                    environment: current.environment,
                    provider: current.provider.clone(),
                    alias_context: None,
                }),
                ProjectionValue::Type(
                    TypeRef::Array { element }
                    | TypeRef::Slice { element }
                    | TypeRef::FixedArray { element, .. },
                ) if matches!(step, PatternProjectionStep::Element) => Some(TypeCursor {
                    value: ProjectionValue::Type((**element).clone()),
                    environment: current.environment,
                    provider: current.provider.clone(),
                    alias_context: current.alias_context,
                }),
                ProjectionValue::Type(TypeRef::Tuple { elements }) => match step {
                    PatternProjectionStep::Tuple(ordinal) => elements
                        .get(*ordinal as usize)
                        .cloned()
                        .map(|ty| TypeCursor {
                            value: ProjectionValue::Type(ty),
                            environment: current.environment,
                            provider: current.provider.clone(),
                            alias_context: current.alias_context,
                        }),
                    _ => None,
                },
                ProjectionValue::Type(ty @ (TypeRef::Named { .. } | TypeRef::Declared { .. })) => {
                    let providers = match ty {
                        TypeRef::Declared { .. } => {
                            ModelProviderSelection::new([current.provider.clone()])
                        }
                        _ => selection.clone(),
                    };
                    let owner =
                        match overlay.model_type_owner(language, ty, &providers, cancellation)? {
                            ModelTypeOwnerAnswer::Unique { declaration, .. } => Some(declaration),
                            _ => None,
                        };
                    if owner.is_none() && normalization.expanded_alias() {
                        return Ok(Some(SummaryEndpointProjectionFailure {
                            reason: SummaryEndpointProjectionRefusal::AliasUnresolvableTarget,
                            step: Some(index as u32),
                            detail: "the alias target has no unique selected declaring provider"
                                .into(),
                        }));
                    }
                    if let Some(owner) = owner {
                        let declaration = owner_declaration(active, &owner);
                        let arguments = match ty {
                            TypeRef::Named { arguments, .. }
                            | TypeRef::Declared { arguments, .. } => arguments,
                            _ => unreachable!(),
                        };
                        if let Some(declaration) = declaration.filter(|declaration| {
                            declaration.type_parameters.len() == arguments.len()
                        }) {
                            let environment = normalization.environments.len();
                            normalization.environments.push(
                                declaration
                                    .type_parameters
                                    .iter()
                                    .zip(arguments)
                                    .map(|(name, argument)| {
                                        (
                                            name.clone(),
                                            TypeCursor {
                                                value: ProjectionValue::Type(argument.clone()),
                                                environment: current.environment,
                                                provider: current.provider.clone(),
                                                alias_context: current.alias_context,
                                            },
                                        )
                                    })
                                    .collect(),
                            );
                            let value = match step {
                                PatternProjectionStep::Element => {
                                    // A generic parameter's position is not element authority.
                                    // Only the selected declaration's explicit Iterator or
                                    // IntoIterator Item binding establishes indexed contents.
                                    let mut item = None;
                                    let mut unproven = false;
                                    for implementation in &declaration.implemented_traits {
                                        let trait_owner = overlay.model_type_owner(
                                            language,
                                            &implementation.trait_type,
                                            &selection,
                                            cancellation,
                                        )?;
                                        let ModelTypeOwnerAnswer::Unique {
                                            declaration: trait_owner,
                                            ..
                                        } = trait_owner
                                        else {
                                            continue;
                                        };
                                        if ![
                                            "core.iter.Iterator",
                                            "std.iter.Iterator",
                                            "core.iter.traits.iterator.Iterator",
                                            "core.iter.IntoIterator",
                                            "std.iter.IntoIterator",
                                            "core.iter.traits.collect.IntoIterator",
                                        ]
                                        .iter()
                                        .any(|name| {
                                            trait_owner.qualified_name == *name
                                                || trait_owner
                                                    .aliases
                                                    .iter()
                                                    .any(|alias| alias == name)
                                        }) {
                                            continue;
                                        }
                                        let mut bindings = std::collections::HashMap::new();
                                        let mut lookup_error = None;
                                        if let Some(pattern) = &implementation.self_pattern {
                                            let applies = pattern.bind_type_arguments(
                                                ty,
                                                &mut bindings,
                                                |actual, expected| {
                                                    let mut resolve = |ty: &TypeRef| match overlay
                                                        .model_type_owner(
                                                            language,
                                                            ty,
                                                            &selection,
                                                            cancellation,
                                                        ) {
                                                        Ok(ModelTypeOwnerAnswer::Unique {
                                                            declaration,
                                                            ..
                                                        }) => Some(declaration),
                                                        Ok(_) => None,
                                                        Err(error) => {
                                                            lookup_error = Some(error);
                                                            None
                                                        }
                                                    };
                                                    let actual = resolve(actual)?;
                                                    let expected = resolve(expected)?;
                                                    if actual.id == expected.id {
                                                        Some(true)
                                                    } else if [&actual, &expected].iter().any(
                                                        |symbol| {
                                                            owner_declaration(active, symbol)
                                                                .is_none_or(|fact| {
                                                                    fact.type_kind
                                                                        == TypeKind::TypeAlias
                                                                })
                                                        },
                                                    ) {
                                                        None
                                                    } else {
                                                        Some(false)
                                                    }
                                                },
                                            );
                                            if let Some(error) = lookup_error {
                                                return Err(error);
                                            }
                                            match applies {
                                                Some(false) => continue,
                                                None => {
                                                    unproven = true;
                                                    continue;
                                                }
                                                Some(true) => {}
                                            }
                                        } else if !implementation.type_parameters.is_empty() {
                                            unproven = true;
                                            continue;
                                        }
                                        // Conditional impl applicability needs independent proof;
                                        // an authored Item alone cannot discharge its bounds.
                                        if implementation.is_negative
                                            || !implementation.bounds.is_empty()
                                        {
                                            unproven = true;
                                            continue;
                                        }
                                        let mut item_bindings =
                                            normalization.environments[environment].clone();
                                        item_bindings.extend(bindings.into_iter().map(
                                            |(name, value)| {
                                                (
                                                    name,
                                                    TypeCursor {
                                                        value: ProjectionValue::Type(value),
                                                        environment: current.environment,
                                                        provider: current.provider.clone(),
                                                        alias_context: current.alias_context,
                                                    },
                                                )
                                            },
                                        ));
                                        // Self is the instantiated receiver, with its older
                                        // environment, rather than the Item environment itself.
                                        item_bindings.insert("Self".into(), current.clone());
                                        let item_environment = normalization.environments.len();
                                        normalization.environments.push(item_bindings);
                                        let mut associated = implementation
                                            .associated_types
                                            .iter()
                                            .filter(|binding| binding.name == "Item");
                                        let selected = associated
                                            .next()
                                            .filter(|_| associated.next().is_none());
                                        let Some(selected) = selected else {
                                            unproven = true;
                                            continue;
                                        };
                                        if item.is_some() {
                                            // Multiple applicable declarations need a type equality
                                            // proof before a single element type can be asserted.
                                            unproven = true;
                                            continue;
                                        }
                                        item = Some((selected.r#type.clone(), item_environment));
                                    }
                                    if unproven || item.is_none() {
                                        return Ok(Some(SummaryEndpointProjectionFailure {
                                            reason: SummaryEndpointProjectionRefusal::UnavailableType,
                                            step: Some(index as u32),
                                            detail: "the selected declaration does not establish one unconditional indexed Item type".into(),
                                        }));
                                    }
                                    let (value, environment) =
                                        item.expect("the element type was checked");
                                    current = TypeCursor {
                                        value: ProjectionValue::Type(value),
                                        environment: Some(environment),
                                        provider: ModelProvider::from(&owner.provenance),
                                        alias_context: None,
                                    };
                                    break 'projection Some(current.clone());
                                }
                                PatternProjectionStep::Variant {
                                    declaration: variant_id,
                                } if declaration.type_kind == TypeKind::Enum => {
                                    let variants =
                                        overlay.symbols_with_id_for(variant_id, language);
                                    let mut selected =
                                        variants.records.into_iter().filter(|variant| {
                                            variant.provenance.pack_digest
                                                == owner.provenance.pack_digest
                                        });
                                    let variant =
                                        selected.next().filter(|_| selected.next().is_none());
                                    variant
                                        .filter(|variant| {
                                            variant.kind == SemanticModelSymbolKind::Constant
                                                && variant.owner_id.as_deref()
                                                    == Some(owner.id.as_str())
                                        })
                                        .and_then(|variant| variant.structured_signature.clone())
                                        .filter(|signature| signature.returns.is_none())
                                        .and_then(|signature| variant_payload(signature.parameters))
                                }
                                PatternProjectionStep::Tuple(ordinal) => {
                                    declaration.tuple_fields.as_ref().and_then(|layout| {
                                        layout.fields.iter().find_map(|field| match field {
                                            TupleFieldSlot::Public {
                                                ordinal: field,
                                                r#type,
                                                ..
                                            } if field == ordinal => {
                                                Some(ProjectionValue::Type(r#type.clone()))
                                            }
                                            _ => None,
                                        })
                                    })
                                }
                                PatternProjectionStep::Named(name)
                                    if !name.bytes().all(|byte| byte.is_ascii_digit()) =>
                                {
                                    overlay
                                        .members_named_for_provider(
                                            &owner.id,
                                            name,
                                            language,
                                            &owner.provenance.pack_digest,
                                        )
                                        .unique()
                                        .and_then(|field| {
                                            if field.kind != SemanticModelSymbolKind::Field {
                                                return None;
                                            }
                                            field
                                                .value_type
                                                .clone()
                                                .or_else(|| {
                                                    field
                                                        .structured_signature
                                                        .as_ref()?
                                                        .returns
                                                        .clone()
                                                })
                                                .map(ProjectionValue::Type)
                                        })
                                }
                                _ => None,
                            };
                            value.map(|value| TypeCursor {
                                value,
                                environment: Some(environment),
                                provider: ModelProvider::from(&owner.provenance),
                                alias_context: None,
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            }
        };
        let Some(next) = next else {
            return Ok(Some(SummaryEndpointProjectionFailure {
                reason: SummaryEndpointProjectionRefusal::InvalidPath,
                step: Some(index as u32),
                detail: format!(
                    "projection {step:?} is not established by authoritative type {:?}",
                    current.value
                ),
            }));
        };
        current = next;
    }
    Ok(None)
}

/// A caller without a publication's admission cannot apply component claims.
/// Whole-value transfers remain usable through the legacy descriptor reader.
pub fn refuse_unvalidated_summary_match(matched: ProcedureSummaryMatch) -> ProcedureSummaryMatch {
    SummaryEndpointAdmission::default().apply_match(matched)
}

pub fn refuse_unvalidated_summary_record(
    shard: &ActiveSemanticModelShard,
    record: &Arc<CompiledProcedureSummary>,
) -> Arc<CompiledProcedureSummary> {
    SummaryEndpointAdmission::default().apply_record(shard, record)
}
