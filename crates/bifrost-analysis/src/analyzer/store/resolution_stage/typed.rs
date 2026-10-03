//! One-fragment stage projection and keyed typed reads. No data survives a query.

use super::super::resolution::with_resolution_read_progress_handler;
use super::super::resolution_prepare::resolution_rows::{code, from_code, namespace_code};
use super::super::resolution_prepare::typed_rows::{self, TypedBodyDecoder};
use super::super::resolution_selection::SelectedResolutionMountInventory;
use super::super::{Result, StoreError};
use super::codec;
use crate::CancellationToken;
use crate::analyzer::resolution::*;
#[cfg(test)]
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::resolution_facts::*;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
use rusqlite::{Connection, Row, params_from_iter};
use serde_json::{Value, json};

#[derive(Clone, Copy)]
struct StageBodyDecoder;
impl TypedBodyDecoder for StageBodyDecoder {
    fn semantic(self, cell: i64) -> SemanticId {
        codec::decode_semantic(cell)
    }
    fn signed_semantic(self, cell: i64) -> SemanticId {
        codec::decode_semantic(cell)
    }
    fn completion(self, body: Option<&str>) -> ResolutionCompletion {
        codec::decode_completion(body)
    }
}

fn semantic_pair(semantic: SemanticId) -> (Option<i64>, Option<i64>) {
    let cell = codec::encode_semantic(semantic);
    if cell < 0 {
        (None, Some(-cell))
    } else {
        (Some(cell), None)
    }
}

fn completion_value(completion: &ResolutionCompletion) -> Value {
    codec::encode_completion(completion)
        .map(|body| serde_json::from_str(&body).expect("stage completion JSON"))
        .unwrap_or(Value::Null)
}

// The row builder is alive for one fragment conversion. Semantic pairs name
// their physical columns explicitly; JSON bodies use the shared BODY layout.
struct EncodedRow {
    columns: Vec<String>,
    values: Vec<Value>,
    json_columns: Vec<usize>,
}
impl EncodedRow {
    fn new() -> Self {
        Self {
            columns: Vec::new(),
            values: Vec::new(),
            json_columns: Vec::new(),
        }
    }
    fn cell(&mut self, name: &str, value: impl Into<Value>) {
        self.columns.push(name.to_owned());
        self.values.push(value.into());
    }
    fn semantic(&mut self, name: &str, value: SemanticId) {
        let (key, shared) = semantic_pair(value);
        self.cell(&format!("{name}_key"), json!(key));
        self.cell(&format!("{name}_shared"), json!(shared));
    }
    fn optional_semantic(&mut self, name: &str, value: Option<SemanticId>) {
        let (key, shared) = value.map(semantic_pair).unwrap_or((None, None));
        self.cell(&format!("{name}_key"), json!(key));
        self.cell(&format!("{name}_shared"), json!(shared));
    }
    fn body(&mut self, name: &str, value: Value) {
        self.json_columns.push(self.values.len());
        self.cell(name, value);
    }
}

/// Visit complete canonical row descriptions without holding the whole fragment
/// twice. The callback either hashes a row or inserts it in the owner's transaction.
fn encode_rows(
    typed: &LoweredTypedFragment,
    cancellation: &CancellationToken,
    mut emit: impl FnMut(&str, usize, EncodedRow) -> Result<()>,
) -> Result<bool> {
    for (sequence, item) in typed.frontiers().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("slot", item.slot());
        row.cell("role", code(ALL_RESOLUTION_TYPE_SLOT_ROLES, item.role()));
        row.optional_semantic(
            "identity_reference",
            item.type_identity_reference().map(|(semantic, _)| semantic),
        );
        row.cell(
            "identity_reference_node",
            json!(
                item.type_identity_reference()
                    .map(|(_, node)| codec::encode_node(node))
            ),
        );
        emit("type_frontiers", sequence, row)?;
    }
    for (sequence, item) in typed.transfers().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("source_slot", item.source_slot());
        row.semantic("rule", item.rule().semantic());
        row.semantic("target_slot", item.rule().target_slot());
        row.cell(
            "kind",
            code(ALL_RESOLUTION_TYPE_TRANSFER_KINDS, item.kind()),
        );
        row.cell("indirection_delta", item.rule().indirection_delta());
        row.cell(
            "reference_indirection_delta",
            item.rule().reference_indirection_delta(),
        );
        row.cell(
            "value_transform",
            typed_rows::value_transform_code(item.rule().value_transform()),
        );
        row.body("completion", completion_value(item.rule().completion()));
        emit("type_transfers", sequence, row)?;
    }
    for (sequence, item) in typed.intrinsic_seeds().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("slot", item.frontier().slot());
        row.cell("kind", code(ALL_INTRINSIC_TYPE_KINDS, item.kind()));
        row.cell("spelling", item.spelling());
        row.body(
            "possible_values",
            Value::Array(
                item.frontier()
                    .possible_values()
                    .iter()
                    .map(|value| {
                        let ty = value.ty();
                        json!([
                            i64::from(value.addressable().is_some()),
                            codec::encode_semantic(ty.identity()),
                            ty.indirection(),
                            ty.reference_indirection(),
                            i64::from(value.addressable().unwrap_or(false))
                        ])
                    })
                    .collect(),
            ),
        );
        row.body("completion", completion_value(item.frontier().completion()));
        emit("intrinsic_seeds", sequence, row)?;
    }
    // Identity membership is a set even when different seed kinds share values.
    // This temporary set is bounded by this fragment conversion and released here.
    let mut identities = std::collections::BTreeSet::new();
    for seed in typed.intrinsic_seeds() {
        for value in seed.frontier().possible_values() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            identities.insert((value.ty().identity(), seed.frontier().slot()));
        }
    }
    for (sequence, (identity, slot)) in identities.into_iter().enumerate() {
        let mut row = EncodedRow::new();
        row.semantic("identity", identity);
        row.semantic("slot", slot);
        emit("intrinsic_seed_identities", sequence, row)?;
    }
    for (sequence, item) in typed.projections().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("reference", item.reference());
        row.semantic("output_slot", item.output_slot());
        row.cell("kind", code(ALL_BINDING_PROJECTION_KINDS, item.kind()));
        emit("binding_projections", sequence, row)?;
    }
    for (sequence, item) in typed.qualified_routes().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("reference", item.reference());
        row.semantic("qualifier_slot", item.qualifier_slot());
        row.semantic("lookup", item.lookup());
        row.semantic("source_lookup", item.source_lookup());
        row.semantic("projection_output_slot", item.projection_output_slot());
        row.semantic("coarse_gap_reason", item.coarse_gap_reason());
        row.cell("precedence_ordinal", i64::from(item.precedence_ordinal()));
        row.cell("namespace", namespace_code(item.namespace()));
        row.cell(
            "projection_kind",
            code(ALL_BINDING_PROJECTION_KINDS, item.projection_kind()),
        );
        row.cell("open_member_surface", i64::from(item.open_member_surface()));
        emit("qualified_routes", sequence, row)?;
    }
    for (sequence, item) in typed.declaration_types().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("definition", item.definition());
        row.semantic("slot", item.slot());
        row.cell("role", code(ALL_DECLARATION_TYPE_ROLES, item.role()));
        emit("declaration_types", sequence, row)?;
    }
    for (sequence, item) in typed.declaration_visibilities().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("definition", item.definition());
        row.cell("visibility", item.visibility().label());
        emit("declaration_visibilities", sequence, row)?;
    }
    for (sequence, item) in typed.member_scopes().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("definition", item.definition());
        row.cell("scope_head_node", codec::encode_node(item.scope_head()));
        emit("member_scopes", sequence, row)?;
    }
    for (sequence, item) in typed.member_owners().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("definition", item.definition());
        row.semantic("owner_definition", item.owner_definition());
        row.cell(
            "owner_scope_head_node",
            codec::encode_node(item.owner_scope_head()),
        );
        row.cell("member_kind", item.kind().label());
        row.cell("member_access", item.access().label());
        row.cell(
            "qualifier_compatibility",
            item.qualifier_compatibility().label(),
        );
        emit("member_owners", sequence, row)?;
    }
    for (sequence, item) in typed.deferred_member_owners().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("definition", item.definition());
        row.semantic("lookup", item.lookup());
        row.body(
            "body",
            json!([
                codec::encode_semantic(item.owner_frontier()),
                item.hierarchy_frontier().map(codec::encode_semantic),
                code(ALL_RESOLUTION_MEMBER_KINDS, item.kind()),
                code(ALL_RESOLUTION_MEMBER_ACCESSES, item.access()),
                code(
                    ALL_RESOLUTION_MEMBER_QUALIFIER_COMPATIBILITIES,
                    item.qualifier_compatibility()
                )
            ]),
        );
        emit("deferred_member_owners", sequence, row)?;
    }
    for (sequence, item) in typed.construction_requirements().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("definition", item.definition());
        row.semantic(
            "required_owner_definition",
            item.required_owner_definition(),
        );
        row.cell(
            "kind",
            code(ALL_RESOLUTION_CONSTRUCTION_REQUIREMENT_KINDS, item.kind()),
        );
        emit("construction_requirements", sequence, row)?;
    }
    for (sequence, item) in typed.supertypes().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("definition", item.definition());
        row.semantic("reference", item.reference());
        row.semantic("frontier", item.frontier());
        row.cell("kind", code(ALL_RESOLUTION_SUPERTYPE_KINDS, item.kind()));
        emit("supertypes", sequence, row)?;
    }
    for (sequence, item) in typed.property_gaps().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("definition", item.definition());
        row.semantic("frontier", item.frontier());
        row.semantic("reason", item.reason_semantic());
        row.cell("kind", code(ALL_RESOLUTION_GAP_KINDS, item.kind()));
        row.cell(
            "source_site",
            i64::try_from(item.source_site().index()).expect("site fits SQLite integer"),
        );
        emit("definition_property_gaps", sequence, row)?;
    }
    for (sequence, item) in typed.call_obligations().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("callee_reference", item.callee_reference());
        row.semantic("call", item.call());
        row.semantic("result_slot", item.result_slot());
        row.semantic("applicability_reason", item.applicability_reason());
        row.optional_semantic("receiver_slot", item.receiver_slot());
        row.cell(
            "explicit_type_argument_count",
            i64::from(item.explicit_type_argument_count()),
        );
        row.body(
            "argument_slots",
            json!(
                item.argument_slots()
                    .iter()
                    .copied()
                    .map(codec::encode_semantic)
                    .collect::<Vec<_>>()
            ),
        );
        row.body(
            "type_argument_slots",
            json!([
                item.type_argument_slots()
                    .iter()
                    .copied()
                    .map(codec::encode_semantic)
                    .collect::<Vec<_>>(),
                item.owner_type_argument_slots()
                    .iter()
                    .copied()
                    .map(codec::encode_semantic)
                    .collect::<Vec<_>>(),
                item.expected_result_slot().map(codec::encode_semantic),
                item.owner_type_segment().map(codec::encode_semantic),
                item.extra_result_slots()
                    .iter()
                    .copied()
                    .map(codec::encode_semantic)
                    .collect::<Vec<_>>()
            ]),
        );
        row.body(
            "eligible_rules",
            json!(
                item.eligible_rules()
                    .iter()
                    .map(|rule| code(ALL_RESOLUTION_ENGINE_RULE_KINDS, *rule))
                    .collect::<Vec<_>>()
            ),
        );
        row.body("completion", completion_value(item.completion()));
        emit("call_obligations", sequence, row)?;
    }
    let mut parameter_sequence = 0;
    for (sequence, item) in typed.callable_signatures().iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let mut row = EncodedRow::new();
        row.semantic("definition", item.definition());
        row.body(
            "body",
            json!([
                item.type_parameter_count(),
                item.parameters()
                    .iter()
                    .map(|parameter| json!([
                        codec::encode_semantic(parameter.definition()),
                        codec::encode_semantic(parameter.slot()),
                        i64::from(parameter.repeated())
                    ]))
                    .collect::<Vec<_>>(),
                completion_value(item.completion()),
                item.result_bindings()
                    .iter()
                    .map(|binding| json!([
                        binding.ordinal(),
                        binding.indirection_delta(),
                        binding.reference_indirection_delta()
                    ]))
                    .collect::<Vec<_>>(),
                item.receiver()
                    .map(|form| code(ALL_RESOLUTION_CALLABLE_RECEIVER_FORMS, form)),
                item.result_type_parameter().map(|parameter| json!([
                    parameter.ordinal(),
                    parameter.indirection_delta(),
                    parameter.reference_indirection_delta()
                ])),
                item.result_owner_type_parameter().map(|parameter| json!([
                    parameter.ordinal(),
                    parameter.indirection_delta(),
                    parameter.reference_indirection_delta()
                ])),
                item.result_types()
                    .iter()
                    .map(|result| json!([result.ordinal(), codec::encode_semantic(result.slot())]))
                    .collect::<Vec<_>>()
            ]),
        );
        emit("callable_signatures", sequence, row)?;
        for parameter in item.parameters() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let mut row = EncodedRow::new();
            row.semantic("parameter_definition", parameter.definition());
            row.semantic("signature_definition", item.definition());
            row.semantic("slot", parameter.slot());
            emit("callable_parameters", parameter_sequence, row)?;
            parameter_sequence += 1;
        }
    }
    Ok(!cancellation.is_cancelled())
}

/// Hash the full typed descriptor, including the exact nested completion bodies.
/// Producer IDs are provenance assigned later and are not descriptor contents.
#[cfg(test)]
pub(in crate::analyzer::store) fn typed_fragment_digest(
    fragment: &LoweredTypedFragment,
    cancellation: &CancellationToken,
) -> Result<Option<[u8; 32]>> {
    let mut digest = CanonicalHasher::new(b"bifrost-selected-stage-typed:v1");
    digest.field("fragment", &fragment.fragment().as_bytes());
    digest.field("language", fragment.language().config_label().as_bytes());
    let completed = encode_rows(fragment, cancellation, |family, sequence, row| {
        digest.field("family", family.as_bytes());
        digest.field(
            "sequence",
            &u64::try_from(sequence)
                .expect("sequence fits u64")
                .to_le_bytes(),
        );
        digest.field(
            "columns",
            serde_json::to_string(&row.columns)
                .expect("column names serialize")
                .as_bytes(),
        );
        digest.field(
            "values",
            serde_json::to_string(&row.values)
                .expect("integer stage rows serialize")
                .as_bytes(),
        );
        Ok(())
    })?;
    Ok(completed.then(|| digest.finish()))
}

/// Insert the borrowed fragment inside SP's transaction. The caller must roll
/// back on false or error and must validate new-row authority before publication.
pub(in crate::analyzer::store) fn insert_typed_fragment(
    connection: &Connection,
    producer_id: i64,
    host: SelectedResolutionMountOrdinal,
    fragment: &LoweredTypedFragment,
    cancellation: &CancellationToken,
) -> Result<bool> {
    assert!(
        !connection.is_autocommit(),
        "stage projection requires its owner's transaction"
    );
    assert_eq!(
        fragment.fragment().ordinal(),
        host.get(),
        "typed fragment belongs to its stage host"
    );
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    let producer_host: u32 = connection.query_row(
        "SELECT host_ordinal FROM temp.selected_resolution_stage_producers WHERE producer_id=?1",
        [producer_id],
        |row| row.get(0),
    )?;
    assert_eq!(
        producer_host,
        host.get(),
        "typed rows belong to their producer's host"
    );
    let inserted = encode_rows(fragment, cancellation, |family, sequence, row| {
        // Names come only from encode_rows, never from source or request text.
        let expressions = row
            .values
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let parameter = index + 4;
                if row.json_columns.contains(&index) {
                    format!("jsonb(?{parameter})")
                } else {
                    format!("?{parameter}")
                }
            })
            .collect::<Vec<_>>();
        let sql = format!(
            "INSERT INTO temp.selected_resolution_stage_{family}(host_ordinal,producer_id,sequence,{}) VALUES(?1,?2,?3,{})",
            row.columns.join(","),
            expressions.join(","),
        );
        let mut values = vec![
            rusqlite::types::Value::Integer(i64::from(host.get())),
            rusqlite::types::Value::Integer(producer_id),
            rusqlite::types::Value::Integer(
                i64::try_from(sequence).expect("stage sequence fits SQLite integer"),
            ),
        ];
        for (index, value) in row.values.into_iter().enumerate() {
            values.push(if row.json_columns.contains(&index) && !value.is_null() {
                rusqlite::types::Value::Text(
                    serde_json::to_string(&value).expect("stage body serializes"),
                )
            } else {
                match value {
                    Value::Null => rusqlite::types::Value::Null,
                    Value::Number(number) => rusqlite::types::Value::Integer(
                        number.as_i64().expect("stage integer fits SQLite"),
                    ),
                    Value::String(value) => rusqlite::types::Value::Text(value),
                    other => panic!("unexpected scalar stage cell: {other:?}"),
                }
            });
        }
        connection
            .prepare_cached(&sql)?
            .execute(params_from_iter(values))?;
        Ok(())
    })?;
    if !inserted {
        return Ok(false);
    }
    if !validate_inserted_typed_rows(connection, producer_id, host, cancellation)? {
        return Ok(false);
    }
    validate_callable_parameter_owners(connection, fragment, cancellation)
}

pub(super) fn row_semantic(row: &Row<'_>, name: &str) -> Result<SemanticId> {
    let key: Option<i64> = row.get(format!("{name}_key").as_str())?;
    let shared: Option<i64> = row.get(format!("{name}_shared").as_str())?;
    Ok(match (key, shared) {
        (Some(key), None) => codec::decode_semantic(key),
        (None, Some(shared)) => codec::decode_semantic(-shared),
        other => panic!("stage semantic {name} has invalid coordinate pair {other:?}"),
    })
}

// A read owns only its answer. Decode the complete query before calling the
// visitor, so early termination retains evidence from every source-known row.
pub(super) fn visit_stage_rows<T>(
    selection: &SelectedResolutionMountInventory<'_>,
    sql: &str,
    parameters: &[&dyn rusqlite::ToSql],
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<T>>,
    decode: impl Fn(&Row<'_>) -> Result<T>,
    include_evidence: impl Fn(&T, &mut PolledCompletionAccumulator<'_>),
) -> Result<TypedFactReadOutcome> {
    let mut evidence = PolledCompletionAccumulator::new(cancellation);
    if cancellation.is_cancelled() {
        return Ok(TypedFactReadOutcome::cancelled(
            ResolutionCompletion::Complete,
        ));
    }
    let Some(answer) = read_stage_rows(
        selection,
        sql,
        parameters,
        cancellation,
        &mut evidence,
        decode,
        include_evidence,
    )?
    else {
        return Ok(TypedFactReadOutcome::cancelled(
            evidence.finish_semantic().0,
        ));
    };
    page_stage_answer(&answer, cancellation, visitor, evidence)
}

pub(super) fn semantic_request_json(request: TypedFactRequest<'_, SemanticId>) -> String {
    serde_json::to_string(
        &request
            .as_slice()
            .iter()
            .copied()
            .map(semantic_pair)
            .collect::<Vec<_>>(),
    )
    .expect("bounded semantic request serializes")
}

fn decode_frontier(row: &Row<'_>) -> Result<LoweredTypedFrontier> {
    let frontier = LoweredTypedFrontier::new(
        row_semantic(row, "slot")?,
        from_code(
            ALL_RESOLUTION_TYPE_SLOT_ROLES,
            row.get("role")?,
            "stage frontier role",
        ),
    );
    let node: Option<i64> = row.get("identity_reference_node")?;
    Ok(match node {
        Some(node) => frontier.with_type_identity_reference(
            row_semantic(row, "identity_reference")?,
            codec::decode_node(node),
        ),
        None => frontier,
    })
}
fn decode_transfer(row: &Row<'_>) -> Result<LoweredTypeTransfer> {
    let completion: Option<String> = row.get("completion_json")?;
    Ok(LoweredTypeTransfer::new(
        row_semantic(row, "source_slot")?,
        from_code(
            ALL_RESOLUTION_TYPE_TRANSFER_KINDS,
            row.get("kind")?,
            "stage transfer kind",
        ),
        TypeTransferRule::new_with_reference_indirection(
            row_semantic(row, "rule")?,
            row_semantic(row, "target_slot")?,
            row.get("indirection_delta")?,
            row.get("reference_indirection_delta")?,
            typed_rows::value_transform_from_code(row.get("value_transform")?),
            codec::decode_completion(completion.as_deref()),
        ),
    ))
}
fn decode_type_component(row: &Row<'_>) -> Result<LoweredTypeComponent> {
    Ok(LoweredTypeComponent::new(
        row_semantic(row, "container_slot")?,
        from_code(
            ALL_RESOLUTION_TYPE_CONSTRUCTOR_KINDS,
            row.get("constructor")?,
            "stage type component constructor",
        ),
        from_code(
            ALL_RESOLUTION_TYPE_COMPONENT_KINDS,
            row.get("kind")?,
            "stage type component kind",
        ),
        row_semantic(row, "component_slot")?,
    ))
}
fn decode_underlying_type(row: &Row<'_>) -> Result<LoweredUnderlyingType> {
    Ok(LoweredUnderlyingType::new(
        row_semantic(row, "definition")?,
        row_semantic(row, "slot")?,
    ))
}
fn decode_intrinsic(row: &Row<'_>) -> Result<LoweredIntrinsicSeed> {
    let values: String = row.get("possible_values_json")?;
    let completion: Option<String> = row.get("completion_json")?;
    let spelling: String = row.get("spelling")?;
    Ok(LoweredIntrinsicSeed::new(
        from_code(
            ALL_INTRINSIC_TYPE_KINDS,
            row.get("kind")?,
            "stage intrinsic kind",
        ),
        spelling,
        TypedFrontierState::new(
            row_semantic(row, "slot")?,
            typed_rows::decode_intrinsic_values(StageBodyDecoder, &values),
            codec::decode_completion(completion.as_deref()),
        ),
    ))
}
fn decode_projection(row: &Row<'_>) -> Result<LoweredBindingProjection> {
    Ok(LoweredBindingProjection::new(
        row_semantic(row, "reference")?,
        row_semantic(row, "output_slot")?,
        from_code(
            ALL_BINDING_PROJECTION_KINDS,
            row.get("kind")?,
            "stage projection kind",
        ),
    ))
}
fn decode_declaration_type(row: &Row<'_>) -> Result<LoweredDeclarationTypeProperty> {
    Ok(LoweredDeclarationTypeProperty::new(
        row_semantic(row, "definition")?,
        row_semantic(row, "slot")?,
        from_code(
            ALL_DECLARATION_TYPE_ROLES,
            row.get("role")?,
            "stage declaration role",
        ),
    ))
}
fn decode_visibility(row: &Row<'_>) -> Result<LoweredDeclarationVisibilityProperty> {
    let visibility: String = row.get("visibility")?;
    Ok(LoweredDeclarationVisibilityProperty::new(
        row_semantic(row, "definition")?,
        DeclaredVisibility::from_label(&visibility).expect("stage visibility is valid"),
    ))
}
fn decode_member_scope(row: &Row<'_>) -> Result<LoweredMemberScopeProperty> {
    Ok(LoweredMemberScopeProperty::new(
        row_semantic(row, "definition")?,
        codec::decode_node(row.get("scope_head_node")?),
    ))
}
fn decode_member_owner(row: &Row<'_>) -> Result<LoweredMemberOwnerProperty> {
    let kind: String = row.get("member_kind")?;
    let access: String = row.get("member_access")?;
    let compatibility: String = row.get("qualifier_compatibility")?;
    Ok(LoweredMemberOwnerProperty::new(
        row_semantic(row, "definition")?,
        row_semantic(row, "owner_definition")?,
        codec::decode_node(row.get("owner_scope_head_node")?),
        typed_rows::member_kind_from_label(&kind),
        typed_rows::member_access_from_label(&access),
        typed_rows::member_qualifier_compatibility_from_label(&compatibility),
    ))
}
fn decode_deferred_owner(row: &Row<'_>) -> Result<LoweredDeferredMemberOwner> {
    let body: String = row.get("body_json")?;
    Ok(typed_rows::decode_deferred_owner_body(
        StageBodyDecoder,
        row_semantic(row, "definition")?,
        row_semantic(row, "lookup")?,
        &body,
    ))
}
fn decode_construction_requirement(
    row: &Row<'_>,
) -> Result<LoweredConstructionRequirementProperty> {
    Ok(LoweredConstructionRequirementProperty::new(
        row_semantic(row, "definition")?,
        row_semantic(row, "required_owner_definition")?,
        from_code(
            ALL_RESOLUTION_CONSTRUCTION_REQUIREMENT_KINDS,
            row.get("kind")?,
            "stage construction kind",
        ),
    ))
}
fn decode_supertype(row: &Row<'_>) -> Result<LoweredSupertypeProperty> {
    Ok(LoweredSupertypeProperty::new(
        row_semantic(row, "definition")?,
        row_semantic(row, "reference")?,
        row_semantic(row, "frontier")?,
        from_code(
            ALL_RESOLUTION_SUPERTYPE_KINDS,
            row.get("kind")?,
            "stage supertype kind",
        ),
    ))
}
fn decode_property_gap(row: &Row<'_>) -> Result<LoweredDefinitionPropertyGap> {
    Ok(LoweredDefinitionPropertyGap::new(
        row_semantic(row, "definition")?,
        ResolutionSiteId::try_from_index(row.get("source_site")?).expect("stage source site fits"),
        from_code(
            ALL_RESOLUTION_GAP_KINDS,
            row.get("kind")?,
            "stage property gap kind",
        ),
        row_semantic(row, "frontier")?,
        row_semantic(row, "reason")?,
    ))
}
fn decode_signature(row: &Row<'_>) -> Result<LoweredCallableSignatureProperty> {
    let body: String = row.get("body_json")?;
    Ok(typed_rows::decode_callable_signature_body(
        StageBodyDecoder,
        row_semantic(row, "definition")?,
        &body,
    ))
}

pub(in crate::analyzer::store) const VISIT_TYPED_FRONTIER_PAGES_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_type_frontiers fact ON fact.slot_key IS request.value->>0 AND fact.slot_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_typed_frontier_pages(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypedFrontier>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_TYPED_FRONTIER_PAGES_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_frontier,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_TYPE_TRANSFER_PAGES_FROM_SOURCES_SQL: &str = "SELECT fact.*,json(fact.completion) AS completion_json FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_type_transfers fact ON fact.source_slot_key IS request.value->>0 AND fact.source_slot_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_type_transfer_pages_from_sources(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_TYPE_TRANSFER_PAGES_FROM_SOURCES_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_transfer,
        |row, evidence| evidence.include(row.rule().completion()),
    )
}

pub(in crate::analyzer::store) const VISIT_TYPE_TRANSFER_PAGES_TO_TARGETS_SQL: &str = "SELECT fact.*,json(fact.completion) AS completion_json FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_type_transfers fact ON fact.target_slot_key IS request.value->>0 AND fact.target_slot_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_type_transfer_pages_to_targets(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_TYPE_TRANSFER_PAGES_TO_TARGETS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_transfer,
        |row, evidence| evidence.include(row.rule().completion()),
    )
}

pub(in crate::analyzer::store) const VISIT_TYPE_COMPONENT_PAGES_FOR_CONTAINERS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_type_components fact ON fact.container_slot_key IS request.value->>0 AND fact.container_slot_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_type_component_pages_for_containers(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeComponent>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_TYPE_COMPONENT_PAGES_FOR_CONTAINERS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_type_component,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_UNDERLYING_TYPE_PAGES_FOR_DEFINITIONS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_underlying_types fact ON fact.definition_key IS request.value->>0 AND fact.definition_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_underlying_type_pages_for_definitions(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredUnderlyingType>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_UNDERLYING_TYPE_PAGES_FOR_DEFINITIONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_underlying_type,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_INTRINSIC_SEED_PAGES_FOR_SLOTS_SQL: &str = "SELECT fact.*,json(fact.possible_values) AS possible_values_json,json(fact.completion) AS completion_json FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_intrinsic_seeds fact ON fact.slot_key IS request.value->>0 AND fact.slot_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_intrinsic_seed_pages_for_slots(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_INTRINSIC_SEED_PAGES_FOR_SLOTS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_intrinsic,
        |row, evidence| evidence.include(row.frontier().completion()),
    )
}

pub(in crate::analyzer::store) const VISIT_BINDING_PROJECTION_PAGES_FOR_REFERENCES_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_binding_projections fact ON fact.reference_key IS request.value->>0 AND fact.reference_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_binding_projection_pages_for_references(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_BINDING_PROJECTION_PAGES_FOR_REFERENCES_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_projection,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_BINDING_PROJECTION_PAGES_FOR_OUTPUTS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_binding_projections fact ON fact.output_slot_key IS request.value->>0 AND fact.output_slot_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_binding_projection_pages_for_outputs(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_BINDING_PROJECTION_PAGES_FOR_OUTPUTS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_projection,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_DECLARATION_TYPE_PAGES_FOR_DEFINITIONS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_declaration_types fact ON fact.definition_key IS request.value->>0 AND fact.definition_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_declaration_type_pages_for_definitions(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_DECLARATION_TYPE_PAGES_FOR_DEFINITIONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_declaration_type,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_DECLARATION_TYPE_PAGES_FOR_SLOTS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_declaration_types fact ON fact.slot_key IS request.value->>0 AND fact.slot_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_declaration_type_pages_for_slots(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_DECLARATION_TYPE_PAGES_FOR_SLOTS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_declaration_type,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_DECLARATION_VISIBILITY_PAGES_FOR_DEFINITIONS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_declaration_visibilities fact ON fact.definition_key IS request.value->>0 AND fact.definition_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_declaration_visibility_pages_for_definitions(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationVisibilityProperty>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_DECLARATION_VISIBILITY_PAGES_FOR_DEFINITIONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_visibility,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_MEMBER_SCOPE_PAGES_FOR_DEFINITIONS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_member_scopes fact ON fact.definition_key IS request.value->>0 AND fact.definition_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_member_scope_pages_for_definitions(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_MEMBER_SCOPE_PAGES_FOR_DEFINITIONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_member_scope,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_MEMBER_OWNER_PAGES_FOR_DEFINITIONS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_member_owners fact ON fact.definition_key IS request.value->>0 AND fact.definition_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_member_owner_pages_for_definitions(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_MEMBER_OWNER_PAGES_FOR_DEFINITIONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_member_owner,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_MEMBER_OWNER_PAGES_FOR_OWNERS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_member_owners fact ON fact.owner_definition_key IS request.value->>0 AND fact.owner_definition_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_member_owner_pages_for_owners(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_MEMBER_OWNER_PAGES_FOR_OWNERS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_member_owner,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_DEFERRED_MEMBER_OWNER_PAGES_FOR_DEFINITIONS_SQL: &str = "SELECT fact.*,json(fact.body) AS body_json FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_deferred_member_owners fact ON fact.definition_key IS request.value->>0 AND fact.definition_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_deferred_member_owner_pages_for_definitions(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeferredMemberOwner>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_DEFERRED_MEMBER_OWNER_PAGES_FOR_DEFINITIONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_deferred_owner,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_CONSTRUCTION_REQUIREMENT_PAGES_FOR_DEFINITIONS_SQL:
    &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_construction_requirements fact ON fact.definition_key IS request.value->>0 AND fact.definition_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_construction_requirement_pages_for_definitions(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<
        '_,
        SelectedTypedRow<LoweredConstructionRequirementProperty>,
    >,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_CONSTRUCTION_REQUIREMENT_PAGES_FOR_DEFINITIONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_construction_requirement,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_SUPERTYPE_PAGES_FOR_DEFINITIONS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_supertypes fact ON fact.definition_key IS request.value->>0 AND fact.definition_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_supertype_pages_for_definitions(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_SUPERTYPE_PAGES_FOR_DEFINITIONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_supertype,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_SUPERTYPE_PAGES_FOR_REFERENCES_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_supertypes fact ON fact.reference_key IS request.value->>0 AND fact.reference_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_supertype_pages_for_references(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_SUPERTYPE_PAGES_FOR_REFERENCES_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_supertype,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_SUPERTYPE_PAGES_FOR_FRONTIERS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_supertypes fact ON fact.frontier_key IS request.value->>0 AND fact.frontier_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_supertype_pages_for_frontiers(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_SUPERTYPE_PAGES_FOR_FRONTIERS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_supertype,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const VISIT_DEFINITION_PROPERTY_GAP_PAGES_FOR_DEFINITIONS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_definition_property_gaps fact ON fact.definition_key IS request.value->>0 AND fact.definition_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_definition_property_gap_pages_for_definitions(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_DEFINITION_PROPERTY_GAP_PAGES_FOR_DEFINITIONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_property_gap,
        |row, evidence| {
            evidence.include_reason(ResolutionIncompleteReason::UnsupportedSemantic(
                row.reason_semantic(),
            ))
        },
    )
}

pub(in crate::analyzer::store) const VISIT_DEFINITION_PROPERTY_GAP_PAGES_FOR_REASONS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_definition_property_gaps fact ON fact.reason_key IS request.value->>0 AND fact.reason_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_definition_property_gap_pages_for_reasons(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_DEFINITION_PROPERTY_GAP_PAGES_FOR_REASONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_property_gap,
        |row, evidence| {
            evidence.include_reason(ResolutionIncompleteReason::UnsupportedSemantic(
                row.reason_semantic(),
            ))
        },
    )
}

pub(in crate::analyzer::store) const VISIT_CALLABLE_SIGNATURE_PAGES_FOR_DEFINITIONS_SQL: &str = "SELECT fact.*,json(fact.body) AS body_json FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_callable_signatures fact ON fact.definition_key IS request.value->>0 AND fact.definition_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_callable_signature_pages_for_definitions(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredCallableSignatureProperty>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_CALLABLE_SIGNATURE_PAGES_FOR_DEFINITIONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_signature,
        |row, evidence| evidence.include(row.completion()),
    )
}

// This predicate deliberately matches the existing partial expression index.
pub(in crate::analyzer::store) const OBSERVATION_REFERENCE_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_type_frontiers fact INDEXED BY selected_resolution_stage_observation_reference ON COALESCE(fact.identity_reference_key,-1)=COALESCE(request.value->>0,-1) AND COALESCE(fact.identity_reference_shared,-1)=COALESCE(request.value->>1,-1) JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal WHERE fact.identity_reference_node IS NOT NULL";
pub(in crate::analyzer::store) fn visit_type_identity_observation_pages_for_references(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypedFrontier>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        OBSERVATION_REFERENCE_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_frontier,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const INTRINSIC_IDENTITY_SQL: &str = "SELECT fact.*,json(fact.possible_values) AS possible_values_json,json(fact.completion) AS completion_json FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_intrinsic_seed_identities named ON named.identity_key IS request.value->>0 AND named.identity_shared IS request.value->>1 JOIN temp.selected_resolution_stage_intrinsic_seeds fact ON fact.host_ordinal=named.host_ordinal AND fact.slot_key IS named.slot_key AND fact.slot_shared IS named.slot_shared JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";
pub(in crate::analyzer::store) fn visit_intrinsic_seed_pages_for_type_identities(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        INTRINSIC_IDENTITY_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_intrinsic,
        |row, evidence| evidence.include(row.frontier().completion()),
    )
}

pub(in crate::analyzer::store) const MEMBER_SCOPE_HEAD_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_member_scopes fact ON fact.scope_head_node=request.value JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";
pub(in crate::analyzer::store) fn visit_member_scope_pages_for_heads(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, BindingNodeId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
) -> Result<TypedFactReadOutcome> {
    let keys = serde_json::to_string(
        &request
            .as_slice()
            .iter()
            .copied()
            .map(codec::encode_node)
            .collect::<Vec<_>>(),
    )
    .expect("node request serializes");
    visit_stage_rows(
        selection,
        MEMBER_SCOPE_HEAD_SQL,
        &[&keys],
        cancellation,
        visitor,
        decode_member_scope,
        |_, _| {},
    )
}

pub(in crate::analyzer::store) const DEFERRED_LOOKUP_SQL: &str = "SELECT fact.*,json(fact.body) AS body_json FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_deferred_member_owners fact ON fact.lookup_key IS request.value->>0 AND fact.lookup_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";
pub(in crate::analyzer::store) fn visit_deferred_member_owner_pages_for_lookup_names(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, DeferredMemberOwnerLookupName>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeferredMemberOwner>>,
) -> Result<TypedFactReadOutcome> {
    let keys = serde_json::to_string(
        &request
            .as_slice()
            .iter()
            .map(|key| semantic_pair(key.lookup()))
            .collect::<Vec<_>>(),
    )
    .expect("lookup request serializes");
    visit_stage_rows(
        selection,
        DEFERRED_LOOKUP_SQL,
        &[&keys],
        cancellation,
        visitor,
        decode_deferred_owner,
        |_, _| {},
    )
}

fn decode_call_obligation(row: &Row<'_>) -> Result<LoweredCallApplicabilityObligation> {
    let arguments: Vec<i64> = serde_json::from_str(&row.get::<_, String>("argument_slots_json")?)
        .expect("argument cells are integers");
    let type_argument_cells: Vec<serde_json::Value> =
        serde_json::from_str(&row.get::<_, String>("type_argument_slots_json")?)
            .expect("type argument cells are a JSON array");
    assert!(
        (4..=5).contains(&type_argument_cells.len()),
        "stage call type argument body has legacy or result-extended shape"
    );
    let type_arguments: Vec<i64> = serde_json::from_value(type_argument_cells[0].clone())
        .expect("call type arguments are integers");
    let owner_type_arguments: Vec<i64> = serde_json::from_value(type_argument_cells[1].clone())
        .expect("owner type arguments are integers");
    let expected: Option<i64> = serde_json::from_value(type_argument_cells[2].clone())
        .expect("expected result slot is an optional integer");
    let segment: Option<i64> = serde_json::from_value(type_argument_cells[3].clone())
        .expect("owner type segment is an optional integer");
    let extra_result_slots: Vec<i64> = type_argument_cells
        .get(4)
        .map(|cell| serde_json::from_value(cell.clone()).expect("extra result slots are integers"))
        .unwrap_or_default();
    let rules: Vec<i64> = serde_json::from_str(&row.get::<_, String>("eligible_rules_json")?)
        .expect("rule cells are integers");
    let completion: Option<String> = row.get("completion_json")?;
    let receiver_key: Option<i64> = row.get("receiver_slot_key")?;
    let receiver_shared: Option<i64> = row.get("receiver_slot_shared")?;
    let receiver = match (receiver_key, receiver_shared) {
        (None, None) => None,
        _ => Some(row_semantic(row, "receiver_slot")?),
    };
    Ok(LoweredCallApplicabilityObligation::new(
        row_semantic(row, "call")?,
        row_semantic(row, "callee_reference")?,
        receiver,
        row_semantic(row, "result_slot")?,
        arguments
            .into_iter()
            .map(codec::decode_semantic)
            .collect::<Vec<_>>(),
        rules
            .into_iter()
            .map(|rule| from_code(ALL_RESOLUTION_ENGINE_RULE_KINDS, rule, "stage call rule"))
            .collect::<Vec<_>>(),
        row.get("explicit_type_argument_count")?,
        row_semantic(row, "applicability_reason")?,
        codec::decode_completion(completion.as_deref()),
    )
    .with_extra_result_slots(
        extra_result_slots
            .into_iter()
            .map(codec::decode_semantic)
            .collect::<Vec<_>>(),
    )
    .with_type_argument_slots(
        type_arguments
            .into_iter()
            .map(codec::decode_semantic)
            .collect::<Vec<_>>(),
    )
    .with_owner_type_arguments(
        segment.map(codec::decode_semantic),
        owner_type_arguments
            .into_iter()
            .map(codec::decode_semantic)
            .collect::<Vec<_>>(),
    )
    .with_expected_result_slot(expected.map(codec::decode_semantic)))
}

pub(in crate::analyzer::store) const VISIT_CALL_APPLICABILITY_PAGES_FOR_CALLEE_REFERENCES_SQL:
    &str = "SELECT fact.*,json(fact.argument_slots) AS argument_slots_json,json(fact.type_argument_slots) AS type_argument_slots_json,json(fact.eligible_rules) AS eligible_rules_json,json(fact.completion) AS completion_json FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_call_obligations fact ON fact.callee_reference_key IS request.value->>0 AND fact.callee_reference_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";
pub(in crate::analyzer::store) fn visit_call_applicability_pages_for_callee_references(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredCallApplicabilityObligation>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_CALL_APPLICABILITY_PAGES_FOR_CALLEE_REFERENCES_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_call_obligation,
        |row, evidence| evidence.include(row.completion()),
    )
}

pub(in crate::analyzer::store) const VISIT_CALL_APPLICABILITY_PAGES_FOR_GAP_REASONS_SQL: &str = "SELECT fact.*,json(fact.argument_slots) AS argument_slots_json,json(fact.type_argument_slots) AS type_argument_slots_json,json(fact.eligible_rules) AS eligible_rules_json,json(fact.completion) AS completion_json FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_call_obligations fact ON fact.applicability_reason_key IS request.value->>0 AND fact.applicability_reason_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";
pub(in crate::analyzer::store) fn visit_call_applicability_pages_for_gap_reasons(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredCallApplicabilityObligation>>,
) -> Result<TypedFactReadOutcome> {
    visit_stage_rows(
        selection,
        VISIT_CALL_APPLICABILITY_PAGES_FOR_GAP_REASONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
        decode_call_obligation,
        |row, evidence| evidence.include(row.completion()),
    )
}

#[cfg(test)]
#[path = "typed_tests.rs"]
mod tests;

fn read_stage_rows<T>(
    selection: &SelectedResolutionMountInventory<'_>,
    sql: &str,
    parameters: &[&dyn rusqlite::ToSql],
    cancellation: &CancellationToken,
    evidence: &mut PolledCompletionAccumulator<'_>,
    decode: impl Fn(&Row<'_>) -> Result<T>,
    include_evidence: impl Fn(&T, &mut PolledCompletionAccumulator<'_>),
) -> Result<Option<Vec<SelectedTypedRow<T>>>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let read =
        with_resolution_read_progress_handler(selection.connection(), cancellation, |connection| {
            let mut statement = connection.prepare_cached(sql)?;
            let mut rows = statement.query(parameters)?;
            let mut answer = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let decoded = decode(row)?;
                include_evidence(&decoded, evidence);
                answer.push(SelectedTypedRow::new(
                    BindingFragmentId::at_ordinal(row.get("host_ordinal")?),
                    decoded,
                ));
            }
            Ok(Some(answer))
        });
    match read {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => Ok(None),
        other => other,
    }
}

fn decode_route(row: &Row<'_>) -> Result<LoweredQualifiedSeededRoute> {
    Ok(LoweredQualifiedSeededRoute::new_with_source_lookup(
        row_semantic(row, "reference")?,
        row_semantic(row, "qualifier_slot")?,
        row_semantic(row, "lookup")?,
        from_code(
            ALL_RESOLUTION_NAMESPACES,
            row.get("namespace")?,
            "stage route namespace",
        ),
        row_semantic(row, "source_lookup")?,
        row.get("precedence_ordinal")?,
        row_semantic(row, "projection_output_slot")?,
        from_code(
            ALL_BINDING_PROJECTION_KINDS,
            row.get("projection_kind")?,
            "stage route projection kind",
        ),
        row_semantic(row, "coarse_gap_reason")?,
        row.get::<_, i64>("open_member_surface")? != 0,
    ))
}

fn visit_route_rows(
    selection: &SelectedResolutionMountInventory<'_>,
    sql: &str,
    parameters: &[&dyn rusqlite::ToSql],
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
) -> Result<TypedFactReadOutcome> {
    let mut evidence = PolledCompletionAccumulator::new(cancellation);
    let Some(routes) = read_stage_rows(
        selection,
        sql,
        parameters,
        cancellation,
        &mut evidence,
        decode_route,
        |route, evidence| {
            evidence.include_reason(ResolutionIncompleteReason::UnsupportedSemantic(
                route.coarse_gap_reason(),
            ))
        },
    )?
    else {
        return Ok(TypedFactReadOutcome::cancelled(
            evidence.finish_semantic().0,
        ));
    };
    // Only this keyed query's answer is retained. Batch authority lookups once
    // per bounded page, never once per row or once per admitted capsule.
    let mut answer = Vec::with_capacity(routes.len());
    for batch in routes.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
        let requests = batch
            .iter()
            .map(|route| {
                (
                    SelectedResolutionMountOrdinal::new(route.fragment().ordinal()),
                    route.row().reference(),
                )
            })
            .collect::<Vec<_>>();
        let Some(nodes) = super::lexical::reference_nodes(selection, &requests, cancellation)?
        else {
            return Ok(TypedFactReadOutcome::cancelled(
                evidence.finish_semantic().0,
            ));
        };
        assert_eq!(
            nodes.len(),
            batch.len(),
            "lexical authority answers every requested position"
        );
        for (route, node) in batch.iter().zip(nodes) {
            let node = node.ok_or_else(||StoreError::new(format!("stage qualified route has no selected lexical reference authority: host={:?}, reference={:?}",route.fragment(),route.row().reference())))?;
            answer.push(SelectedQualifiedRoute::new(
                route.fragment(),
                node,
                *route.row(),
            ));
        }
    }
    page_stage_answer(&answer, cancellation, visitor, evidence)
}

pub(in crate::analyzer::store) const VISIT_QUALIFIED_ROUTE_PAGES_FOR_REFERENCES_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_qualified_routes fact ON fact.reference_key IS request.value->>0 AND fact.reference_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";
pub(in crate::analyzer::store) fn visit_qualified_route_pages_for_references(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
) -> Result<TypedFactReadOutcome> {
    visit_route_rows(
        selection,
        VISIT_QUALIFIED_ROUTE_PAGES_FOR_REFERENCES_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
    )
}

pub(in crate::analyzer::store) const VISIT_QUALIFIED_ROUTE_PAGES_FOR_QUALIFIER_SLOTS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_qualified_routes fact ON fact.qualifier_slot_key IS request.value->>0 AND fact.qualifier_slot_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";
pub(in crate::analyzer::store) fn visit_qualified_route_pages_for_qualifier_slots(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
) -> Result<TypedFactReadOutcome> {
    visit_route_rows(
        selection,
        VISIT_QUALIFIED_ROUTE_PAGES_FOR_QUALIFIER_SLOTS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
    )
}

pub(in crate::analyzer::store) const VISIT_QUALIFIED_ROUTE_PAGES_FOR_GAP_REASONS_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_qualified_routes fact ON fact.coarse_gap_reason_key IS request.value->>0 AND fact.coarse_gap_reason_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";
pub(in crate::analyzer::store) fn visit_qualified_route_pages_for_gap_reasons(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
) -> Result<TypedFactReadOutcome> {
    visit_route_rows(
        selection,
        VISIT_QUALIFIED_ROUTE_PAGES_FOR_GAP_REASONS_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
    )
}

pub(in crate::analyzer::store) const QUALIFIED_SLOT_LOOKUP_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_qualified_routes fact ON fact.qualifier_slot_key IS request.value->>0 AND fact.qualifier_slot_shared IS request.value->>1 AND fact.lookup_key IS request.value->>2 AND fact.lookup_shared IS request.value->>3 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal UNION SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_qualified_routes fact ON fact.qualifier_slot_key IS request.value->>0 AND fact.qualifier_slot_shared IS request.value->>1 AND fact.source_lookup_key IS request.value->>2 AND fact.source_lookup_shared IS request.value->>3 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";
pub(in crate::analyzer::store) fn visit_qualified_route_pages_for_slot_lookups(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, QualifiedRouteSlotLookup>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
) -> Result<TypedFactReadOutcome> {
    let keys = request
        .as_slice()
        .iter()
        .map(|request| {
            let slot = semantic_pair(request.qualifier_slot());
            let lookup = semantic_pair(request.lookup());
            (slot.0, slot.1, lookup.0, lookup.1)
        })
        .collect::<Vec<_>>();
    let keys = serde_json::to_string(&keys).expect("compound request serializes");
    visit_route_rows(
        selection,
        QUALIFIED_SLOT_LOOKUP_SQL,
        &[&keys],
        cancellation,
        visitor,
    )
}

pub(in crate::analyzer::store) const QUALIFIED_ROUTE_INVENTORY_SQL: &str = "SELECT fact.* FROM temp.selected_resolution_scope_mounts scope JOIN temp.selected_resolution_stage_qualified_routes fact ON fact.host_ordinal=scope.mount_ordinal";
pub(in crate::analyzer::store) fn visit_qualified_route_inventory_pages(
    selection: &SelectedResolutionMountInventory<'_>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
) -> Result<TypedFactReadOutcome> {
    visit_route_rows(
        selection,
        QUALIFIED_ROUTE_INVENTORY_SQL,
        &[],
        cancellation,
        visitor,
    )
}

/// RP's ordinary relation answers the actual reverse ownership question. A
/// Parameter declaration role and slot cannot prove which signature owns it.
/// Admission uses the full selection; mutable read scope cannot hide an owner.
pub(in crate::analyzer::store) const CALLABLE_PARAMETER_CONFLICT_SQL: &str = "SELECT input.value->>0,input.value->>1,owner.signature_definition,input.value->>2,input.value->>3 FROM json_each(?1) input CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=input.value->>0 JOIN main.resolution_callable_parameter_owners owner ON owner.blob_id=mount.blob_id AND owner.parameter_definition=input.value->>1 WHERE NOT(mount.mount_ordinal IS input.value->>2 AND owner.signature_definition IS input.value->>3)";

fn validate_callable_parameter_owners(
    connection: &Connection,
    fragment: &LoweredTypedFragment,
    cancellation: &CancellationToken,
) -> Result<bool> {
    // This is one borrowed fragment's parameter query, dropped on return.
    // An ordinary producer admits only content-local parameter definitions.
    let mut parameters = Vec::new();
    for signature in fragment.callable_signatures() {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        for parameter in signature.parameters() {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            if let Some(ordinal) = parameter.definition().ordinal() {
                parameters.push((
                    ordinal,
                    parameter
                        .definition()
                        .local_key()
                        .expect("mounted parameter has a local key"),
                    signature.definition().ordinal(),
                    signature.definition().local_key(),
                ));
            }
        }
    }
    let read = with_resolution_read_progress_handler(connection, cancellation, |connection| {
        for batch in parameters.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let batch =
                serde_json::to_string(batch).expect("parameter ownership request serializes");
            let mut statement = connection.prepare_cached(CALLABLE_PARAMETER_CONFLICT_SQL)?;
            let mut rows = statement.query([&batch])?;
            let mut conflicts = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(false);
                }
                conflicts.push((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, Option<u32>>(3)?,
                    row.get::<_, Option<u32>>(4)?,
                ));
            }
            if !conflicts.is_empty() {
                return Err(StoreError::new(format!(
                    "stage callable parameters conflict with selected ordinary signature ownership (parameter mount/key, ordinary owner key, proposed owner mount/key): {conflicts:?}"
                )));
            }
        }
        Ok(!cancellation.is_cancelled())
    });
    match read {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => Ok(false),
        other => other,
    }
}

pub(in crate::analyzer::store) const QUALIFIED_LOOKUP_SQL: &str = "SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_qualified_routes fact ON fact.lookup_key IS request.value->>0 AND fact.lookup_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal UNION SELECT fact.* FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_qualified_routes fact ON fact.source_lookup_key IS request.value->>0 AND fact.source_lookup_shared IS request.value->>1 JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";
pub(in crate::analyzer::store) fn visit_qualified_route_pages_for_lookups(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
) -> Result<TypedFactReadOutcome> {
    // fact.* includes producer and sequence, so UNION suppresses only the
    // same physical row reached through both aliases or different request keys.
    visit_route_rows(
        selection,
        QUALIFIED_LOOKUP_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        visitor,
    )
}

/// Incoming fragments already satisfy their constructor's within-fragment
/// dependencies. These keyed checks prevent appending duplicate or conflicting
/// authority from the ordinary fragment at the same host. Runtime cells from
/// another host or another identity domain never become local keys by masking.
/// A fragment may own multiple projection outputs for one reference. A later
/// fragment still cannot append a second owner of that ordinary reference:
/// the reference-wide conflict checks intentionally remain stricter than the
/// within-fragment (reference, output) keys.
pub(in crate::analyzer::store) const ORDINARY_TYPED_CONFLICTS_SQL: &str = r#"
SELECT 'frontier slot' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_type_frontiers new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_type_frontiers old ON old.blob_id=mount.blob_id AND old.slot=new.slot_key-?3 WHERE new.producer_id=?1 AND new.slot_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'transfer rule' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_type_transfers new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_type_transfers old INDEXED BY resolution_type_transfers_rule ON old.blob_id=mount.blob_id AND old.rule=new.rule_key-?3 WHERE new.producer_id=?1 AND new.rule_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'projection reference' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_binding_projections new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_binding_projections old ON old.blob_id=mount.blob_id AND old.reference=new.reference_key-?3 WHERE new.producer_id=?1 AND new.reference_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'route reference/precedence' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_qualified_routes new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_qualified_routes old ON old.blob_id=mount.blob_id AND old.reference=new.reference_key-?3 AND old.precedence_ordinal=new.precedence_ordinal WHERE new.producer_id=?1 AND new.reference_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'declaration type role' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_declaration_types new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_declaration_types old ON old.blob_id=mount.blob_id AND old.definition=new.definition_key-?3 AND old.role=new.role WHERE new.producer_id=?1 AND new.definition_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'declaration visibility' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_declaration_visibilities new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_declaration_visibility_properties old ON old.blob_id=mount.blob_id AND old.definition_semantic_key=new.definition_key-?3 WHERE new.producer_id=?1 AND new.definition_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'member scope definition' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_member_scopes new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_member_scope_properties old ON old.blob_id=mount.blob_id AND old.definition_semantic_key=new.definition_key-?3 WHERE new.producer_id=?1 AND new.definition_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'member scope head' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_member_scopes new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_member_scope_properties old ON old.blob_id=mount.blob_id AND old.scope_head_node_key=new.scope_head_node-?3 WHERE new.producer_id=?1 AND new.scope_head_node BETWEEN ?3 AND ?4
UNION ALL
SELECT 'member owner tuple' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_member_owners new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_member_owner_properties old ON old.blob_id=mount.blob_id AND old.definition_semantic_key=new.definition_key-?3 AND new.owner_definition_key=?3+old.owner_definition_semantic_key AND new.owner_scope_head_node=?3+old.owner_scope_head_node_key AND new.member_kind=old.member_kind AND new.member_access=old.member_access AND new.qualifier_compatibility=old.qualifier_compatibility WHERE new.producer_id=?1 AND new.definition_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'deferred owner definition' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_deferred_member_owners new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_deferred_member_owners old ON old.blob_id=mount.blob_id AND old.definition=new.definition_key-?3 WHERE new.producer_id=?1 AND new.definition_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'construction tuple' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_construction_requirements new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_construction_requirements old ON old.blob_id=mount.blob_id AND old.definition=new.definition_key-?3 AND new.required_owner_definition_key=?3+old.required_owner_definition AND new.kind=old.kind WHERE new.producer_id=?1 AND new.definition_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'supertype tuple' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_supertypes new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_supertypes old ON old.blob_id=mount.blob_id AND old.definition=new.definition_key-?3 AND new.reference_key=?3+old.reference AND new.frontier_key=?3+old.frontier AND new.kind=old.kind WHERE new.producer_id=?1 AND new.definition_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'property gap tuple' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_definition_property_gaps new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_definition_property_gaps old ON old.blob_id=mount.blob_id AND old.definition=new.definition_key-?3 AND new.reason_key=?3+old.reason AND new.frontier_key=?3+old.frontier WHERE new.producer_id=?1 AND new.definition_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'call identity' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_call_obligations new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_call_obligations old INDEXED BY resolution_call_obligations_call ON old.blob_id=mount.blob_id AND old.call=new.call_key-?3 WHERE new.producer_id=?1 AND new.call_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'callee reference' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_call_obligations new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_call_obligations old ON old.blob_id=mount.blob_id AND old.callee_reference=new.callee_reference_key-?3 WHERE new.producer_id=?1 AND new.callee_reference_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'callable definition' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_callable_signatures new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_callable_signatures old ON old.blob_id=mount.blob_id AND old.definition=new.definition_key-?3 WHERE new.producer_id=?1 AND new.definition_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'observed reference' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_type_frontiers new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_type_frontiers old ON old.blob_id=mount.blob_id AND old.identity_reference=new.identity_reference_key-?3 AND old.identity_reference IS NOT NULL WHERE new.producer_id=?1 AND new.identity_reference_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'route reason owner' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_qualified_routes new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_qualified_routes old ON old.blob_id=mount.blob_id AND old.coarse_gap_reason=new.coarse_gap_reason_key-?3 AND new.reference_key IS NOT ?3+old.reference WHERE new.producer_id=?1 AND new.coarse_gap_reason_key BETWEEN ?3 AND ?4
UNION ALL
SELECT 'property provenance owner' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_definition_property_gaps new CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2 CROSS JOIN main.resolution_definition_property_gaps old INDEXED BY resolution_definition_property_gaps_provenance ON old.blob_id=mount.blob_id AND old.reason=new.reason_key-?3 AND old.site=new.source_site AND old.kind=new.kind AND new.definition_key IS NOT ?3+old.definition WHERE new.producer_id=?1 AND new.reason_key BETWEEN ?3 AND ?4
"#;

pub(in crate::analyzer::store) const STAGE_TYPED_CONFLICTS_SQL: &str = r#"
SELECT 'route reason owner' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_qualified_routes new CROSS JOIN temp.selected_resolution_stage_qualified_routes old ON old.host_ordinal=new.host_ordinal AND old.coarse_gap_reason_key IS new.coarse_gap_reason_key AND old.coarse_gap_reason_shared IS new.coarse_gap_reason_shared WHERE new.producer_id=?1 AND (new.reference_key IS NOT old.reference_key OR new.reference_shared IS NOT old.reference_shared)
UNION ALL
SELECT 'property provenance owner' AS invariant,new.sequence AS sequence FROM temp.selected_resolution_stage_definition_property_gaps new CROSS JOIN temp.selected_resolution_stage_definition_property_gaps old ON old.host_ordinal=new.host_ordinal AND old.reason_key IS new.reason_key AND old.reason_shared IS new.reason_shared WHERE new.producer_id=?1 AND new.source_site=old.source_site AND new.kind=old.kind AND (new.definition_key IS NOT old.definition_key OR new.definition_shared IS NOT old.definition_shared)
"#;

fn validate_inserted_typed_rows(
    connection: &Connection,
    producer: i64,
    host: SelectedResolutionMountOrdinal,
    cancellation: &CancellationToken,
) -> Result<bool> {
    let base = codec::encode_semantic(SemanticId::local(host.get(), 0));
    let maximum = codec::encode_semantic(SemanticId::local(host.get(), u32::MAX));
    let read = with_resolution_read_progress_handler(connection, cancellation, |connection| {
        for (sql, parameters) in [
            (
                ORDINARY_TYPED_CONFLICTS_SQL,
                vec![producer, i64::from(host.get()), base, maximum],
            ),
            (STAGE_TYPED_CONFLICTS_SQL, vec![producer]),
        ] {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let mut statement = connection.prepare_cached(sql)?;
            let mut rows = statement.query(params_from_iter(parameters))?;
            let mut conflicts = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(false);
                }
                conflicts.push((row.get::<_, String>(0)?, row.get::<_, i64>(1)?));
            }
            if !conflicts.is_empty() {
                return Err(StoreError::new(format!(
                    "new typed rows violate selected host {host:?} authority (invariant,producer-local sequence): {conflicts:?}"
                )));
            }
        }
        Ok(!cancellation.is_cancelled())
    });
    match read {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => Ok(false),
        other => other,
    }
}

fn page_stage_answer<T>(
    answer: &[T],
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, T>,
    evidence: PolledCompletionAccumulator<'_>,
) -> Result<TypedFactReadOutcome> {
    for page in answer.chunks(visitor.maximum_rows()) {
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(
                evidence.finish_semantic().0,
            ));
        }
        let keep_going = visitor.visit_page(page)?;
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(
                evidence.finish_semantic().0,
            ));
        }
        if !keep_going {
            return Ok(TypedFactReadOutcome::stopped(evidence.finish_semantic().0));
        }
    }
    Ok(if cancellation.is_cancelled() {
        TypedFactReadOutcome::cancelled(evidence.finish_semantic().0)
    } else {
        TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
    })
}

/// Gap tuples can repeat a reason across coverage families. The public raw
/// provenance key is (host,reason), so deduplicate only identical authority.
pub(in crate::analyzer::store) const GAP_REASON_PROVENANCE_SQL: &str = "SELECT DISTINCT fact.host_ordinal,fact.reason_key,fact.source_site,fact.origin FROM json_each(?1) request CROSS JOIN temp.selected_resolution_stage_gaps fact ON fact.reason_key=request.value->>0 AND request.value->>1 IS NULL JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=fact.host_ordinal";

pub(in crate::analyzer::store) fn visit_gap_reason_provenance_pages_for_reasons(
    selection: &SelectedResolutionMountInventory<'_>,
    request: TypedFactRequest<'_, SemanticId>,
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, SelectedGapReasonProvenance>,
) -> Result<TypedFactReadOutcome> {
    let mut evidence = PolledCompletionAccumulator::new(cancellation);
    let Some(mut rows) = read_stage_rows(
        selection,
        GAP_REASON_PROVENANCE_SQL,
        &[&semantic_request_json(request)],
        cancellation,
        &mut evidence,
        |row| {
            Ok((
                codec::decode_semantic(row.get("reason_key")?),
                ResolutionSiteId::try_from_index(row.get("source_site")?)
                    .expect("stage gap source site fits"),
                super::super::resolution_prepare::resolution_rows::gap_origin_from_code(
                    row.get("origin")?,
                ),
            ))
        },
        |_, _| {},
    )?
    else {
        return Ok(TypedFactReadOutcome::cancelled(
            evidence.finish_semantic().0,
        ));
    };
    rows.sort_unstable_by_key(|row| (row.fragment(), row.row().0));
    if rows
        .windows(2)
        .any(|pair| pair[0].fragment() == pair[1].fragment() && pair[0].row().0 == pair[1].row().0)
    {
        return Err(StoreError::new(format!(
            "stage gap reasons have conflicting source provenance: {rows:?}"
        )));
    }
    let answer = rows
        .into_iter()
        .map(|row| {
            let &(reason, site, origin) = row.row();
            SelectedGapReasonProvenance::new(row.fragment(), reason, site, origin)
        })
        .collect::<Vec<_>>();
    page_stage_answer(&answer, cancellation, visitor, evidence)
}
