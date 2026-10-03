//! Exact Rust authority prepared once per blob from canonical source facts.

use super::super::resolution::{
    PreparedResolutionBundleRows, PreparedResolutionRow, PreparedResolutionValue,
};
use super::super::{Result, resolution_operation};
use crate::CancellationToken;
use crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog;
use brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts;
use brokk_bifrost_core::analyzer::rust_facts::{RustCfgCondition, RustVisibility};
use serde_json::{Value, json};

pub(crate) const REFERENCES_SQL: &str = "SELECT semantic_key, source_site, source_occurrence, module_context, module_declaration, json(cfg_condition) FROM resolution_rust_reference_contexts WHERE blob_id=?1 AND semantic_key IN (SELECT value FROM json_each(?2)) ORDER BY semantic_key";
pub(crate) const DECLARATIONS_SQL: &str = "SELECT semantic_key, source_site, declaration, json(visibility), module_context, module_declaration, json(cfg_condition), activation_reason FROM resolution_rust_declaration_authorities WHERE blob_id=?1 AND semantic_key IN (SELECT value FROM json_each(?2)) ORDER BY semantic_key";

pub(super) fn prepare(
    lowered: &LoweredResolutionFactsWithIdentityCatalog,
    source: &ParsedSourceFacts,
    rows: &mut PreparedResolutionBundleRows,
    cancellation: &CancellationToken,
) -> Result<bool> {
    if cancellation.is_cancelled() {
        return Ok(false);
    }
    let references = resolution_operation::rust_reference_context_sources(source, cancellation)?
        .into_iter()
        .map(|row| (row.source_site(), row))
        .collect();
    let declarations = resolution_operation::rust_declaration_context_sources(
        source,
        &source.native_declaration_sources,
        cancellation,
    )?
    .into_iter()
    .map(|row| (row.source_site(), row))
    .collect();
    let Some(authority) = resolution_operation::lower_rust_context_rows(
        "blob preparation",
        &references,
        &declarations,
        &source.native_declaration_sources,
        &source.rust_declaration_properties,
        lowered,
        cancellation,
    )?
    else {
        return Ok(false);
    };
    let (references, declarations) = authority.into_parts();
    for reference in references {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let row = reference.row();
        rows.rust_reference_contexts
            .push(PreparedResolutionRow::new(vec![
                row.reference()
                    .local_key()
                    .expect("reference is local")
                    .into(),
                row.source_site().get().into(),
                row.source_occurrence().get().into(),
                row.module_context().get().into(),
                row.module_declaration().map(|id| id.get()).into(),
                encode_cfg(row.cfg_condition()).into(),
            ]));
    }
    for declaration in declarations {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let row = declaration.row();
        rows.rust_declaration_authorities
            .push(PreparedResolutionRow::new(vec![
                row.definition()
                    .local_key()
                    .expect("definition is local")
                    .into(),
                row.source_site().get().into(),
                row.declaration().get().into(),
                row.visibility()
                    .map(encode_visibility)
                    .map_or(PreparedResolutionValue::Null, Into::into),
                row.module_context().get().into(),
                row.module_declaration().map(|id| id.get()).into(),
                encode_cfg(row.cfg_condition()).into(),
                row.activation_reason()
                    .map(|reason| reason.local_key().expect("activation reason is local"))
                    .into(),
            ]));
    }
    Ok(true)
}

// This family deliberately uses structured JSON arrays, distinct from the
// existing source tables' text codecs. SQL can inspect predicate instructions
// and visibility path segments without parsing embedded text. Compound cfg
// uses RustCfgInstruction's existing typed serde representation.
pub(crate) fn encode_cfg(condition: &RustCfgCondition) -> String {
    match condition {
        RustCfgCondition::Always => json!(["always"]),
        RustCfgCondition::Unknown => json!(["unknown"]),
        RustCfgCondition::Atom(atom) => json!(["atom", atom]),
        RustCfgCondition::NotAtom(atom) => json!(["not", atom]),
        RustCfgCondition::Expression(instructions) => json!(["expression", instructions]),
    }
    .to_string()
}

pub(crate) fn decode_cfg(body: &str) -> RustCfgCondition {
    let value: Value = serde_json::from_str(body).expect("stored cfg is JSON");
    let cells = value.as_array().expect("stored cfg is an array");
    let tag = cells
        .first()
        .and_then(Value::as_str)
        .expect("stored cfg tag");
    assert_eq!(
        cells.len(),
        if matches!(tag, "always" | "unknown") {
            1
        } else {
            2
        },
        "stored cfg arity"
    );
    match tag {
        "always" => RustCfgCondition::Always,
        "unknown" => RustCfgCondition::Unknown,
        "atom" => RustCfgCondition::Atom(cells[1].as_str().expect("cfg atom").to_owned()),
        "not" => RustCfgCondition::NotAtom(cells[1].as_str().expect("cfg atom").to_owned()),
        "expression" => RustCfgCondition::Expression(
            serde_json::from_value(cells[1].clone()).expect("cfg instructions"),
        ),
        other => panic!("unknown stored cfg tag: {other:?}"),
    }
}

pub(crate) fn encode_visibility(visibility: &RustVisibility) -> String {
    match visibility {
        RustVisibility::Private => json!(["private"]),
        RustVisibility::Public => json!(["public"]),
        RustVisibility::Crate => json!(["crate"]),
        RustVisibility::SelfModule => json!(["self"]),
        RustVisibility::SuperModule => json!(["super"]),
        RustVisibility::InPath(path) => json!(["in", path]),
    }
    .to_string()
}

pub(crate) fn decode_visibility(body: &str) -> RustVisibility {
    let value: Value = serde_json::from_str(body).expect("stored visibility is JSON");
    let cells = value.as_array().expect("stored visibility is an array");
    let tag = cells
        .first()
        .and_then(Value::as_str)
        .expect("stored visibility tag");
    assert_eq!(
        cells.len(),
        if tag == "in" { 2 } else { 1 },
        "stored visibility arity"
    );
    match tag {
        "private" => RustVisibility::Private,
        "public" => RustVisibility::Public,
        "crate" => RustVisibility::Crate,
        "self" => RustVisibility::SelfModule,
        "super" => RustVisibility::SuperModule,
        "in" => RustVisibility::InPath(
            serde_json::from_value(cells[1].clone()).expect("visibility path"),
        ),
        other => panic!("unknown stored visibility tag: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::rust_facts::RustCfgInstruction;

    #[test]
    fn structured_authority_values_round_trip() {
        for cfg in [
            RustCfgCondition::Always,
            RustCfgCondition::Unknown,
            RustCfgCondition::Atom("feature = \"nested\"".into()),
            RustCfgCondition::NotAtom("unix".into()),
            RustCfgCondition::Expression(
                vec![
                    RustCfgInstruction::KeyValue {
                        key: "feature".into(),
                        value: "nested".into(),
                    },
                    RustCfgInstruction::Atom("unix".into()),
                    RustCfgInstruction::Not,
                    RustCfgInstruction::Any(2),
                ]
                .into_boxed_slice(),
            ),
        ] {
            assert_eq!(decode_cfg(&encode_cfg(&cfg)), cfg);
        }
        for visibility in [
            RustVisibility::Private,
            RustVisibility::Public,
            RustVisibility::Crate,
            RustVisibility::SelfModule,
            RustVisibility::SuperModule,
            RustVisibility::InPath(vec!["crate".into(), "nested".into()]),
        ] {
            assert_eq!(
                decode_visibility(&encode_visibility(&visibility)),
                visibility
            );
        }
    }

    #[test]
    #[should_panic(expected = "stored cfg arity")]
    fn structured_cfg_rejects_extra_cells() {
        decode_cfg(r#"["always", 1]"#);
    }

    #[test]
    #[should_panic(expected = "visibility path")]
    fn structured_visibility_rejects_non_string_segments() {
        decode_visibility(r#"["in", [1]]"#);
    }
}
