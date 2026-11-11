//! Pinned Rust MaD inventory and conservative identity candidates.
//! Model strings are parsed as Rust syntax; they never constitute declaration proof.
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ArtifactExtractionKind, AuthoredPayload, AuthoredSemanticModelPack, Locator, MemberFact,
    MemberKind, TypeFact, TypeKind, Visibility,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const CODEQL_COMMIT: &str = "1be292a1e54696ca543b4ad0f9b4537b9687caa7";
const PINNED: &str = include_str!("rust-pinned-files.txt");
const TRANSLATOR: &str = "rust-mad-m2/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    extensions: Vec<Extension>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Extension {
    #[serde(rename = "addsTo")]
    adds_to: AddsTo,
    data: Vec<Vec<String>>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddsTo {
    pack: String,
    extensible: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RowKey {
    pub commit: &'static str,
    pub path: String,
    pub extension_ordinal: usize,
    pub row_ordinal: usize,
    pub row_sha256: String,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CallableCandidate {
    /// First crate-path segment selected from the parsed Rust AST.
    pub crate_root: String,
    pub owner: String,
    pub member: String,
    pub trait_owner: Option<String>,
    pub self_type: Option<String>,
    pub explicit_type_owner: bool,
    /// Receiver shape is not proven until the reference-role artifact is selected.
    pub receiver_proven: bool,
    /// Written argument count is likewise unknown at this stage.
    pub arity_proven: bool,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RowDecision {
    pub key: RowKey,
    pub kind: String,
    pub status: &'static str,
    pub reason: &'static str,
    pub candidate: Option<CallableCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<StdFreeFunctionBinding>,
    pub cells: Vec<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct SkipBucket {
    pub status: String,
    pub reason: String,
    pub kind: String,
    pub file: String,
    /// Exact input/output access-path spellings; retains every step and union.
    pub paths: Vec<String>,
    pub rows: usize,
}
#[derive(Debug, Serialize)]
pub struct Audit {
    pub translator: &'static str,
    pub source_commit: &'static str,
    pub file_count: usize,
    pub file_set_sha256: String,
    pub ledger_rows_sha256: String,
    pub semantic_output_sha256: String,
    pub artifact_digests: BTreeMap<String, String>,
    pub rows_by_kind: BTreeMap<String, usize>,
    pub status_by_reason: BTreeMap<String, usize>,
    pub skip_breakdown: Vec<SkipBucket>,
    pub model_rows: usize,
    pub excluded_field_rows: usize,
    pub emitted_transfers: usize,
    pub certified_std_free_function_rows: usize,
    pub std_candidate_remaining_by_reason: BTreeMap<String, usize>,
    pub rows: Vec<RowDecision>,
}

fn recount(audit: &mut Audit) -> Result<(), String> {
    audit.status_by_reason.clear();
    let mut breakdown: BTreeMap<(String, String, String, String, Vec<String>), usize> =
        BTreeMap::new();
    for row in &audit.rows {
        *audit
            .status_by_reason
            .entry(format!("{}:{}", row.status, row.reason))
            .or_default() += 1;
        if row.status == "translated" {
            continue;
        }
        let paths = match row.kind.as_str() {
            "summaryModel" => row.cells[1..3].to_vec(),
            "sourceModel" | "sinkModel" => row.cells[1..2].to_vec(),
            _ => Vec::new(),
        };
        *breakdown
            .entry((
                row.status.into(),
                row.reason.into(),
                row.kind.clone(),
                row.key.path.clone(),
                paths,
            ))
            .or_default() += 1;
    }
    audit.skip_breakdown = breakdown
        .into_iter()
        .map(|((status, reason, kind, file, paths), rows)| SkipBucket {
            status,
            reason,
            kind,
            file,
            paths,
            rows,
        })
        .collect();
    audit.ledger_rows_sha256 = digest(&serde_json::to_vec(&audit.rows).map_err(|e| e.to_string())?);
    Ok(())
}

pub fn apply_std_summary_output(
    audit: &mut Audit,
    certified: &[StdFreeFunctionBinding],
    summary_emitted: &[RowKey],
    catalog_emitted: &[RowKey],
    emitted_transfer_count: usize,
    pack_bytes: &[u8],
) -> Result<(), String> {
    let certified_keys: BTreeSet<_> = certified.iter().map(|item| &item.row).collect();
    let summary_keys: BTreeSet<_> = summary_emitted.iter().collect();
    let catalog_keys: BTreeSet<_> = catalog_emitted.iter().collect();
    let emitted_keys: BTreeSet<_> = summary_keys.union(&catalog_keys).copied().collect();
    if !emitted_keys.is_subset(&certified_keys) {
        return Err("emitted row lacks stdlib proof".into());
    }
    audit.certified_std_free_function_rows = certified_keys.len();
    audit.std_candidate_remaining_by_reason.clear();
    let binding_by_key: BTreeMap<_, _> = certified
        .iter()
        .map(|binding| (&binding.row, binding))
        .collect();
    for row in &mut audit.rows {
        row.binding = binding_by_key
            .get(&row.key)
            .map(|binding| (*binding).clone());
        if summary_keys.contains(&row.key) {
            row.status = "translated";
            row.reason = "stdlib_taint_summary";
        } else if catalog_keys.contains(&row.key) {
            row.status = "translated";
            row.reason = "stdlib_endpoint_catalog";
        } else if certified_keys.contains(&row.key) {
            *audit
                .std_candidate_remaining_by_reason
                .entry("certified_but_unsupported_m2_kind_or_path".into())
                .or_default() += 1;
        } else if row.candidate.as_ref().is_some_and(|candidate| {
            matches!(candidate.crate_root.as_str(), "std" | "core" | "alloc")
        }) && row.status == "blocked"
        {
            *audit
                .std_candidate_remaining_by_reason
                .entry(row.reason.into())
                .or_default() += 1;
        }
    }
    audit.emitted_transfers = emitted_transfer_count;
    audit.semantic_output_sha256 = digest(pack_bytes);
    recount(audit)
}

/// Policy-catalog documents for independently certified std free functions.
/// Only whole return sources and positional-argument sinks are expressible.
pub fn std_endpoint_catalogs(
    audit: &Audit,
    certified: &[StdFreeFunctionBinding],
) -> Result<(BTreeMap<String, serde_json::Value>, Vec<RowKey>), String> {
    use brokk_bifrost_policy::{CatalogSourceIdentity, PolicyCategoryId, TaintCatalogRegistry};
    use brokk_bifrost_rql::query::{CallArgumentSelector, CallIdentity, CodeQuery, QueryStep};
    use serde_json::{Value, json};
    let mut catalogs: BTreeMap<String, Value> = BTreeMap::new();
    let mut emitted = Vec::new();
    for binding in certified {
        let Some(row) = audit.rows.iter().find(|row| row.key == binding.row) else {
            continue;
        };
        let (role, port_name) = match row.kind.as_str() {
            "sourceModel" if row.cells[1] == "ReturnValue" => ("sources", "bind"),
            "sinkModel" if row.cells[1] != "ReturnValue" => ("sinks", "dangerous_operand"),
            _ => continue,
        };
        let category = row.cells[2].replace('[', "-").replace(']', "");
        if PolicyCategoryId::new(&category).is_err() {
            continue;
        }
        let port = if role == "sources" {
            json!({"type":"return_value"})
        } else {
            let Ok(path) = super::parse_access_path(&row.cells[1]) else {
                continue;
            };
            let super::MadRoot::Argument(items) = path.root else {
                continue;
            };
            let [super::MadArgumentItem::Index(index)] = items.as_slice() else {
                continue;
            };
            json!({"type":"argument_index","index":index})
        };
        let call = format!(
            "(call :callee (name {}))",
            serde_json::to_string(&binding.member).map_err(|e| e.to_string())?
        );
        let mut query = CodeQuery::from_sexp(&format!(
            "(language rust (resolved-call :resolves-to member.generated :proof declared (call-bindings (call-shape {call}))))"
        ))?;
        for step in &mut query.plan.steps {
            if let QueryStep::ResolvedCall(filter) = step {
                filter.resolves_to = CallIdentity::Stable(binding.declaration_id.clone());
            }
        }
        if let Some(index) = port.get("index").and_then(Value::as_u64) {
            query
                .plan
                .steps
                .push(QueryStep::CallArgument(CallArgumentSelector::FormalIndex(
                    index as usize,
                )));
        }
        let name = format!("codeql-rust-{role}-{category}");
        let id = format!(
            "codeql-{}",
            digest(
                &serde_json::to_vec(&(role, &category, &binding.declaration_id, &port))
                    .map_err(|e| e.to_string())?
            )
        );
        let mut entry = json!({"id":id,"categories":[category],"selector":{"type":"inline","schema_version":1,"query":query.to_canonical_query_plan_json()}});
        entry[port_name] = port;
        entry["display_name"] = json!(format!("{}.{}", binding.owner, binding.member));
        if role == "sources" {
            entry["labels"] = json!(["attacker-controlled"]);
            entry["threat_model"] = if matches!(
                row.cells[2].as_str(),
                "remote" | "commandargs" | "environment" | "stdin" | "file" | "database"
            ) {
                json!(row.cells[2])
            } else {
                Value::Null
            };
            entry["evidence"] = Value::Null;
        } else {
            entry["accepts"] = json!(["attacker-controlled"]);
            entry["tags"] = json!([]);
            entry["impacts"] = json!([]);
        }
        let catalog = catalogs.entry(name.clone()).or_insert_with(|| json!({"schema_version":1,"name":name,"version":1,"categories":[category],"sources":[],"sinks":[],"sanitizers":[],"transforms":[],"external_models":[]}));
        catalog[role]
            .as_array_mut()
            .ok_or("invalid catalog array")?
            .push(entry);
        emitted.push(binding.row.clone());
    }
    let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
    for (name, catalog) in &mut catalogs {
        for role in ["sources", "sinks"] {
            let items = catalog[role]
                .as_array_mut()
                .ok_or("invalid catalog array")?;
            items.sort_by_cached_key(|entry| entry["id"].as_str().unwrap_or("").to_owned());
            items.dedup();
        }
        let bytes = serde_json::to_vec(catalog).map_err(|e| e.to_string())?;
        let hash = registry
            .register_json_bytes(
                CatalogSourceIdentity::new(name.clone()).map_err(|e| e.to_string())?,
                &bytes,
            )
            .map_err(|e| e.to_string())?;
        *catalog = serde_json::from_slice(
            registry
                .iter()
                .find(|item| item.semantic_hash() == hash)
                .ok_or("missing registered catalog")?
                .canonical_json(),
        )
        .map_err(|e| e.to_string())?;
    }
    Ok((catalogs, emitted))
}

/// Preflight evidence only. The selected resolver and dated-toolchain gate must
/// still accept this binding before the row changes to `translated`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StdFreeFunctionBinding {
    pub row: RowKey,
    pub owner: String,
    pub member: String,
    pub declaration_id: String,
    pub parameter_arity: usize,
    pub source_set_digest: String,
    pub declaration_locator: Locator,
}

/// Caller supplies these from the pinned stdlib spec or verified release input.
pub struct StdlibDeclarationEvidence<'a> {
    pub pack_id: &'a str,
    pub version: &'a str,
    pub source_set_digest: &'a str,
}

/// Inspect the already-produced stdlib declaration pack. Never infer a
/// declaration from a MaD spelling or emit a parallel declaration source.
pub fn preflight_std_free_functions(
    audit: &Audit,
    declarations: &AuthoredSemanticModelPack,
    expected: &StdlibDeclarationEvidence<'_>,
) -> Result<Vec<StdFreeFunctionBinding>, String> {
    if declarations.pack_id != expected.pack_id
        || declarations.language != "rust"
        || declarations.version != expected.version
    {
        return Err("expected the pinned Rust stdlib declaration pack".into());
    }
    let extraction = declarations
        .extraction
        .as_ref()
        .ok_or("stdlib declarations lack producer-carried source-set evidence")?;
    if extraction.kind != ArtifactExtractionKind::RustdocJsonSet
        || extraction.digest() != expected.source_set_digest
    {
        return Err("stdlib declarations came from an unpinned source set".into());
    }
    let mut types = Vec::new();
    let mut members = Vec::new();
    for shard in &declarations.shards {
        if let AuthoredPayload::DeclarationFacts {
            types: shard_types,
            members: shard_members,
            ..
        } = &shard.payload
        {
            types.extend(shard_types.iter());
            members.extend(shard_members.iter());
        }
    }
    let mut bindings = Vec::new();
    for row in &audit.rows {
        if row.status != "blocked" || row.reason != "missing_declaration_evidence" {
            continue;
        }
        let Some(candidate) = row.candidate.as_ref() else {
            continue;
        };
        if !matches!(candidate.crate_root.as_str(), "std" | "core" | "alloc")
            || candidate.trait_owner.is_some()
            || candidate.explicit_type_owner
        {
            continue;
        }
        if let Some((declaration_id, parameter_arity, declaration_locator)) =
            unique_public_free_function(&types, &members, candidate)
        {
            let ports: &[String] = match row.kind.as_str() {
                "summaryModel" if row.cells.len() == 5 => &row.cells[1..3],
                "sourceModel" | "sinkModel" if row.cells.len() == 4 => &row.cells[1..2],
                _ => continue,
            };
            if !ports
                .iter()
                .all(|port| positional_port_fits(port, parameter_arity))
            {
                continue;
            }
            bindings.push(StdFreeFunctionBinding {
                row: row.key.clone(),
                owner: candidate.owner.clone(),
                member: candidate.member.clone(),
                declaration_id,
                parameter_arity,
                source_set_digest: extraction.digest().to_owned(),
                declaration_locator,
            });
        }
    }
    Ok(bindings)
}

fn positional_port_fits(port: &str, arity: usize) -> bool {
    match super::parse_access_path(port) {
        Ok(path) if path.components.is_empty() => match path.root {
            super::MadRoot::ReturnValue => true,
            super::MadRoot::Argument(items) => {
                matches!(items.as_slice(), [super::MadArgumentItem::Index(index)] if (*index as usize) < arity)
            }
        },
        _ => false,
    }
}

/// Build a separate summary-only pack from one proven free-function slice.
/// The stdlib declaration pack is only evidence; no declarations are copied.
pub fn build_std_taint_summary_pack(
    audit: &Audit,
    declarations: &AuthoredSemanticModelPack,
    expected: &StdlibDeclarationEvidence<'_>,
) -> Result<(AuthoredSemanticModelPack, Vec<RowKey>), String> {
    let bindings = preflight_std_free_functions(audit, declarations, expected)?;
    let mut rows = Vec::new();
    let mut summaries = BTreeMap::new();
    for binding in bindings {
        let row = audit
            .rows
            .iter()
            .find(|row| row.key == binding.row)
            .ok_or("preflight row disappeared")?;
        if row.kind != "summaryModel" || row.cells[3] != "taint" || row.cells[2] != "ReturnValue" {
            continue;
        }
        let Ok(path) = super::parse_access_path(&row.cells[1]) else {
            continue;
        };
        let super::MadRoot::Argument(items) = path.root else {
            continue;
        };
        let [super::MadArgumentItem::Index(index)] = items.as_slice() else {
            continue;
        };
        let Locator::Artifact { path, .. } = &binding.declaration_locator else {
            continue;
        };
        // Runtime procedure lookup keys on the public callable spelling.
        // The rustdoc locator symbol includes a #member suffix and is only
        // declaration evidence; using it here leaves the summary unbound.
        let callable_symbol = format!("{}.{}", binding.owner, binding.member);
        let summary_id = format!("summary.codeql-rust.{}", binding.declaration_id);
        let summary: brokk_bifrost_analysis::analyzer::semantic_model::AuthoredProcedureSummary =
            serde_json::from_value(serde_json::json!({
                "id": summary_id,
                "target": {
                    "path": path, "symbol": callable_symbol, "has_receiver": false,
                    "parameter_count": binding.parameter_arity,
                },
                "completeness": "partial",
                "transfers": [{
                    "input": {"kind":"parameter", "ordinal": index},
                    "exit_kind": "normal", "output": {"kind":"normal_return"}
                }]
            }))
            .map_err(|error| format!("invalid Rust MaD summary: {error}"))?;
        let entry: &mut brokk_bifrost_analysis::analyzer::semantic_model::AuthoredProcedureSummary =
            summaries
                .entry(summary.id.clone())
                .or_insert_with(|| summary.clone());
        for transfer in summary.transfers {
            if !entry.transfers.contains(&transfer) {
                entry.transfers.push(transfer);
            }
        }
        rows.push(binding.row);
    }
    let shard = serde_json::from_value(serde_json::json!({
            "id": "summaries.codeql-rust-stdlib",
            "activation": declarations.shards.first().ok_or("stdlib pack has no shards")?.activation,
            "payload": {"kind":"procedure_summaries", "summaries": summaries.into_values().collect::<Vec<_>>()}
        })).map_err(|error| format!("invalid Rust MaD summary shard: {error}"))?;
    let mut pack = super::super::authored_pack(
        "codeql.rust-stdlib.summaries".into(),
        "1.0.0".into(),
        "bifrost-codeql-rust".into(),
        "rust".into(),
        "cargo".into(),
        declarations.compatibility.clone(),
        brokk_bifrost_analysis::analyzer::semantic_model::Provenance {
            source: format!(
                "https://github.com/github/codeql (MIT); stdlib {}@{} source-set {}",
                expected.pack_id, expected.version, expected.source_set_digest
            ),
            revision: Some(CODEQL_COMMIT.into()),
            rust_artifact_approximation: None,
        },
        brokk_bifrost_analysis::analyzer::semantic_model::Completeness::Partial,
        vec![shard],
    );
    pack.license = "MIT".into();
    pack.safety.review_required = true;
    Ok((pack, rows))
}

fn unique_public_free_function(
    types: &[&TypeFact],
    members: &[&MemberFact],
    candidate: &CallableCandidate,
) -> Option<(String, usize, Locator)> {
    // Both the root and the written owner must be unique public modules.
    // Alias/re-export spellings need a separate selected-resolver witness.
    let root = types.iter().filter(|ty| {
        ty.name == candidate.crate_root
            && ty.type_kind == TypeKind::Module
            && ty.visibility == Visibility::Public
    });
    if root.count() != 1 {
        return None;
    }
    let mut owners = types.iter().filter(|ty| {
        ty.name == candidate.owner
            && ty.type_kind == TypeKind::Module
            && ty.visibility == Visibility::Public
    });
    let owner = owners.next()?;
    if owners.next().is_some() {
        return None;
    }
    let mut callables = members.iter().filter(|member| {
        member.owner == owner.id
            && member.name == candidate.member
            && member.member_kind == MemberKind::Function
            && member.visibility == Visibility::Public
            && member.is_static
            && member.receiver.is_none()
            && member.signature.is_some()
    });
    let callable = callables.next()?;
    if callables.next().is_some() {
        return None;
    }
    Some((
        callable.id.clone(),
        callable.signature.as_ref()?.parameters.len(),
        callable.locator.clone(),
    ))
}

fn digest(bytes: &[u8]) -> String {
    brokk_bifrost_analysis::analyzer::canonical_hash::lower_hex_string(
        &Sha256::digest(bytes).into(),
    )
}

/// The caller supplies paths relative to rust/ql/lib, never host paths.
pub fn audit_pinned_rust_models(files: &[(String, Vec<u8>)]) -> Result<Audit, String> {
    let expected: BTreeMap<&str, &str> = PINNED
        .lines()
        .map(|line| line.split_once(' ').expect("pinned manifest line"))
        .collect();
    if expected.len() != 51 {
        return Err("bad embedded Rust MaD pin set".into());
    }
    let mut seen = BTreeSet::new();
    let mut sorted = files.iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut file_set = String::new();
    let mut rows = Vec::new();
    let mut counts = BTreeMap::new();
    let mut excluded = 0;
    for (path, bytes) in sorted {
        if path.contains("..")
            || path.starts_with('/')
            || path.contains('\\')
            || !seen.insert(path.as_str())
        {
            return Err(format!("invalid or duplicate Rust MaD path: {path}"));
        }
        let hash = digest(bytes);
        if expected.get(path.as_str()) != Some(&hash.as_str()) {
            return Err(format!("unrecognized or changed Rust MaD file: {path}"));
        }
        file_set.push_str(path);
        file_set.push(' ');
        file_set.push_str(&hash);
        file_set.push('\n');
        let doc: Document =
            super::parse_codeql_yaml(bytes).map_err(|error| format!("{path}: {error}"))?;
        for (ext_no, extension) in doc.extensions.iter().enumerate() {
            if extension.adds_to.pack != "codeql/rust-all" {
                return Err(format!("{path}: unexpected pack"));
            }
            let (kind, width) = match extension.adds_to.extensible.as_str() {
                "sourceModel" | "sinkModel" => (extension.adds_to.extensible.as_str(), 4),
                "summaryModel" => ("summaryModel", 5),
                "neutralModel" => ("neutralModel", 3),
                "excludeFieldTaintStep" => ("excludeFieldTaintStep", 1),
                "additionalExternalFile" if extension.data.is_empty() => continue,
                other => return Err(format!("{path}: unknown extension {other}")),
            };
            for (row_no, cells) in extension.data.iter().enumerate() {
                if cells.len() != width {
                    return Err(format!(
                        "{path}: extension {} row {} has {} cells, expected {width}",
                        ext_no + 1,
                        row_no + 1,
                        cells.len()
                    ));
                }
                *counts.entry(kind.to_owned()).or_insert(0) += 1;
                if kind == "excludeFieldTaintStep" {
                    excluded += 1;
                }
                let (status, reason, candidate) = decide(kind, cells);
                rows.push(RowDecision {
                    key: RowKey {
                        commit: CODEQL_COMMIT,
                        path: path.clone(),
                        extension_ordinal: ext_no + 1,
                        row_ordinal: row_no + 1,
                        row_sha256: digest(&serde_json::to_vec(cells).map_err(|e| e.to_string())?),
                    },
                    kind: kind.to_owned(),
                    status,
                    reason,
                    candidate,
                    binding: None,
                    cells: cells.clone(),
                });
            }
        }
    }
    if seen.len() != expected.len() {
        return Err(format!(
            "missing {} pinned Rust MaD files",
            expected.len() - seen.len()
        ));
    }
    let mut status_by_reason = BTreeMap::new();
    let mut breakdown: BTreeMap<(String, String, String, String, Vec<String>), usize> =
        BTreeMap::new();
    for row in &rows {
        *status_by_reason
            .entry(format!("{}:{}", row.status, row.reason))
            .or_insert(0) += 1;
        if row.status != "translated" {
            let paths = match row.kind.as_str() {
                "summaryModel" => row.cells[1..3].to_vec(),
                "sourceModel" | "sinkModel" => row.cells[1..2].to_vec(),
                _ => Vec::new(),
            };
            *breakdown
                .entry((
                    row.status.to_owned(),
                    row.reason.to_owned(),
                    row.kind.clone(),
                    row.key.path.clone(),
                    paths,
                ))
                .or_default() += 1;
        }
    }
    let ledger_rows_sha256 = digest(&serde_json::to_vec(&rows).map_err(|e| e.to_string())?);
    let skip_breakdown = breakdown
        .into_iter()
        .map(|((status, reason, kind, file, paths), rows)| SkipBucket {
            status,
            reason,
            kind,
            file,
            paths,
            rows,
        })
        .collect();
    Ok(Audit {
        translator: TRANSLATOR,
        source_commit: CODEQL_COMMIT,
        file_count: seen.len(),
        file_set_sha256: digest(file_set.as_bytes()),
        ledger_rows_sha256,
        semantic_output_sha256: digest(b""),
        artifact_digests: BTreeMap::new(),
        rows_by_kind: counts,
        status_by_reason,
        skip_breakdown,
        model_rows: rows.len() - excluded,
        excluded_field_rows: excluded,
        emitted_transfers: 0,
        certified_std_free_function_rows: 0,
        std_candidate_remaining_by_reason: BTreeMap::new(),
        rows,
    })
}

fn decide(kind: &str, cells: &[String]) -> (&'static str, &'static str, Option<CallableCandidate>) {
    if kind == "excludeFieldTaintStep" {
        return ("skipped", "field_exclusion_requires_engine_support", None);
    }
    let candidate = match callable_candidate(&cells[0]) {
        Ok(candidate) => candidate,
        Err(reason) => return ("skipped", reason, None),
    };
    if candidate.trait_owner.is_some() {
        return ("skipped", "unproven_trait_dispatch", Some(candidate));
    }
    if kind == "neutralModel" {
        return ("skipped", "neutral_precedence_unsupported", Some(candidate));
    }
    let paths = match kind {
        "summaryModel" => &[cells[1].as_str(), cells[2].as_str()][..],
        _ => &[cells[1].as_str()][..],
    };
    if paths.iter().any(|path| !simple_port(path)) {
        return ("skipped", "unsupported_access_path", Some(candidate));
    }
    if kind == "summaryModel" && !matches!(cells[3].as_str(), "taint" | "value") {
        return ("skipped", "unknown_transfer_kind", Some(candidate));
    }
    if candidate.explicit_type_owner
        && paths.contains(&"Argument[self]")
        && matches!(candidate.crate_root.as_str(), "std" | "core" | "alloc")
    {
        // #6542: these must attach to the rustdoc-derived std pack, whose
        // selected method identities are not currently resolvable.
        return ("blocked", "std_binding_pending_6542", Some(candidate));
    }
    ("blocked", "missing_declaration_evidence", Some(candidate))
}
fn simple_port(value: &str) -> bool {
    match super::parse_access_path(value) {
        Ok(path) if path.components.is_empty() => match path.root {
            super::MadRoot::ReturnValue => true,
            super::MadRoot::Argument(items) => matches!(
                items.as_slice(),
                [super::MadArgumentItem::Index(_) | super::MadArgumentItem::This]
            ),
        },
        _ => false,
    }
}

/// Parse model data with the same grammar as analyzed Rust, then read AST leaves.
/// This yields only a candidate: the selected resolver must still prove binding.
fn callable_candidate(input: &str) -> Result<CallableCandidate, &'static str> {
    let source = format!("fn __mad() {{ let _ = {input}; }}");
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|_| "rust_grammar_unavailable")?;
    let tree = parser.parse(&source, None).ok_or("non_rust_mad_path")?;
    if tree.root_node().has_error() {
        return Err("non_rust_mad_path");
    }
    let mut names = Vec::new();
    fn visit(node: tree_sitter::Node<'_>, source: &str, names: &mut Vec<String>) {
        if matches!(
            node.kind(),
            "identifier" | "type_identifier" | "primitive_type"
        ) {
            names.push(source[node.byte_range()].to_owned());
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            visit(child, source, names);
        }
    }
    // Select only the let value; never collect the synthetic function name.
    fn find_let(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
        if node.kind() == "let_declaration" {
            return node.child_by_field_name("value");
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(found) = find_let(child) {
                return Some(found);
            }
        }
        None
    }
    fn find_kind<'tree>(
        node: tree_sitter::Node<'tree>,
        kind: &str,
    ) -> Option<tree_sitter::Node<'tree>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(found) = find_kind(child, kind) {
                return Some(found);
            }
        }
        None
    }
    let value = find_let(tree.root_node()).ok_or("non_rust_mad_path")?;
    if find_kind(value, "generic_type").is_some() || find_kind(value, "type_arguments").is_some() {
        return Err("generic_owner_unbound");
    }
    let trait_parts = if let Some(qualified) = find_kind(value, "qualified_type") {
        let mut self_names = Vec::new();
        let mut trait_names = Vec::new();
        visit(
            qualified
                .child_by_field_name("type")
                .ok_or("non_rust_mad_path")?,
            &source,
            &mut self_names,
        );
        visit(
            qualified
                .child_by_field_name("alias")
                .ok_or("non_rust_mad_path")?,
            &source,
            &mut trait_names,
        );
        let trait_root = trait_names.first().cloned().ok_or("non_rust_mad_path")?;
        let trait_owner = trait_names.join(".");
        let self_type = (!self_names.is_empty()).then(|| self_names.join("."));
        Some((trait_owner, trait_root, self_type))
    } else {
        None
    };
    if value.has_error()
        || matches!(value.kind(), "call_expression" | "macro_invocation")
        || find_kind(value, "tuple_type").is_some()
    {
        return Err("unsupported_callable_syntax");
    }
    visit(value, &source, &mut names);
    if names.len() < 2 || names.iter().any(|part| part == "__mad") {
        return Err("unsupported_callable_syntax");
    }
    let member = names.pop().ok_or("unsupported_callable_syntax")?;
    let crate_root = trait_parts
        .as_ref()
        .map(|(_, root, _)| root.clone())
        .or_else(|| names.first().cloned())
        .ok_or("unsupported_callable_syntax")?;
    let owner = trait_parts
        .as_ref()
        .map_or_else(|| names.join("."), |(owner, _, _)| owner.clone());
    Ok(CallableCandidate {
        crate_root,
        owner,
        member,
        trait_owner: trait_parts.as_ref().map(|(owner, _, _)| owner.clone()),
        self_type: trait_parts.and_then(|(_, _, self_type)| self_type),
        explicit_type_owner: find_kind(value, "bracketed_type").is_some(),
        receiver_proven: false,
        arity_proven: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pinned_stdlib_preflight_when_source_set_is_supplied() {
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            ActivationSelector, ArtifactProducerLimits, ArtifactProductionRequest, Compatibility,
            ExternalArtifactKind, NameSelector, Provenance, Safety, read_exact_source_set,
        };
        use brokk_bifrost_rust_analysis::analyzer::rust::RustdocJsonPackProducer;
        let Ok(source_root) = std::env::var("RUST_MAD_STDLIB_SOURCE_SET") else {
            return;
        };
        let root = std::path::Path::new(&source_root);
        let paths = ["core.json", "alloc.json", "std.json"]
            .map(std::path::PathBuf::from)
            .to_vec();
        let limits = ArtifactProducerLimits::default();
        let artifact = read_exact_source_set(root, &paths, 3, 8, &limits).unwrap();
        assert_eq!(
            artifact.sha256(),
            "c7ef5e3d3c34f267d81d2c06f1d5cacced6abdfd59e51e5b8467529600ef5bce"
        );
        let request = ArtifactProductionRequest {
            path: root.to_path_buf(),
            artifact_kind: ExternalArtifactKind::RustdocJsonSet,
            pack_id: "bifrost.rust-stdlib".into(),
            pack_version: "1.100.0-nightly".into(),
            ecosystem: "cargo".into(),
            compatibility: Compatibility { bifrost: None, toolchains: vec![serde_json::from_value(json!({"name":"rust","requirement":"=1.100.0-nightly"})).unwrap()] },
            activation: vec![ActivationSelector {
                package: None, module: None,
                toolchain: Some(NameSelector { name: "rust".into(), version: Some("=1.100.0-nightly".into()) }),
                targets: Vec::new(), configurations: Vec::new(), artifact_sha256: None,
            }],
            provenance: Provenance { source: "https://static.rust-lang.org/dist/2026-08-24/rust-docs-json-nightly-x86_64-unknown-linux-gnu.tar.xz".into(), revision: Some("fb6531d550e0075b9eb9a51464f404805eec87d9".into()), rust_artifact_approximation: None },
            license: "MIT OR Apache-2.0".into(),
            safety: Safety { generated_code_only: true, review_required: true },
        };
        let crates = ["core", "alloc", "std"].map(|name| (name.to_owned(), format!("{name}.json")));
        let production = RustdocJsonPackProducer
            .produce_loaded_source_set(&request, &limits, None, &artifact, &crates);
        let declarations = production
            .pack
            .expect("pinned source set must produce declarations");
        let mut audit = Audit {
            translator: TRANSLATOR,
            source_commit: CODEQL_COMMIT,
            file_count: 0,
            file_set_sha256: String::new(),
            ledger_rows_sha256: String::new(),
            semantic_output_sha256: String::new(),
            artifact_digests: BTreeMap::new(),
            rows_by_kind: BTreeMap::new(),
            status_by_reason: BTreeMap::new(),
            skip_breakdown: Vec::new(),
            model_rows: 1,
            excluded_field_rows: 0,
            emitted_transfers: 0,
            certified_std_free_function_rows: 0,
            std_candidate_remaining_by_reason: BTreeMap::new(),
            rows: Vec::new(),
        };
        audit.rows.push(RowDecision {
            key: RowKey {
                commit: CODEQL_COMMIT,
                path: "fixture".into(),
                extension_ordinal: 1,
                row_ordinal: 1,
                row_sha256: "fixture".into(),
            },
            kind: "sinkModel".into(),
            status: "blocked",
            reason: "missing_declaration_evidence",
            candidate: Some(callable_candidate("std::fs::read").unwrap()),
            binding: None,
            cells: vec![
                "std::fs::read".into(),
                "Argument[0]".into(),
                "path-injection".into(),
                "manual".into(),
            ],
        });
        let expected = StdlibDeclarationEvidence {
            pack_id: "bifrost.rust-stdlib",
            version: "1.100.0-nightly",
            source_set_digest: artifact.sha256(),
        };
        let bindings = preflight_std_free_functions(&audit, &declarations, &expected).unwrap();
        assert_eq!(
            bindings.len(),
            1,
            "std::fs::read should have unique public rustdoc evidence"
        );
        assert_eq!(bindings[0].row.row_ordinal, 1);
        audit.rows.push(RowDecision {
            key: RowKey {
                commit: CODEQL_COMMIT,
                path: "fixture".into(),
                extension_ordinal: 1,
                row_ordinal: 2,
                row_sha256: "summary-fixture".into(),
            },
            kind: "summaryModel".into(),
            status: "blocked",
            reason: "missing_declaration_evidence",
            candidate: Some(callable_candidate("alloc::fmt::format").unwrap()),
            binding: None,
            cells: vec![
                "alloc::fmt::format".into(),
                "Argument[0]".into(),
                "ReturnValue".into(),
                "taint".into(),
                "manual".into(),
            ],
        });
        let (summary_pack, attached) =
            build_std_taint_summary_pack(&audit, &declarations, &expected).unwrap();
        assert_eq!(
            attached.len(),
            1,
            "the real alloc::fmt::format row attaches"
        );
        assert!(
            summary_pack
                .shards
                .iter()
                .all(|shard| matches!(shard.payload, AuthoredPayload::ProcedureSummaries { .. }))
        );
        let compiled = brokk_bifrost_analysis::analyzer::semantic_model::compile_pack(
            &summary_pack,
            &Default::default(),
        );
        assert!(
            compiled.is_ok(),
            "summary-only pack must compile: {compiled:?}"
        );
        if let Ok(codeql_root) = std::env::var("RUST_MAD_CODEQL_ROOT") {
            let mut files = Vec::new();
            for relative in ["codeql/rust/frameworks", "ext/generated"] {
                let directory = std::path::Path::new(&codeql_root).join(relative);
                files.extend(
                    super::super::super::read_codeql_models(&directory)
                        .unwrap()
                        .into_iter()
                        .map(|(name, bytes)| (format!("{relative}/{name}"), bytes)),
                );
            }
            let full_audit = audit_pinned_rust_models(&files).unwrap();
            let (full_pack, full_rows) =
                build_std_taint_summary_pack(&full_audit, &declarations, &expected).unwrap();
            assert_eq!(full_rows.len(), 16);
            assert_eq!(
                serde_json::to_vec_pretty(&full_pack).unwrap(),
                include_bytes!("../../../testdata/summary-corpora/codeql-rust/expected-pack.json"),
                "pinned corpus summary pack changed"
            );
            let certified =
                preflight_std_free_functions(&full_audit, &declarations, &expected).unwrap();
            assert_eq!(certified.len(), 112);
            let (catalogs, catalog_rows) = std_endpoint_catalogs(&full_audit, &certified).unwrap();
            assert_eq!((catalogs.len(), catalog_rows.len()), (9, 51));
            for (name, catalog) in catalogs {
                let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("testdata/summary-corpora/codeql-rust/catalogs")
                    .join(format!("{name}.json"));
                assert_eq!(
                    serde_json::to_vec_pretty(&catalog).unwrap(),
                    std::fs::read(fixture).unwrap()
                );
            }
        }
    }

    #[test]
    fn std_free_function_requires_unique_public_module_and_receiverless_callable() {
        assert!(positional_port_fits("Argument[0]", 1));
        assert!(!positional_port_fits("Argument[1]", 1));
        assert!(!positional_port_fits("Argument[self]", 1));
        assert!(!positional_port_fits("Argument[0,1]", 2));
        let root: TypeFact = serde_json::from_value(json!({
            "id":"root", "name":"std", "type_kind":"module",
            "visibility":"public", "locator":{"kind":"artifact","path":"std.json","symbol":"std"}
        }))
        .unwrap();
        let owner: TypeFact = serde_json::from_value(json!({
            "id":"module", "name":"std.fs", "type_kind":"module",
            "visibility":"public", "locator":{"kind":"artifact","path":"std.json","symbol":"std.fs"}
        }))
        .unwrap();
        let mut function: MemberFact = serde_json::from_value(json!({
            "id":"function", "owner":"module", "name":"read", "member_kind":"function",
            "visibility":"public", "is_static":true, "signature":{"parameters":[]},
            "callable_family_complete":true,
            "locator":{"kind":"artifact","path":"std.json","symbol":"std.fs.read"}
        }))
        .unwrap();
        let candidate = callable_candidate("std::fs::read").unwrap();
        assert_eq!(
            unique_public_free_function(&[&root, &owner], &[&function], &candidate),
            Some(("function".into(), 0, function.locator.clone()))
        );
        assert!(
            unique_public_free_function(&[&root, &owner], &[&function, &function], &candidate)
                .is_none()
        );
        function.visibility = Visibility::Private;
        assert!(unique_public_free_function(&[&root, &owner], &[&function], &candidate).is_none());
        function.visibility = Visibility::Public;
        function.receiver = Some(serde_json::from_value(json!({})).unwrap());
        assert!(unique_public_free_function(&[&root, &owner], &[&function], &candidate).is_none());
    }
    #[test]
    fn direct_candidate() {
        let c = callable_candidate("reqwest::blocking::get").unwrap();
        assert_eq!(c.owner, "reqwest.blocking");
        assert_eq!(c.crate_root, "reqwest");
        assert_eq!(c.member, "get");
    }
    #[test]
    fn associated_type_candidate() {
        let c = callable_candidate("<reqwest::blocking::Response>::text").unwrap();
        assert_eq!(c.owner, "reqwest.blocking.Response");
        assert_eq!(c.crate_root, "reqwest");
        assert_eq!(c.member, "text");
        assert!(!c.receiver_proven);
        assert!(!c.arity_proven);
    }
    #[test]
    fn trait_candidate_is_not_asserted() {
        let c = callable_candidate("<T as core::ops::Deref>::deref").unwrap();
        assert_eq!(c.trait_owner.as_deref(), Some("core.ops.Deref"));
        assert_eq!(c.crate_root, "core");
        assert_eq!(c.self_type.as_deref(), Some("T"));
        assert_eq!(c.member, "deref");
        let row = vec![
            "<T as core::ops::Deref>::deref".into(),
            "Argument[self]".into(),
            "ReturnValue".into(),
            "taint".into(),
            "manual".into(),
        ];
        assert_eq!(decide("summaryModel", &row).1, "unproven_trait_dispatch");
    }
    #[test]
    fn explicit_ufcs_candidate_is_not_binding_proof() {
        let c = callable_candidate("<std::io::Stdin as std::io::Read>::read").unwrap();
        assert_eq!(c.trait_owner.as_deref(), Some("std.io.Read"));
        assert_eq!(c.self_type.as_deref(), Some("std.io.Stdin"));
        assert_eq!(c.member, "read");
        assert!(!c.receiver_proven);
    }
    #[test]
    fn generic_owner_is_not_minted() {
        assert!(matches!(
            callable_candidate("<std::vec::Vec<T>>::len"),
            Err("generic_owner_unbound")
        ));
    }
    #[test]
    fn aliases_and_std_calls_require_external_proof() {
        let alias = vec![
            "alias::module::run".into(),
            "Argument[0]".into(),
            "command-injection".into(),
            "manual".into(),
        ];
        let (status, reason, alias_candidate) = decide("sinkModel", &alias);
        assert_eq!(
            (status, reason),
            ("blocked", "missing_declaration_evidence")
        );
        assert_eq!(alias_candidate.unwrap().owner, "alias.module");
        let shadowed = vec![
            "local_shadow::module::run".into(),
            "Argument[0]".into(),
            "command-injection".into(),
            "manual".into(),
        ];
        let (status, reason, shadowed_candidate) = decide("sinkModel", &shadowed);
        assert_eq!(
            (status, reason),
            ("blocked", "missing_declaration_evidence")
        );
        assert_eq!(shadowed_candidate.unwrap().owner, "local_shadow.module");
        let std_free = vec![
            "std::fs::read".into(),
            "Argument[0]".into(),
            "path-injection".into(),
            "manual".into(),
        ];
        assert_eq!(
            decide("sinkModel", &std_free).1,
            "missing_declaration_evidence"
        );
        let std_associated = vec![
            "std::process::Command::new".into(),
            "Argument[0]".into(),
            "command-injection".into(),
            "manual".into(),
        ];
        assert_eq!(
            decide("sinkModel", &std_associated).1,
            "missing_declaration_evidence"
        );
        let std_method = vec![
            "<std::option::Option>::take".into(),
            "Argument[self]".into(),
            "ReturnValue".into(),
            "taint".into(),
            "manual".into(),
        ];
        assert_eq!(
            decide("summaryModel", &std_method).1,
            "std_binding_pending_6542"
        );
    }
    #[test]
    fn unions_are_not_flattened() {
        assert!(!simple_port("Argument[0,1]"));
        assert!(!simple_port("ReturnValue.Field[x]"));
    }
    #[test]
    fn rust_yaml_rejects_unknown_fields_and_duplicate_keys() {
        let extra = b"extensions: []\nextra: true\n";
        assert!(super::super::parse_codeql_yaml::<Document>(extra).is_err());
        let duplicate = b"extensions: []\nextensions: []\n";
        assert!(super::super::parse_codeql_yaml::<Document>(duplicate).is_err());
    }
}
