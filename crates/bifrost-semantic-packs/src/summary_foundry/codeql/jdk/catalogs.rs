//! Offline CodeQL endpoint catalogs. No generated product catalogs live here.
use super::*;
use brokk_bifrost_policy::{CatalogSourceIdentity, PolicyCategoryId, TaintCatalogRegistry};
use brokk_bifrost_rql::query::{CallArgumentSelector, CallIdentity, CodeQuery, QueryStep};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const LABEL: &str = "attacker-controlled";

#[derive(Debug, Default, Serialize)]
pub struct CatalogReport {
    pub codeql_commit: String,
    pub catalog_version: u32,
    pub catalogs: BTreeMap<String, CatalogCounts>,
    pub translated_rows: u32,
    pub skipped_by_reason: BTreeMap<String, u32>,
    pub collapsed_by_content_kind: BTreeMap<String, u32>,
    pub rows_by_extensible_and_kind: BTreeMap<String, BTreeMap<String, u32>>,
    pub skipped_targets_by_reason: BTreeMap<String, u32>,
    pub source_kinds_without_threat_model: BTreeSet<String>,
    /// Exact CodeQL `.expected` model rows that emitted at least one catalog entry.
    pub rows_by_catalog: BTreeMap<String, BTreeSet<String>>,
    pub neutrals_by_kind: BTreeMap<String, u32>,
    pub conflicts: BTreeSet<String>,
    /// The catalog wire format has no corpus provenance field. Count every
    /// in-scope row, including rows that cannot produce a catalog entry.
    pub rows_by_provenance: BTreeMap<String, u32>,
    pub unmatched_declarations: Vec<JdkRow>,
}

#[derive(Debug, Default, Serialize)]
pub struct CatalogCounts {
    pub entries: usize,
    pub semantic_hash: String,
}

/// Canonical M5 catalog documents keyed by stable catalog name.
/// The caller owns publication, version increments and the corpus MIT notice.
pub fn generate_jvm_catalogs(
    files: &[(String, Vec<u8>)],
    types: &[JvmType],
    commit: &str,
    prefix: &str,
    version: u32,
) -> Result<(BTreeMap<String, Value>, CatalogReport), CodeqlParseError> {
    assert!(version > 0, "catalog version must be positive");
    assert!(!prefix.is_empty(), "catalog prefix must not be empty");
    let inventory = JvmInventory::new(types);
    let mut report = CatalogReport {
        codeql_commit: commit.to_owned(),
        catalog_version: version,
        ..Default::default()
    };
    let mut catalogs = BTreeMap::<String, Value>::new();
    let mut neutrals = BTreeSet::new();
    let mut positives = BTreeSet::new();
    for_each_codeql_row(files, |file, kind, ordinal, row| {
        let mut translate = || -> Result<(), &'static str> {
            if !matches!(
                kind,
                SOURCE_MODEL | SINK_MODEL | "barrierModel" | "barrierGuardModel" | NEUTRAL_MODEL
            ) {
                return Err("extensible_out_of_scope");
            }
            let neutral = kind == NEUTRAL_MODEL;
            let columns = if neutral {
                NEUTRAL_ROW_COLUMNS
            } else if kind == "barrierGuardModel" {
                10
            } else {
                ENDPOINT_ROW_COLUMNS
            };
            if row.len() != columns {
                return Err("malformed_row");
            }
            *report
                .rows_by_provenance
                .entry(row[columns - 1].text().to_owned())
                .or_default() += 1;
            if kind == "barrierGuardModel" {
                return Err("guard_sanitizer_requires_conditional_guard_support");
            }
            let category = row[if neutral { 4 } else { 7 }].text();
            *report
                .rows_by_extensible_and_kind
                .entry(kind.to_owned())
                .or_default()
                .entry(category.to_owned())
                .or_default() += 1;
            if neutral {
                if !matches!(category, "sink" | "source") {
                    return Err("neutral_not_sink_or_source");
                }
                *report
                    .neutrals_by_kind
                    .entry(category.to_owned())
                    .or_default() += 1;
            }
            if category.starts_with("regex-use[") && category.ends_with(']') {
                return Err("kind_argument_qualifier_unsupported");
            }
            let name_column = if neutral { 2 } else { 3 };
            let signature =
                parse_signature(row[name_column + 1].text()).map_err(|_| "malformed_signature")?;
            let subtypes = if neutral {
                false
            } else {
                row[2].boolean().ok_or("malformed_subtypes")?
            };
            let targets = inventory.targets(
                row[0].text(),
                row[1].text(),
                row[name_column].text(),
                &signature,
                subtypes,
            );
            if targets.is_empty() {
                report.unmatched_declarations.push(JdkRow {
                    file: file.to_owned(),
                    row: ordinal,
                    cells: row.iter().map(|cell| cell.text().to_owned()).collect(),
                });
                return Err("unmatched_declaration");
            }
            if neutral {
                for (ty, method) in targets {
                    neutrals.insert((target(ty, method), category.to_owned()));
                }
                return Ok(());
            }
            let catalog_category = match category {
                "path-injection[read]" => "path-injection-read",
                _ => category,
            };
            PolicyCategoryId::new(catalog_category)
                .map_err(|_| "kind_not_expressible_as_catalog_category")?;
            if !row[5].text().is_empty() {
                return Err("extension_qualifier");
            }
            if kind == SOURCE_MODEL
                && parse_component(row[6].text()).is_ok_and(|(head, _)| head.name == "Parameter")
            {
                return Err("source_parameter_requires_override_binding_support");
            }
            let path = parse_access_path(row[6].text()).map_err(|_| "unsupported_access_path")?;
            if kind == SOURCE_MODEL && matches!(path.root, MadRoot::Argument(_)) {
                return Err("source_argument_requires_heap_write_support");
            }
            let mut contents = BTreeSet::new();
            for component in &path.components {
                if kind != SINK_MODEL {
                    return Err("source_or_barrier_content_requires_heap_support");
                }
                match component.name.as_str() {
                    "Element" | "MapKey" | "MapValue" | "ArrayElement" | "Field"
                    | "SyntheticField" => {
                        contents.insert(component.name.clone());
                    }
                    _ => return Err("unsupported_access_path"),
                }
            }
            let role = match kind {
                SINK_MODEL => "sinks",
                SOURCE_MODEL => "sources",
                _ => "barriers",
            };
            let name = format!("codeql-{prefix}-{role}-{catalog_category}");
            let mut emitted = false;
            let mut reasons = BTreeSet::new();
            for (ty, method) in targets {
                let ports = match ports(&path.root, method) {
                    Ok(ports) => ports,
                    Err(reason) => {
                        reasons.insert(reason);
                        *report
                            .skipped_targets_by_reason
                            .entry(reason.to_owned())
                            .or_default() += 1;
                        continue;
                    }
                };
                if kind == SINK_MODEL && matches!(path.root, MadRoot::ReturnValue) {
                    reasons.insert("sink_return_value_not_expressible");
                    continue;
                }
                let target = target(ty, method);
                let symbol = format!(
                    "{}.{}({})",
                    ty.name,
                    method.name,
                    method.parameters.join(",")
                );
                // A declared target is sufficient for a boundary endpoint; it
                // makes no claim about runtime dispatch or receiver identity.
                // Let call bindings determine arity: Java varargs need not
                // have the same written argument count as the declaration.
                let call = if method.name == "<init>" {
                    // Constructor source spellings differ from JVM member names.
                    "(call)".to_owned()
                } else {
                    format!(
                        "(call :callee (name {}))",
                        serde_json::to_string(&method.name).expect("string")
                    )
                };
                let mut query = CodeQuery::from_sexp(&format!(
                    "(language java (resolved-call :resolves-to member.generated :proof declared (call-bindings (call-shape {call}))))"
                )).expect("generated declared-call query");
                // A qualified name denotes an overload family. Use the actual
                // JMOD declaration ID so equal-arity overloads stay distinct.
                for step in &mut query.plan.steps {
                    if let QueryStep::ResolvedCall(filter) = step {
                        filter.resolves_to = CallIdentity::Stable(method.id.clone());
                    }
                }
                for port in ports {
                    let mut query = query.clone();
                    if let Some(index) = port.get("index").and_then(Value::as_u64) {
                        // Policy indexed ports consume the selected formal's
                        // actual binding, rather than every binding of the call.
                        query.plan.steps.push(QueryStep::CallArgument(
                            CallArgumentSelector::FormalIndex(
                                usize::try_from(index).expect("port ordinal fits usize"),
                            ),
                        ));
                    }
                    let selector = json!({"type": "inline", "schema_version": 1, "query": query.to_canonical_query_plan_json()});
                    let mut identity = json!([role, catalog_category, symbol, port]);
                    identity.sort_all_objects();
                    let digest = Sha256::digest(serde_json::to_vec(&identity).expect("identity"));
                    let id = format!("codeql-{digest:x}");
                    let mut entry = json!({
                        "id": id,
                        "categories": [catalog_category],
                        "selector": selector
                    });
                    let array = match kind {
                        SINK_MODEL => {
                            entry["display_name"] = json!(symbol);
                            entry["dangerous_operand"] = port;
                            entry["accepts"] = json!([LABEL]);
                            entry["tags"] = json!([]);
                            entry["impacts"] = json!([]);
                            positives.insert((
                                target.clone(),
                                "sink".to_owned(),
                                catalog_category.to_owned(),
                            ));
                            "sinks"
                        }
                        SOURCE_MODEL => {
                            entry["display_name"] = json!(symbol);
                            entry["bind"] = port;
                            entry["labels"] = json!([LABEL]);
                            // M5 has a finite threat-model enum. Preserve every
                            // CodeQL kind as its category even without an enum value.
                            entry["threat_model"] = if matches!(
                                category,
                                "remote"
                                    | "commandargs"
                                    | "environment"
                                    | "stdin"
                                    | "file"
                                    | "database"
                            ) {
                                json!(category)
                            } else {
                                report
                                    .source_kinds_without_threat_model
                                    .insert(category.to_owned());
                                Value::Null
                            };
                            entry["evidence"] = Value::Null;
                            positives.insert((
                                target.clone(),
                                "source".to_owned(),
                                catalog_category.to_owned(),
                            ));
                            "sources"
                        }
                        _ => {
                            entry["input"] = port.clone();
                            entry["output"] = port;
                            entry["removes"] = json!([LABEL]);
                            "sanitizers"
                        }
                    };
                    let catalog = catalogs.entry(name.clone()).or_insert_with(|| json!({
                        "schema_version": 1, "name": name, "version": version, "categories": [catalog_category],
                        "sources": [], "sinks": [], "sanitizers": [], "transforms": [], "external_models": []
                    }));
                    catalog[array]
                        .as_array_mut()
                        .expect("entry array")
                        .push(entry);
                    emitted = true;
                }
            }
            if !emitted {
                return Err(reasons.first().copied().unwrap_or("empty_port_set"));
            }
            if matches!(kind, SOURCE_MODEL | SINK_MODEL) {
                let role = if kind == SOURCE_MODEL {
                    "Source"
                } else {
                    "Sink"
                };
                let printed_row = format!(
                    "{role}: {}",
                    row.iter().map(MadCell::text).collect::<Vec<_>>().join("; ")
                );
                report
                    .rows_by_catalog
                    .entry(name.clone())
                    .or_default()
                    .insert(printed_row);
            }
            report.translated_rows += 1;
            for content in contents {
                *report.collapsed_by_content_kind.entry(content).or_default() += 1;
            }
            Ok(())
        };
        if let Err(reason) = translate() {
            *report
                .skipped_by_reason
                .entry(reason.to_owned())
                .or_default() += 1;
        }
    })?;
    for (target, role, category) in positives {
        if neutrals.contains(&(target.clone(), role.clone())) {
            report.conflicts.insert(format!(
                "{} {:?}: {role}/{category}",
                target.member, target.signature
            ));
        }
    }
    let mut registry = TaintCatalogRegistry::new_without_workspace(Default::default());
    for (name, catalog) in &mut catalogs {
        for array in ["sources", "sinks", "sanitizers"] {
            let entries = catalog[array].as_array_mut().expect("entry array");
            entries.sort_by_cached_key(|entry| entry["id"].as_str().expect("entry id").to_owned());
            entries.dedup();
        }
        let bytes = serde_json::to_vec(catalog).expect("catalog JSON");
        let hash = registry
            .register_json_bytes(
                CatalogSourceIdentity::new(name.clone()).expect("catalog identity"),
                &bytes,
            )
            .map_err(|error| CodeqlParseError {
                file: name.clone(),
                message: error.to_string(),
            })?;
        let registered = registry
            .iter()
            .find(|item| item.semantic_hash() == hash)
            .expect("registered catalog");
        *catalog =
            serde_json::from_slice(registered.canonical_json()).expect("canonical catalog JSON");
        report.catalogs.insert(
            name.clone(),
            CatalogCounts {
                entries: registered.definition().entry_count(),
                semantic_hash: hash.to_string(),
            },
        );
    }
    report.unmatched_declarations.sort();
    Ok((catalogs, report))
}

fn ports(root: &MadRoot, method: &JvmMethod) -> Result<Vec<Value>, &'static str> {
    let mut ports = Vec::new();
    match root {
        MadRoot::ReturnValue => ports.push(json!({"type": "return_value"})),
        MadRoot::Argument(items) => {
            for item in items {
                match item {
                    MadArgumentItem::This => {
                        if !method.has_receiver {
                            return Err("receiver_on_static_method");
                        }
                        ports.push(json!({"type": "receiver"}));
                    }
                    MadArgumentItem::Index(index) => {
                        if *index as usize >= method.parameters.len() {
                            return Err("argument_index_out_of_bounds");
                        }
                        ports.push(json!({"type": "argument_index", "index": index}));
                    }
                    MadArgumentItem::Range(low, high) => {
                        if *high as usize >= method.parameters.len() {
                            return Err("argument_index_out_of_bounds");
                        }
                        ports.extend(
                            (*low..=*high)
                                .map(|index| json!({"type": "argument_index", "index": index})),
                        );
                    }
                }
            }
        }
    }
    Ok(ports)
}
