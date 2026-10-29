//! Offline declaration expansion of the foundry's CodeQL summary translation.
//!
//! Root-only CodeQL value rows from Argument[this] to ReturnValue classify
//! receiver identity. Taint rows and collapsed content paths remain unclassified.
//!
//! Pack `completeness: complete` means each summary carried by the pack is a
//! complete contract, not that every JDK callable is modeled. `require-model`
//! handles absent summaries per call.
pub mod catalogs;

use super::*;
use brokk_bifrost_analysis::analyzer::semantic_model::{
    ActivationSelector, AuthoredPayload, AuthoredSemanticModelPack, AuthoredShard, Compatibility,
    Completeness, Locator, MemberKind, NameSelector, Provenance, SummaryValuePreservation,
    SummaryValueTransfer, SummaryValueTransferKind, SummaryValueTransferOperation, TypeRef,
    VersionConstraint,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One run's declaration inventory, also usable with small test-only inputs.
#[derive(Debug, Deserialize, Serialize)]
pub struct JvmType {
    pub name: String,
    pub path: String,
    pub supertypes: Vec<String>,
    pub methods: Vec<JvmMethod>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JvmMethod {
    pub id: String,
    pub name: String,
    pub parameters: Vec<String>,
    pub has_receiver: bool,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct JdkRow {
    file: String,
    row: u32,
    cells: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct JdkReport {
    pub rows_by_extensible_and_kind: BTreeMap<String, BTreeMap<String, u32>>,
    pub translated_rows: u32,
    pub expanded_targets: usize,
    /// Targets with both a summary-kind neutral row and a flow row. The flow
    /// wins, as in CodeQL; the neutral does not erase an emitted transfer.
    pub targets_with_neutral_and_flow: usize,
    pub skipped_by_reason: BTreeMap<String, u32>,
    pub collapsed_by_content_kind: BTreeMap<String, u32>,
    /// Inventory of value rows whose content steps were collapsed. Emitted
    /// transfers without value_transfer make no result-identity claim.
    pub value_rows_demoted: u32,
    pub unmatched_declarations: Vec<JdkRow>,
    pub skips: Vec<FoundrySkip>,
}

/// Extract the structured inventory emitted by the existing JMOD producer.
/// Nothing is retained after the offline generator returns.
pub fn declarations(pack: &AuthoredSemanticModelPack) -> Result<Vec<JvmType>, String> {
    let mut names = BTreeMap::new();
    for shard in &pack.shards {
        let AuthoredPayload::DeclarationFacts { types, .. } = &shard.payload else {
            continue;
        };
        for ty in types {
            names.insert(ty.id.clone(), ty.name.clone());
            if let Locator::Artifact { symbol, .. } = &ty.locator
                && let Some(class) = symbol
                    .strip_prefix("classes/")
                    .unwrap_or(symbol)
                    .strip_suffix(".class")
            {
                names.insert(class.replace('/', "."), ty.name.clone());
            }
        }
    }
    let mut result = Vec::new();
    for shard in &pack.shards {
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &shard.payload else {
            continue;
        };
        for ty in types {
            let Locator::Artifact { symbol, .. } = &ty.locator else {
                return Err(format!("JMOD type has no class locator: {:?}", ty.locator));
            };
            // These are artifact entry names, not Java source syntax.
            let class = symbol
                .strip_prefix("classes/")
                .unwrap_or(symbol)
                .strip_suffix(".class")
                .ok_or_else(|| format!("invalid class entry {symbol}"))?;
            let outer = class.split('$').next().expect("class entry is nonempty");
            let module = shard.id.strip_prefix("declarations.jdk.");
            let mut methods = Vec::new();
            for member in members.iter().filter(|member| member.owner == ty.id) {
                if !matches!(
                    member.member_kind,
                    MemberKind::Constructor | MemberKind::Method
                ) {
                    continue;
                }
                let signature = member
                    .signature
                    .as_ref()
                    .ok_or_else(|| format!("no signature: {}", member.id))?;
                methods.push(JvmMethod {
                    id: member.id.clone(),
                    name: member.name.clone(),
                    parameters: signature
                        .parameters
                        .iter()
                        .map(|parameter| erased_type(&parameter.r#type, &names))
                        .collect::<Result<_, _>>()?,
                    has_receiver: member.member_kind != MemberKind::Constructor
                        && !member.is_static,
                });
            }
            result.push(JvmType {
                name: ty.name.clone(),
                path: module.map_or_else(
                    || format!("{outer}.java"),
                    |module| format!("{module}/{outer}.java"),
                ),
                supertypes: ty
                    .hierarchy
                    .iter()
                    .map(|edge| erased_type(&edge.target, &names))
                    .collect::<Result<_, _>>()?,
                methods,
            });
        }
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}

fn erased_type(ty: &TypeRef, names: &BTreeMap<String, String>) -> Result<String, String> {
    let mut current = ty;
    let mut dimensions = 0;
    while let TypeRef::Array { element } = current {
        dimensions += 1;
        current = element;
    }
    let name = match current {
        TypeRef::Named { name, .. } => names.get(name).map_or(name.as_str(), String::as_str),
        TypeRef::Declared { id, .. } => names
            .get(id)
            .map(String::as_str)
            .ok_or_else(|| format!("unknown declared type {id}"))?,
        TypeRef::TypeParameter { .. } => {
            return Err(format!(
                "JMOD inventory must provide erased parameter identities: {ty:?}"
            ));
        }
        _ => return Err(format!("unsupported JMOD parameter type: {ty:?}")),
    };
    Ok(format!("{name}{}", "[]".repeat(dimensions)))
}

fn signature_matches(signature: &FoundrySignature, parameters: &[String]) -> bool {
    match signature {
        FoundrySignature::AnyOverload => true,
        FoundrySignature::Overload { types } => {
            types.len() == parameters.len()
                && types.iter().zip(parameters).all(|(model, declared)| {
                    // The model grammar contains erased simple or qualified names and arrays.
                    let model = model.replace("...", "[]").replace('$', ".");
                    let declared = declared.replace('$', ".");
                    model == declared
                        || declared
                            .strip_suffix(&model)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                })
        }
    }
}

fn root_text(root: &MadRoot) -> String {
    match root {
        MadRoot::ReturnValue => "ReturnValue".to_owned(),
        MadRoot::Argument(items) => format!(
            "Argument[{}]",
            items
                .iter()
                .map(|item| match item {
                    MadArgumentItem::This => "this".to_owned(),
                    MadArgumentItem::Index(index) => index.to_string(),
                    MadArgumentItem::Range(low, high) => format!("{low}..{high}"),
                })
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// Query-lifetime inventory for offline JDK generators. Shared declaration identity,
/// overload matching and transitive override expansion.
struct JvmInventory<'a> {
    by_name: BTreeMap<&'a str, &'a JvmType>,
    descendants: BTreeMap<&'a str, Vec<&'a JvmType>>,
}

impl<'a> JvmInventory<'a> {
    fn new(types: &'a [JvmType]) -> Self {
        let by_name = types
            .iter()
            .map(|ty| (ty.name.as_str(), ty))
            .collect::<BTreeMap<_, _>>();
        let mut descendants: BTreeMap<&str, Vec<&JvmType>> = BTreeMap::new();
        for ty in types {
            let mut pending = ty.supertypes.iter().map(String::as_str).collect::<Vec<_>>();
            let mut seen = BTreeSet::new();
            while let Some(name) = pending.pop() {
                if !seen.insert(name) {
                    continue;
                }
                descendants.entry(name).or_default().push(ty);
                if let Some(parent) = by_name.get(name) {
                    pending.extend(parent.supertypes.iter().map(String::as_str));
                }
            }
        }
        Self {
            by_name,
            descendants,
        }
    }

    fn targets(
        &self,
        package: &str,
        type_name: &str,
        member: &str,
        signature: &FoundrySignature,
        subtypes: bool,
    ) -> Vec<(&'a JvmType, &'a JvmMethod)> {
        let name = member_name(type_name, member);
        let owner = format!("{}.{}", package, type_name.replace('$', "."));
        let owner_type = self.by_name.get(owner.as_str()).copied();
        let overridden_parameters = owner_type.map(|ty| {
            ty.methods
                .iter()
                .filter(|method| {
                    method.name == name
                        && method.has_receiver
                        && signature_matches(signature, &method.parameters)
                })
                .map(|method| &method.parameters)
                .collect::<BTreeSet<_>>()
        });
        let mut candidates = self
            .by_name
            .get(owner.as_str())
            .copied()
            .into_iter()
            .collect::<Vec<_>>();
        if subtypes && name != "<init>" {
            candidates.extend(
                self.descendants
                    .get(owner.as_str())
                    .into_iter()
                    .flatten()
                    .copied(),
            );
        }
        candidates
            .into_iter()
            .flat_map(|ty| {
                ty.methods
                    .iter()
                    .filter(|method| {
                        method.name == name
                            && (ty.name == owner
                                || (method.has_receiver
                                    && overridden_parameters.as_ref().is_none_or(|parameters| {
                                        parameters.contains(&method.parameters)
                                    })))
                            && signature_matches(signature, &method.parameters)
                    })
                    .map(move |method| (ty, method))
            })
            .collect::<Vec<_>>()
    }
}

fn target(ty: &JvmType, method: &JvmMethod) -> FoundryTarget {
    FoundryTarget {
        artifact_path: ty.path.clone(),
        member: format!("{}.{}", ty.name, method.name),
        signature: FoundrySignature::Overload {
            types: method.parameters.clone(),
        },
    }
}

/// Expand models against this run's JDK inventory, using the ordinary foundry
/// translator for the actual port, arity and transfer interpretation.
pub fn generate_jdk_summaries(
    files: &[(String, Vec<u8>)],
    types: &[JvmType],
    commit: &str,
) -> Result<(AuthoredSemanticModelPack, JdkReport), CodeqlParseError> {
    let inventory = JvmInventory::new(types);
    let mut report = JdkReport::default();
    let mut builders = BTreeMap::<FoundryTarget, FoundryEntryBuilder>::new();
    let mut boundaries = BTreeMap::new();
    for_each_codeql_row(files, |file, kind, ordinal, row| {
        let kind_column = match kind {
            SUMMARY_MODEL | "experimentalSummaryModel" => 8,
            NEUTRAL_MODEL => 4,
            SOURCE_MODEL
            | SINK_MODEL
            | "experimentalSourceModel"
            | "experimentalSinkModel"
            | "barrierModel" => 7,
            "barrierGuardModel" => 8,
            _ => usize::MAX,
        };
        let row_kind = row.get(kind_column).map_or("unknown", MadCell::text);
        *report
            .rows_by_extensible_and_kind
            .entry(kind.to_owned())
            .or_default()
            .entry(row_kind.to_owned())
            .or_default() += 1;
        let mut skip = |reason: &str| {
            *report
                .skipped_by_reason
                .entry(reason.to_owned())
                .or_default() += 1;
        };
        if !matches!(kind, SUMMARY_MODEL | NEUTRAL_MODEL) {
            skip("extensible_out_of_scope");
            return;
        }
        if row.len()
            != if kind == SUMMARY_MODEL {
                SUMMARY_ROW_COLUMNS
            } else {
                NEUTRAL_ROW_COLUMNS
            }
        {
            skip("malformed_row");
            return;
        }
        if kind == NEUTRAL_MODEL && row_kind != "summary" {
            skip("neutral_not_summary");
            return;
        }
        if kind == SUMMARY_MODEL && !matches!(row_kind, "taint" | "value") {
            skip("unsupported_flow_kind");
            return;
        }
        let name_col = if kind == SUMMARY_MODEL { 3 } else { 2 };
        let signature = match parse_signature(row[name_col + 1].text()) {
            Ok(value) => value,
            Err(_) => {
                skip("malformed_signature");
                return;
            }
        };
        let subtypes = if kind == SUMMARY_MODEL {
            let Some(flag) = row[2].boolean() else {
                skip("malformed_subtypes");
                return;
            };
            flag
        } else {
            false
        };
        let targets = inventory.targets(
            row[0].text(),
            row[1].text(),
            row[name_col].text(),
            &signature,
            subtypes,
        );
        if targets.is_empty() {
            skip("unmatched_declaration");
            report.unmatched_declarations.push(JdkRow {
                file: file.to_owned(),
                row: ordinal,
                cells: row.iter().map(|cell| cell.text().to_owned()).collect(),
            });
            return;
        }
        let mut normalized = row.to_vec();
        let mut contents = BTreeSet::new();
        if kind == SUMMARY_MODEL {
            if !row[5].text().is_empty() {
                skip("extension_qualifier");
                return;
            }
            let is_constructor = member_name(row[1].text(), row[name_col].text()) == "<init>";
            let mut constructor_receiver_input = false;
            for column in [6, 7] {
                let mut path = match parse_access_path(row[column].text()) {
                    Ok(path) => path,
                    Err(_) => {
                        skip("malformed_access_path");
                        return;
                    }
                };
                if is_constructor
                    && column == 7
                    && path.root == MadRoot::Argument(vec![MadArgumentItem::This])
                {
                    // A constructor's Argument[this] output is its constructed value.
                    // Keep any content path components so they follow ReturnValue handling.
                    path.root = MadRoot::ReturnValue;
                }
                if is_constructor
                    && column == 6
                    && path.root == MadRoot::Argument(vec![MadArgumentItem::This])
                {
                    constructor_receiver_input = true;
                }
                for component in &path.components {
                    match component.name.as_str() {
                        "Parameter" | "ReturnValue" => {
                            skip("callback_path");
                            return;
                        }
                        "Element" | "MapKey" | "MapValue" | "ArrayElement" | "Field"
                        | "SyntheticField" => {
                            contents.insert(component.name.clone());
                        }
                        _ => {
                            skip("unsupported_access_path");
                            return;
                        }
                    }
                }
                normalized[column] = MadCell::Text(root_text(&path.root));
            }
            if constructor_receiver_input {
                // Output rewriting runs first so this constructor-specific skip
                // cannot be confused with a receiver output.
                skip("constructor_receiver_input");
                return;
            }
        }
        let mut translated = false;
        let mut row_skip_reasons = BTreeSet::new();
        for (ty, method) in targets {
            let mut concrete = normalized.clone();
            concrete[name_col + 1] = MadCell::Text(format!("({})", method.parameters.join(",")));
            let mut local = BTreeMap::new();
            let mut skips = Vec::new();
            if kind == SUMMARY_MODEL {
                translate_summary_row(file, ordinal, &concrete, &mut local, &mut skips);
            } else {
                translate_neutral_row(file, ordinal, &concrete, &mut local, &mut skips);
            }
            for foundry_skip in skips {
                row_skip_reasons.insert(foundry_skip.reason.as_str().to_owned());
                report.skips.push(foundry_skip);
            }
            for (_, builder) in local {
                let target = target(ty, method);
                let entry = builder.finish(
                    FoundryCorpus::Codeql,
                    target.clone(),
                    Some(method.parameters.len() as u32),
                );
                if !method.has_receiver
                    && entry.transfers.iter().any(|transfer| {
                        matches!(transfer.input, AuthoredSummaryInput::Receiver {})
                            || matches!(transfer.output, AuthoredSummaryOutput::Receiver {})
                    })
                {
                    row_skip_reasons.insert("receiver_on_static_method".to_owned());
                    continue;
                }
                let destination = builders.entry(target.clone()).or_default();
                if entry.transfers.is_empty() {
                    destination.declare_no_flow();
                }
                for mut transfer in entry.transfers {
                    // Collapsing content paths preserves dependency, not the
                    // object identity of their root containers.
                    if row_kind == "value"
                        && contents.is_empty()
                        && row[6].text() == "Argument[this]"
                        && row[7].text() == "ReturnValue"
                    {
                        // Identity is keyed on literal CodeQL row text. The constructor
                        // output rewrite above cannot make an Argument[this] output Identity.
                        transfer.value_transfer = Some(SummaryValueTransfer {
                            kind: SummaryValueTransferKind::Conversion {
                                preservation: SummaryValuePreservation::Identity,
                            },
                            operation: SummaryValueTransferOperation::None {},
                        });
                    }
                    destination.add_transfer(transfer);
                }
                boundaries.insert(target, method.has_receiver);
                translated = true;
            }
        }
        if !translated {
            for reason in row_skip_reasons {
                *report.skipped_by_reason.entry(reason).or_default() += 1;
            }
        }
        if translated {
            report.translated_rows += 1;
            if !contents.is_empty() && row_kind == "value" {
                report.value_rows_demoted += 1;
            }
            for content in contents {
                *report.collapsed_by_content_kind.entry(content).or_default() += 1;
            }
        }
    })?;
    let summaries = builders
        .into_iter()
        .map(|(target, builder)| {
            let has_receiver = boundaries[&target];
            let arity = target.signature.arity();
            let mut entry = builder.finish(FoundryCorpus::Codeql, target, arity);
            entry.boundary.has_receiver = has_receiver;
            if entry.notes.contains(&FoundryNote::ContradictoryCorpusRows) {
                report.targets_with_neutral_and_flow += 1;
            }
            // CodeQL indexes the declared JVM array parameter. The summary
            // schema cannot reference a variadic tail, so retain that array
            // boundary, as existing Java summaries do.
            entry.authored_complete_summary()
        })
        .collect::<Vec<_>>();
    report.expanded_targets = summaries.len();
    report.skips.sort();
    let requirement = ">=21.0.0, <22.0.0";
    let mut pack = super::super::authored_pack(
        "codeql.jdk21.summaries".to_owned(),
        "1.0.0".to_owned(),
        "bifrost-codeql-jdk".to_owned(),
        "java".to_owned(),
        "jdk".to_owned(),
        Compatibility {
            bifrost: None,
            toolchains: vec![VersionConstraint {
                name: "jdk".to_owned(),
                requirement: requirement.to_owned(),
            }],
        },
        Provenance {
            source: "https://github.com/github/codeql (MIT license)".to_owned(),
            revision: Some(commit.to_owned()),
        },
        Completeness::Complete,
        vec![AuthoredShard {
            id: "codeql.jdk21.procedure-summaries".to_owned(),
            activation: vec![ActivationSelector {
                toolchain: Some(NameSelector {
                    name: "jdk".to_owned(),
                    version: Some(requirement.to_owned()),
                }),
                targets: vec!["jvm".to_owned()],
                package: None,
                module: None,
                configurations: Vec::new(),
                artifact_sha256: None,
            }],
            payload: AuthoredPayload::ProcedureSummaries { summaries },
            runtime_values: None,
            runtime_contracts: None,
            collection_flows: None,
            deferred_yields: None,
            conditional_type_refinements: None,
            callable_values: None,
        }],
    );
    pack.license = "MIT".to_owned();
    pack.safety.review_required = false;
    Ok((pack, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use std::path::Path;

    #[test]
    #[hardwon(
        "#7550: JDK constructor summaries carried a receiver and never matched a constructor call"
    )]
    fn codeql_jdk_pack_and_report_golden() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/summary-corpora/codeql-jdk");
        let files = super::super::super::read_codeql_models(&root).unwrap();
        let declarations: Vec<JvmType> =
            serde_json::from_slice(&std::fs::read(root.join("declarations.json")).unwrap())
                .unwrap();
        let (pack, mut report) = generate_jdk_summaries(
            &files,
            &declarations,
            "c9142680f5b6409dbe0944350321c54e8c801e61",
        )
        .unwrap();
        let source = serde_json::to_string_pretty(&pack).unwrap() + "\n";
        super::super::super::compile_pack_source(&source).unwrap();
        let first = (
            source,
            serde_json::to_string_pretty(&report).unwrap() + "\n",
        );
        let mut reversed_files = files.clone();
        reversed_files.reverse();
        // Reverse the overlapping rows within a file as well as file order.
        for (name, source) in &mut reversed_files {
            if name.ends_with("identity.model.yml") {
                let text = std::str::from_utf8(source).unwrap();
                let (header, rows) = text.split_once("    data:\n").unwrap();
                let rows = rows.lines().rev().collect::<Vec<_>>().join("\n");
                *source = format!("{header}    data:\n{rows}\n").into_bytes();
            }
        }
        let (again_pack, mut again_report) = generate_jdk_summaries(
            &reversed_files,
            &declarations,
            "c9142680f5b6409dbe0944350321c54e8c801e61",
        )
        .unwrap();
        assert_eq!(
            first.0,
            serde_json::to_string_pretty(&again_pack).unwrap() + "\n"
        );
        // The report lists unmatched declarations and skips in input order;
        // every other field is a count or a sorted map. Compare the whole
        // report once those two lists are sorted.
        for report in [&mut report, &mut again_report] {
            report.unmatched_declarations.sort();
            report.skips.sort();
        }
        assert_eq!(
            serde_json::to_string_pretty(&report).unwrap(),
            serde_json::to_string_pretty(&again_report).unwrap()
        );
        let reverse_summary = pack
            .shards
            .iter()
            .find_map(|shard| {
                let AuthoredPayload::ProcedureSummaries { summaries } = &shard.payload else {
                    return None;
                };
                summaries
                    .iter()
                    .find(|summary| summary.target.symbol.ends_with(".reverse()"))
            })
            .expect("root value overlap summary");
        assert!(matches!(
            reverse_summary.transfers[0]
                .value_transfer
                .as_ref()
                .map(|value| &value.kind),
            Some(SummaryValueTransferKind::Conversion {
                preservation: SummaryValuePreservation::Identity,
            })
        ));
        let capture_root = std::env::var_os("BIFROST_GOLDEN_ACTUAL_DIR");
        let mut differences = Vec::new();
        for (name, actual) in [
            ("expected-pack.json", first.0),
            ("expected-report.json", first.1),
        ] {
            let path = root.join(name);
            if let Some(capture_root) = &capture_root {
                let directory = Path::new(capture_root).join("codeql-jdk");
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(directory.join(name), &actual).unwrap();
                continue;
            }
            if std::env::var_os("BIFROST_BLESS").is_some_and(|value| value == "1") {
                std::fs::write(&path, &actual).unwrap();
            }
            if std::fs::read_to_string(path).unwrap() != actual {
                differences.push(name);
            }
        }
        assert!(capture_root.is_none(), "BIFROST_GOLDEN_CAPTURE: codeql-jdk");
        assert!(
            differences.is_empty(),
            "JDK generator goldens differ: {differences:?}"
        );
    }
    #[test]
    fn codeql_jdk_catalogs_and_report_golden() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/summary-corpora/codeql-jdk-catalogs");
        let files = super::super::super::read_codeql_models(&root).unwrap();
        let declarations: Vec<JvmType> =
            serde_json::from_slice(&std::fs::read(root.join("declarations.json")).unwrap())
                .unwrap();
        let generate = |files: &[(String, Vec<u8>)]| {
            let (catalogs, report) = catalogs::generate_jvm_catalogs(
                files,
                &declarations,
                "ae741615f300000000000000000000000000000000",
                "jdk",
                7,
            )
            .unwrap();
            let mut document = serde_json::json!({"catalogs": catalogs, "report": report});
            document.sort_all_objects();
            serde_json::to_string_pretty(&document).unwrap() + "\n"
        };
        let actual = generate(&files);
        let mut reversed = files.clone();
        reversed.reverse();
        assert_eq!(actual, generate(&reversed));
        let expected = root.join("expected.txt");
        if std::env::var_os("BIFROST_BLESS").is_some_and(|value| value == "1") {
            std::fs::write(&expected, &actual).unwrap();
        }
        assert_eq!(std::fs::read_to_string(expected).unwrap(), actual);
    }

    #[test]
    fn codeql_servlet_catalogs_and_report_golden() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/summary-corpora/codeql-servlet-catalogs");
        let files = super::super::super::read_codeql_models(&root).unwrap();
        let declarations: Vec<JvmType> =
            serde_json::from_slice(&std::fs::read(root.join("declarations.json")).unwrap())
                .unwrap();
        let generate = |files: &[(String, Vec<u8>)]| {
            let (catalogs, report) = catalogs::generate_jvm_catalogs(
                files,
                &declarations,
                "ae741615f3e178ce61289a651790dc67fcc18e19",
                "servlet",
                1,
            )
            .unwrap();
            let mut document = serde_json::json!({"catalogs": catalogs, "report": report});
            document.sort_all_objects();
            serde_json::to_string_pretty(&document).unwrap() + "\n"
        };
        let actual = generate(&files);
        let mut reversed = files.clone();
        reversed.reverse();
        assert_eq!(actual, generate(&reversed));
        let expected = root.join("expected.txt");
        if std::env::var_os("BIFROST_BLESS").is_some_and(|value| value == "1") {
            std::fs::write(&expected, &actual).unwrap();
        }
        assert_eq!(std::fs::read_to_string(expected).unwrap(), actual);
    }
}
