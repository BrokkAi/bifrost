use super::java_artifact::{
    MAX_ARCHIVE_ENTRIES, MAX_SOURCE_ENTRY_BYTES, MAX_TOTAL_ARCHIVE_BYTES, ZipDirectoryStatus,
    zip_directory_status,
};
use crate::CancellationToken;
use crate::analyzer::common::node_source_text_trimmed;
use crate::analyzer::kotlin::declarations::{
    KotlinClassLikeKind, KotlinDeclaredVisibility, kotlin_class_like_kind,
    kotlin_declared_visibility, parse_kotlin_file,
};
use crate::analyzer::kotlin::language;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest,
    AuthoredPayload, AuthoredSemanticModelPack, AuthoredShard, BoundedProducerDiagnostics,
    Completeness, ExactArtifact, ExternalArtifactKind, ExternalArtifactPackProducer, HierarchyFact,
    HierarchyKind, Locator, MemberFact, MemberIdentity, MemberKind, Parameter, Producer,
    ProducerDiagnostic, ProducerDiagnosticSeverity, Signature, TypeFact, TypeIdentity, TypeKind,
    TypeRef, Visibility, member_declaration_id, read_exact_artifact_while, type_declaration_id,
};
use crate::analyzer::tree_sitter_analyzer::ParsedFile;
use crate::analyzer::tree_walk::{first_named_child_of_kind, named_children};
use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::HashMap;
use std::io::{Cursor, Read};
use tree_sitter::{Node, Parser, Tree};
use zip::ZipArchive;

#[derive(Debug, Clone, Copy, Default)]
pub struct KotlinSourceJarPackProducer;

impl ExternalArtifactPackProducer for KotlinSourceJarPackProducer {
    fn produce_exact_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
    ) -> ArtifactProduction {
        self.produce(request, limits, None)
    }

    fn produce_exact_artifact_with_cancellation(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        self.produce(request, limits, cancellation)
    }
}

impl KotlinSourceJarPackProducer {
    fn produce(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::KotlinSourceJar {
            return failure(
                "artifact.kind",
                "Kotlin producer requires a Kotlin source JAR artifact",
                limits,
            );
        }
        let artifact = match read_exact_artifact_while(&request.path, limits, || {
            cancellation.is_some_and(CancellationToken::is_cancelled)
        }) {
            Ok(artifact) => artifact,
            Err(diagnostic) => return ArtifactProduction::failed(diagnostic, limits),
        };
        self.produce_loaded_artifact(request, limits, cancellation, &artifact)
    }

    pub fn produce_loaded_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
    ) -> ArtifactProduction {
        if zip_directory_status(artifact.bytes()) == ZipDirectoryStatus::Exceeded {
            return failure(
                "limit.archive_directory",
                "Kotlin JAR central directory exceeds bounded entry or byte limits",
                limits,
            );
        }
        let mut archive = match ZipArchive::new(Cursor::new(artifact.bytes())) {
            Ok(archive) => archive,
            Err(_) => {
                return failure(
                    "kotlin.archive.invalid",
                    "artifact is not a readable ZIP/JAR archive",
                    limits,
                );
            }
        };
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let mut entries = Vec::new();
        let mut total_bytes = 0u64;
        let entry_limit = archive.len().min(MAX_ARCHIVE_ENTRIES);
        if archive.len() > MAX_ARCHIVE_ENTRIES {
            diagnostics.warning(
                "limit.archive_entries",
                None,
                format!("producer inspected at most {MAX_ARCHIVE_ENTRIES} archive entries"),
            );
        }
        for index in 0..entry_limit {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return cancelled(limits);
            }
            let Ok(mut entry) = archive.by_index(index) else {
                diagnostics.warning(
                    "kotlin.archive.entry",
                    None,
                    format!("could not read archive entry at index {index}"),
                );
                continue;
            };
            let name = entry.name().to_owned();
            if !name.ends_with(".kt") {
                continue;
            }
            let next_total = total_bytes.saturating_add(entry.size());
            if entry.size() > MAX_SOURCE_ENTRY_BYTES || next_total > MAX_TOTAL_ARCHIVE_BYTES {
                diagnostics.warning(
                    "limit.archive_bytes",
                    Some(name),
                    "archive entry exceeded the bounded Kotlin extraction budget",
                );
                continue;
            }
            total_bytes = next_total;
            let mut bytes = Vec::with_capacity(entry.size() as usize);
            if entry
                .by_ref()
                .take(MAX_SOURCE_ENTRY_BYTES + 1)
                .read_to_end(&mut bytes)
                .is_err()
                || bytes.len() as u64 > MAX_SOURCE_ENTRY_BYTES
            {
                diagnostics.warning(
                    "kotlin.archive.entry_read",
                    Some(name),
                    "could not read bounded archive entry bytes",
                );
                continue;
            }
            match String::from_utf8(bytes) {
                Ok(source) => entries.push((name, source)),
                Err(_) => diagnostics.warning(
                    "kotlin.source.encoding",
                    Some(name),
                    "Kotlin source entry is not valid UTF-8",
                ),
            }
        }
        entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

        let mut types = Vec::new();
        let mut members = Vec::new();
        let mut remaining = limits.max_records;
        let mut limit_hit = false;
        for (name, source) in entries {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return cancelled(limits);
            }
            let Some((tree, parsed)) = parse_entry(&name, &source, &mut diagnostics) else {
                continue;
            };
            let (mut entry_types, mut entry_members) = entry_facts(
                &name,
                &source,
                &tree,
                &parsed,
                &mut remaining,
                &mut limit_hit,
            );
            types.append(&mut entry_types);
            members.append(&mut entry_members);
        }
        if limit_hit {
            diagnostics.warning(
                "limit.records",
                None,
                format!(
                    "producer stopped after {} declaration records",
                    limits.max_records
                ),
            );
        }
        merge_types(&mut types);
        types.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        members.sort_unstable_by(|left, right| {
            (&left.owner, &left.name, &left.id).cmp(&(&right.owner, &right.name, &right.id))
        });
        members.dedup_by(|left, right| left.id == right.id);
        finish(request, artifact.sha256(), types, members, diagnostics)
    }
}

fn parse_entry(
    name: &str,
    source: &str,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Option<(Tree, ParsedFile)> {
    let mut parser = Parser::new();
    parser
        .set_language(&language::LANGUAGE.into())
        .expect("Kotlin language");
    let tree = parser.parse(source, None)?;
    if tree.root_node().has_error() {
        diagnostics.warning(
            "kotlin.source.parse",
            Some(name.to_owned()),
            format!(
                "Kotlin source entry contains malformed syntax: {}",
                tree.root_node().to_sexp()
            ),
        );
        return None;
    }
    let file = ProjectFile::new(std::env::temp_dir(), "external.kt");
    let parsed = parse_kotlin_file(&file, source, &tree);
    Some((tree, parsed))
}

fn entry_facts(
    entry: &str,
    source: &str,
    tree: &Tree,
    parsed: &ParsedFile,
    remaining: &mut usize,
    limit_hit: &mut bool,
) -> (Vec<TypeFact>, Vec<MemberFact>) {
    let parents = parent_index(parsed);
    let mut declarations = parsed.declarations().iter().collect::<Vec<_>>();
    declarations.sort_unstable_by_key(|unit| unit.fq_name());
    let mut types = Vec::new();
    let mut type_ids = HashMap::default();
    let mut type_kinds = HashMap::default();

    if !parsed.package_name.is_empty() && take_record(remaining, limit_hit) {
        types.push(package_fact(entry, &parsed.package_name));
    }
    for declaration in declarations
        .iter()
        .copied()
        .filter(|unit| unit.is_class() || parsed.type_aliases.contains(*unit))
    {
        let Some(visibility) = effective_visibility(tree, source, parsed, declaration, &parents)
        else {
            continue;
        };
        let Some(node) = declaration_node(tree, parsed, declaration) else {
            continue;
        };
        if !take_record(remaining, limit_hit) {
            break;
        }
        let name = declaration.fq_name();
        let id = type_declaration_id(TypeIdentity {
            ecosystem: "jvm",
            name: &name,
        });
        let kind = type_kind(node, parsed.type_aliases.contains(declaration));
        type_ids.insert(declaration.clone(), id.clone());
        type_kinds.insert(declaration.clone(), kind);
        types.push(TypeFact {
            id,
            name: name.clone(),
            type_kind: kind,
            visibility,
            is_abstract: kind == TypeKind::Interface,
            is_sealed: modifier_present(node, source, "sealed"),
            has_explicit_type_terms: false,
            type_parameters: type_parameters(node, source),
            type_parameter_constraints: Vec::new(),
            underlying_type: None,
            embedded_types: Vec::new(),
            hierarchy: parsed
                .raw_supertypes
                .get(declaration)
                .into_iter()
                .flatten()
                .map(|name| HierarchyFact {
                    hierarchy_kind: HierarchyKind::Extends,
                    target: named_type(name.clone()),
                    declaration_ordinal: None,
                })
                .collect(),
            aliases: Vec::new(),
            extension_surfaces: Vec::new(),
            locator: Locator::Source {
                path: entry.to_owned(),
                symbol: Some(name),
            },
        });
    }

    let package_owner = (!parsed.package_name.is_empty()).then(|| {
        type_declaration_id(TypeIdentity {
            ecosystem: "jvm",
            name: &parsed.package_name,
        })
    });
    let mut members = Vec::new();
    for declaration in declarations.into_iter().filter(|unit| {
        (unit.is_function() || unit.is_field()) && !parsed.type_aliases.contains(*unit)
    }) {
        let owner = parents.get(declaration);
        let Some(owner_id) = owner
            .and_then(|value| type_ids.get(value))
            .cloned()
            .or_else(|| package_owner.clone())
        else {
            continue;
        };
        let Some(visibility) = effective_visibility(tree, source, parsed, declaration, &parents)
        else {
            continue;
        };
        let Some(node) = declaration_node(tree, parsed, declaration) else {
            continue;
        };
        if !take_record(remaining, limit_hit) {
            break;
        }
        let constructor = declaration.is_function()
            && declaration.is_synthetic()
            && owner.is_some_and(|value| value.identifier() == declaration.identifier());
        let kind = if constructor {
            MemberKind::Constructor
        } else if declaration.is_function() {
            MemberKind::Method
        } else {
            MemberKind::Property
        };
        let owner_kind = owner
            .and_then(|value| type_kinds.get(value))
            .copied()
            .unwrap_or(TypeKind::Module);
        let is_static = !constructor && owner_kind == TypeKind::Module;
        let signature = signature(node, source, parsed, declaration);
        let parameter_types = signature
            .as_ref()
            .map(|value| {
                value
                    .parameters
                    .iter()
                    .map(|parameter| parameter.r#type.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let name = declaration.identifier().to_owned();
        let id = member_declaration_id(MemberIdentity {
            owner_id: &owner_id,
            kind,
            is_static,
            parameter_arity: signature.as_ref().map_or(0, |value| value.parameters.len()),
            name: &name,
            generic_arity: signature
                .as_ref()
                .map_or(0, |value| value.type_parameters.len()),
            parameter_types: &parameter_types,
            return_type: signature.as_ref().and_then(|value| value.returns.as_ref()),
        });
        members.push(MemberFact {
            id,
            owner: owner_id,
            name,
            member_kind: kind,
            visibility,
            is_static,
            is_abstract: owner_kind == TypeKind::Interface
                || modifier_present(node, source, "abstract"),
            is_virtual: kind == MemberKind::Method
                && !is_static
                && !modifier_present(node, source, "final"),
            signature,
            receiver: None,
            aliases: Vec::new(),
            locator: Locator::Source {
                path: entry.to_owned(),
                symbol: Some(declaration.fq_name()),
            },
        });
    }
    apply_extension_surfaces(&mut types, parsed, tree, source, &parents);
    (types, members)
}

fn package_fact(entry: &str, name: &str) -> TypeFact {
    TypeFact {
        id: type_declaration_id(TypeIdentity {
            ecosystem: "jvm",
            name,
        }),
        name: name.to_owned(),
        type_kind: TypeKind::Module,
        visibility: Visibility::Public,
        is_abstract: false,
        is_sealed: false,
        has_explicit_type_terms: false,
        type_parameters: Vec::new(),
        type_parameter_constraints: Vec::new(),
        underlying_type: None,
        embedded_types: Vec::new(),
        hierarchy: Vec::new(),
        aliases: Vec::new(),
        extension_surfaces: Vec::new(),
        locator: Locator::Source {
            path: entry.to_owned(),
            symbol: Some(name.to_owned()),
        },
    }
}

fn parent_index(parsed: &ParsedFile) -> HashMap<CodeUnit, CodeUnit> {
    let mut parents = HashMap::default();
    for (parent, children) in &parsed.children {
        for child in children {
            parents.insert(child.clone(), parent.clone());
        }
    }
    parents
}

fn declaration_node<'tree>(
    tree: &'tree Tree,
    parsed: &ParsedFile,
    declaration: &CodeUnit,
) -> Option<Node<'tree>> {
    let range = parsed.declaration_ranges(declaration).first()?;
    let mut node = tree
        .root_node()
        .descendant_for_byte_range(range.start_byte, range.end_byte)?;
    while node.start_byte() != range.start_byte || node.end_byte() != range.end_byte {
        node = node.parent()?;
    }
    Some(node)
}

fn effective_visibility(
    tree: &Tree,
    source: &str,
    parsed: &ParsedFile,
    declaration: &CodeUnit,
    parents: &HashMap<CodeUnit, CodeUnit>,
) -> Option<Visibility> {
    let mut visibility = Visibility::Public;
    let mut current = Some(declaration);
    while let Some(candidate) = current {
        match kotlin_declared_visibility(declaration_node(tree, parsed, candidate)?, source) {
            KotlinDeclaredVisibility::Public => {}
            KotlinDeclaredVisibility::Protected => visibility = Visibility::Protected,
            KotlinDeclaredVisibility::Internal | KotlinDeclaredVisibility::Private => return None,
        }
        current = parents.get(candidate);
    }
    Some(visibility)
}

fn type_kind(node: Node<'_>, alias: bool) -> TypeKind {
    if alias {
        return TypeKind::TypeAlias;
    }
    match kotlin_class_like_kind(node).expect("class-like declaration") {
        KotlinClassLikeKind::Class => TypeKind::Class,
        KotlinClassLikeKind::Interface => TypeKind::Interface,
        KotlinClassLikeKind::Enum => TypeKind::Enum,
        KotlinClassLikeKind::Annotation => TypeKind::Annotation,
        KotlinClassLikeKind::Object => TypeKind::Module,
    }
}

fn signature(
    node: Node<'_>,
    source: &str,
    parsed: &ParsedFile,
    declaration: &CodeUnit,
) -> Option<Signature> {
    let metadata = parsed.signature_metadata.get(declaration)?.first();
    let parameters = metadata
        .into_iter()
        .flat_map(|value| value.parameters())
        .filter_map(|parameter| {
            let parameter_node = exact_node(node, parameter.start_byte(), parameter.end_byte())?;
            let name = first_descendant(parameter_node, "simple_identifier")
                .map(|value| node_source_text_trimmed(value, source).to_owned());
            Some(Parameter {
                name,
                r#type: first_type_descendant(parameter_node)
                    .map_or_else(any_type, |value| type_ref(value, source)),
                optional: false,
                variadic: modifier_present(parameter_node, source, "vararg"),
            })
        })
        .collect();
    Some(Signature {
        type_parameters: type_parameters(node, source),
        parameters,
        returns: direct_return_type(node).map(|value| type_ref(value, source)),
    })
}

const TYPE_KINDS: &[&str] = &[
    "user_type",
    "nullable_type",
    "not_nullable_type",
    "function_type",
    "parenthesized_type",
];

fn exact_node(node: Node<'_>, start: usize, end: usize) -> Option<Node<'_>> {
    let mut found = node.descendant_for_byte_range(start, end)?;
    while found.start_byte() != start || found.end_byte() != end {
        found = found.parent()?;
    }
    Some(found)
}

fn first_type_descendant(node: Node<'_>) -> Option<Node<'_>> {
    let mut stack = named_children(node);
    while let Some(found) = stack.pop() {
        if TYPE_KINDS.contains(&found.kind()) {
            return Some(found);
        }
        stack.extend(named_children(found));
    }
    None
}

fn direct_return_type(node: Node<'_>) -> Option<Node<'_>> {
    let end = first_named_child_of_kind(node, "function_value_parameters")
        .map_or(node.start_byte(), |value| value.end_byte());
    named_children(node)
        .into_iter()
        .find(|child| child.start_byte() >= end && TYPE_KINDS.contains(&child.kind()))
}

fn type_ref(node: Node<'_>, source: &str) -> TypeRef {
    if node.kind() == "nullable_type"
        && let Some(inner) = named_children(node)
            .into_iter()
            .find(|child| TYPE_KINDS.contains(&child.kind()))
    {
        return nullable(type_ref(inner, source));
    }
    if matches!(node.kind(), "not_nullable_type" | "parenthesized_type")
        && let Some(inner) = named_children(node)
            .into_iter()
            .find(|child| TYPE_KINDS.contains(&child.kind()))
    {
        return type_ref(inner, source);
    }
    named_type(node_source_text_trimmed(node, source).to_owned())
}

fn named_type(name: String) -> TypeRef {
    TypeRef::Named {
        name,
        arguments: Vec::new(),
        nullable: false,
    }
}
fn any_type() -> TypeRef {
    named_type("kotlin.Any".to_owned())
}
fn nullable(value: TypeRef) -> TypeRef {
    match value {
        TypeRef::Named {
            name, arguments, ..
        } => TypeRef::Named {
            name,
            arguments,
            nullable: true,
        },
        TypeRef::Declared { id, arguments, .. } => TypeRef::Declared {
            id,
            arguments,
            nullable: true,
        },
        other => other,
    }
}

fn type_parameters(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = first_named_child_of_kind(node, "type_parameters") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut stack = vec![parameters];
    while let Some(found) = stack.pop() {
        if found.kind() == "type_identifier" {
            names.push(node_source_text_trimmed(found, source).to_owned());
        } else {
            stack.extend(named_children(found));
        }
    }
    names.sort();
    names.dedup();
    names
}

fn modifier_present(node: Node<'_>, source: &str, expected: &str) -> bool {
    let Some(modifiers) = first_named_child_of_kind(node, "modifiers") else {
        return false;
    };
    let mut stack = vec![modifiers];
    while let Some(found) = stack.pop() {
        if node_source_text_trimmed(found, source) == expected {
            return true;
        }
        stack.extend(named_children(found));
    }
    false
}

fn first_descendant<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut stack = vec![node];
    while let Some(found) = stack.pop() {
        if found.kind() == kind {
            return Some(found);
        }
        stack.extend(named_children(found));
    }
    None
}

fn apply_extension_surfaces(
    types: &mut [TypeFact],
    parsed: &ParsedFile,
    tree: &Tree,
    source: &str,
    parents: &HashMap<CodeUnit, CodeUnit>,
) {
    let ids = types
        .iter()
        .map(|fact| (fact.name.clone(), fact.id.clone()))
        .collect::<HashMap<_, _>>();
    let mut surfaces: HashMap<String, Vec<String>> = HashMap::default();
    for declaration in parsed
        .declarations()
        .iter()
        .filter(|unit| unit.is_function() || unit.is_field())
    {
        let Some(metadata) = parsed
            .signature_metadata
            .get(declaration)
            .and_then(|values| values.first())
        else {
            continue;
        };
        let Some(receiver) = metadata.extension_receiver_type() else {
            continue;
        };
        let owner_name = parents
            .get(declaration)
            .map(CodeUnit::fq_name)
            .unwrap_or_else(|| parsed.package_name.clone());
        let Some(owner_id) = ids.get(&owner_name) else {
            continue;
        };
        let receiver = declaration_node(tree, parsed, declaration)
            .and_then(|node| node.child_by_field_name("receiver"))
            .map(|node| node_source_text_trimmed(node, source).to_owned())
            .unwrap_or_else(|| receiver.to_owned());
        surfaces.entry(owner_id.clone()).or_default().push(receiver);
    }
    for fact in types {
        if let Some(mut values) = surfaces.remove(&fact.id) {
            values.sort_unstable();
            values.dedup();
            fact.extension_surfaces = values;
        }
    }
}

fn merge_types(types: &mut Vec<TypeFact>) {
    types.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    let mut merged: Vec<TypeFact> = Vec::with_capacity(types.len());
    for mut fact in types.drain(..) {
        if let Some(previous) = merged.last_mut()
            && previous.name == fact.name
            && previous.type_kind == fact.type_kind
        {
            previous
                .extension_surfaces
                .append(&mut fact.extension_surfaces);
            previous.extension_surfaces.sort_unstable();
            previous.extension_surfaces.dedup();
        } else {
            merged.push(fact);
        }
    }
    *types = merged;
}

fn take_record(remaining: &mut usize, hit: &mut bool) -> bool {
    if *remaining == 0 {
        *hit = true;
        false
    } else {
        *remaining -= 1;
        true
    }
}

fn failure(code: &str, message: &str, limits: &ArtifactProducerLimits) -> ArtifactProduction {
    ArtifactProduction::failed(
        ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: code.to_owned(),
            location: None,
            message: message.to_owned(),
        },
        limits,
    )
}

fn cancelled(limits: &ArtifactProducerLimits) -> ArtifactProduction {
    failure(
        "artifact.cancelled",
        "Kotlin archive production was cancelled",
        limits,
    )
}

fn finish(
    request: &ArtifactProductionRequest,
    digest: &str,
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
    mut bounded: BoundedProducerDiagnostics,
) -> ArtifactProduction {
    if types.is_empty() {
        bounded.error(
            "kotlin.archive.no_external_declarations",
            None,
            "JAR contains no externally visible Kotlin declarations",
        );
        let (diagnostics, suppressed_diagnostics) = bounded.finish();
        return ArtifactProduction {
            artifact_sha256: Some(digest.to_owned()),
            pack: None,
            completeness: Completeness::Partial,
            diagnostics,
            suppressed_diagnostics,
        };
    }
    let mut activation: Vec<ActivationSelector> = request.activation.clone();
    for selector in &mut activation {
        selector.artifact_sha256 = Some(digest.to_owned());
    }
    let (diagnostics, suppressed_diagnostics) = bounded.finish();
    let completeness = if diagnostics.is_empty() && suppressed_diagnostics == 0 {
        Completeness::Complete
    } else {
        Completeness::Partial
    };
    ArtifactProduction {
        artifact_sha256: Some(digest.to_owned()),
        pack: Some(AuthoredSemanticModelPack {
            schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
            pack_id: request.pack_id.clone(),
            version: request.pack_version.clone(),
            producer: Producer {
                name: "bifrost-kotlin-source-jar".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            language: "kotlin".to_owned(),
            ecosystem: request.ecosystem.clone(),
            compatibility: request.compatibility.clone(),
            provenance: request.provenance.clone(),
            license: request.license.clone(),
            completeness,
            safety: request.safety.clone(),
            shards: vec![AuthoredShard {
                id: "declarations.kotlin.external".to_owned(),
                activation,
                payload: AuthoredPayload::DeclarationFacts {
                    types,
                    members,
                    relations: Vec::new(),
                },
            }],
        }),
        completeness,
        diagnostics,
        suppressed_diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        Compatibility, CompilerOptions, NameSelector, Provenance, Safety, compile_pack,
    };
    use std::fs::File;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    const SOURCE: &str = r#"package kotlin.example
interface Contract
class Dependency<T>(val value: T) : Contract {
    fun relay(input: String): String = input
    companion object {
        fun create(): Dependency<String> = TODO()
    }
}
object Registry {
    val name: String = "registry"
}
fun topLevelHelper(value: String): String = value
fun String.relay(times: Int): String = repeat(times)
private fun hidden(): Unit = Unit
"#;

    #[test]
    fn produces_source_level_kotlin_api() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("dependency-sources.jar");
        write_zip(&archive, &[("kotlin/example/Dependency.kt", SOURCE)]);
        let production = KotlinSourceJarPackProducer
            .produce_exact_artifact(&request(archive), &ArtifactProducerLimits::default());
        assert!(
            production.diagnostics.is_empty(),
            "{:#?}",
            production.diagnostics
        );
        let pack = production.pack.as_ref().unwrap();
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload
        else {
            panic!("declarations")
        };
        assert!(
            types
                .iter()
                .any(|fact| fact.name == "kotlin.example.Dependency")
        );
        assert!(
            types
                .iter()
                .any(|fact| fact.name == "kotlin.example.Dependency.Companion")
        );
        assert!(members.iter().any(|fact| fact.name == "topLevelHelper"));
        assert!(members.iter().any(|fact| fact.name == "relay"));
        assert!(!members.iter().any(|fact| fact.name == "hidden"));
        assert!(!types.iter().any(|fact| fact.name.contains("Kt")));
        compile_pack(pack, &CompilerOptions::default()).unwrap();
    }

    #[test]
    fn deterministic_across_archive_order_and_path() {
        let root = tempfile::tempdir().unwrap();
        let first_path = root.path().join("first.jar");
        let second_path = root.path().join("second.jar");
        write_zip(
            &first_path,
            &[
                ("b/B.kt", "package b\nclass B"),
                ("a/A.kt", "package a\nclass A"),
            ],
        );
        std::fs::copy(&first_path, &second_path).unwrap();
        let first = KotlinSourceJarPackProducer
            .produce_exact_artifact(&request(first_path), &ArtifactProducerLimits::default());
        let second = KotlinSourceJarPackProducer
            .produce_exact_artifact(&request(second_path), &ArtifactProducerLimits::default());
        let first =
            compile_pack(first.pack.as_ref().unwrap(), &CompilerOptions::default()).unwrap();
        let second =
            compile_pack(second.pack.as_ref().unwrap(), &CompilerOptions::default()).unwrap();
        assert_eq!(first.manifest, second.manifest);
        assert_eq!(first.shards, second.shards);
    }

    fn request(path: std::path::PathBuf) -> ArtifactProductionRequest {
        ArtifactProductionRequest {
            path,
            artifact_kind: ExternalArtifactKind::KotlinSourceJar,
            pack_id: "kotlin-fixture".to_owned(),
            pack_version: "2.2.0".to_owned(),
            ecosystem: "maven".to_owned(),
            compatibility: Compatibility {
                bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                toolchains: vec![crate::analyzer::semantic_model::VersionConstraint {
                    name: "kotlin".to_owned(),
                    requirement: "=2.2.0".to_owned(),
                }],
            },
            activation: vec![ActivationSelector {
                package: Some(NameSelector {
                    name: "example:kotlin-library".to_owned(),
                    version: Some("=2.2.0".to_owned()),
                }),
                module: None,
                toolchain: Some(NameSelector {
                    name: "kotlin".to_owned(),
                    version: Some("=2.2.0".to_owned()),
                }),
                targets: vec!["jvm".to_owned()],
                configurations: Vec::new(),
                artifact_sha256: None,
            }],
            provenance: Provenance {
                source: "test".to_owned(),
                revision: Some("2.2.0".to_owned()),
            },
            license: "Apache-2.0".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
        }
    }

    fn write_zip(path: &std::path::Path, entries: &[(&str, &str)]) {
        let mut writer = zip::ZipWriter::new(File::create(path).unwrap());
        for (name, source) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(source.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
    }
}
