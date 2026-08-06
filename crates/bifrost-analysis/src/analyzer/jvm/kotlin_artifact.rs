use super::java_artifact::{
    MAX_ARCHIVE_ENTRIES, MAX_SOURCE_ENTRY_BYTES, MAX_TOTAL_ARCHIVE_BYTES, ZipDirectoryStatus,
    zip_directory_status,
};
use crate::CancellationToken;
use crate::analyzer::common::node_source_text_trimmed;
use crate::analyzer::kotlin::language;
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest,
    AuthoredPayload, AuthoredSemanticModelPack, AuthoredShard, BoundedProducerDiagnostics,
    Completeness, ExactArtifact, ExternalArtifactKind, ExternalArtifactPackProducer, HierarchyFact,
    HierarchyKind, Locator, MemberFact, MemberIdentity, MemberKind, Parameter, Producer,
    ProducerDiagnostic, ProducerDiagnosticSeverity, Signature, StructuredTypeExpression, TypeFact,
    TypeIdentity, TypeKind, TypeRef, Visibility, member_declaration_id, read_exact_artifact_while,
    type_declaration_id,
};
use crate::analyzer::tree_sitter_analyzer::ParsedFile;
use crate::analyzer::tree_walk::{first_named_child_of_kind, named_children};
use crate::analyzer::{CodeUnit, ProjectFile, SignatureMetadata};
use crate::hash::HashMap;
use brokk_bifrost_jvm::kotlin::declarations::{
    KotlinClassLikeKind, KotlinDeclaredVisibility, kotlin_class_like_kind,
    kotlin_declared_visibility, parse_kotlin_file,
};
use brokk_bifrost_jvm::kotlin::imports::KOTLIN_DEFAULT_IMPORT_PACKAGES;
use brokk_bifrost_jvm::kotlin::syntax::{kotlin_type_spelling, kotlin_user_type_segments};
use std::io::{Cursor, Read};
use tree_sitter::{Node, Parser, Tree};
use zip::ZipArchive;

const KOTLIN_PACKAGE_MARKER: &str = "bifrost:kotlin-package";
const MAX_LOCATOR_PATH_BYTES: usize = 1_024;
const MAX_QUALIFIED_NAME_BYTES: usize = 1_024;
const MAX_NESTED_NAME_CANDIDATES: usize = 64;

#[derive(Default)]
struct KnownTypes {
    exact: crate::hash::HashSet<String>,
    by_simple_name: HashMap<String, Vec<String>>,
}

impl KnownTypes {
    fn insert(&mut self, name: String) {
        if !self.exact.insert(name.clone()) {
            return;
        }
        let simple = name.rsplit('.').next().unwrap_or(&name).to_owned();
        let candidates = self.by_simple_name.entry(simple).or_default();
        if candidates.len() <= MAX_NESTED_NAME_CANDIDATES {
            candidates.push(name);
        }
    }

    fn contains(&self, name: &str) -> bool {
        self.exact.contains(name)
    }

    fn nested_candidates(&self, name: &str) -> &[String] {
        let simple = name.rsplit('.').next().unwrap_or(name);
        self.by_simple_name
            .get(simple)
            .filter(|values| values.len() <= MAX_NESTED_NAME_CANDIDATES)
            .map_or(&[], Vec::as_slice)
    }
}

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
        match zip_directory_status(artifact.bytes()) {
            ZipDirectoryStatus::Valid => {}
            ZipDirectoryStatus::Exceeded => {
                return failure(
                    "limit.archive_directory",
                    "Kotlin JAR central directory exceeds bounded entry or byte limits",
                    limits,
                );
            }
            ZipDirectoryStatus::Invalid => {
                return failure(
                    "kotlin.archive.invalid",
                    "artifact has an invalid ZIP/JAR central directory",
                    limits,
                );
            }
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
            if name.len() > MAX_LOCATOR_PATH_BYTES {
                diagnostics.warning(
                    "limit.locator_path",
                    None,
                    "Kotlin source entry path exceeded the locator length limit",
                );
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

        if limits.max_records == 0 {
            diagnostics.warning(
                "limit.records",
                None,
                "producer record limit is zero; no Kotlin sources were parsed",
            );
            return finish(
                request,
                artifact.sha256(),
                Vec::new(),
                Vec::new(),
                diagnostics,
            );
        }

        let mut known_types = KnownTypes::default();
        let mut inventoried_records = 0usize;
        let mut inventoried_entries = 0usize;
        let mut inventory_diagnostics = BoundedProducerDiagnostics::new(limits);
        for (name, source) in &entries {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return cancelled(limits);
            }
            inventoried_entries += 1;
            let Some((_, parsed)) = parse_entry(name, source, &mut inventory_diagnostics) else {
                continue;
            };
            let available = limits.max_records.saturating_sub(inventoried_records);
            for name in parsed
                .declarations()
                .iter()
                .filter(|unit| unit.is_class() || parsed.type_aliases.contains(*unit))
                .map(CodeUnit::fq_name)
                .filter(|name| name.len() <= MAX_QUALIFIED_NAME_BYTES)
                .take(available)
            {
                known_types.insert(name);
            }
            let records = parsed
                .declarations()
                .len()
                .saturating_add(usize::from(!parsed.package_name.is_empty()));
            inventoried_records = inventoried_records
                .saturating_add(records)
                .min(limits.max_records);
            if inventoried_records == limits.max_records {
                break;
            }
        }
        let mut types = Vec::new();
        let mut members = Vec::new();
        let mut remaining = limits.max_records;
        let mut limit_hit = false;
        let mut signature_limit_hit = false;
        if inventoried_entries < entries.len() {
            limit_hit = true;
        }
        for (name, source) in entries.into_iter().take(inventoried_entries) {
            if remaining == 0 {
                limit_hit = true;
                break;
            }
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
                &known_types,
                limits.max_signature_depth,
                &mut signature_limit_hit,
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
        if signature_limit_hit {
            diagnostics.warning(
                "limit.signature_depth",
                None,
                format!(
                    "Kotlin structured signatures exceeded depth {} and were truncated",
                    limits.max_signature_depth
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
            "Kotlin source entry contains syntax unsupported by the pinned parser",
        );
        return None;
    }
    if !source_shape_within_limits(tree.root_node(), source) {
        diagnostics.warning(
            "kotlin.source.name_limit",
            Some(name.to_owned()),
            format!(
                "Kotlin package, import, or declaration name exceeds {MAX_QUALIFIED_NAME_BYTES} bytes"
            ),
        );
        return None;
    }
    let file = ProjectFile::new(std::env::temp_dir(), "external.kt");
    let parsed = parse_kotlin_file(&file, source, &tree);
    Some((tree, parsed))
}

fn source_shape_within_limits(root: Node<'_>, source: &str) -> bool {
    let package_bytes = named_children(root)
        .into_iter()
        .find(|child| child.kind() == "package_header")
        .and_then(|header| first_named_descendant_of_kind(header, "identifier"))
        .map_or(0, |identifier| {
            node_source_text_trimmed(identifier, source).len()
        });
    if package_bytes > MAX_QUALIFIED_NAME_BYTES {
        return false;
    }
    if named_children(root)
        .into_iter()
        .filter(|child| child.kind() == "import_list")
        .flat_map(named_children)
        .filter(|child| child.kind() == "import_header")
        .any(|import| node_source_text_trimmed(import, source).len() > MAX_QUALIFIED_NAME_BYTES)
    {
        return false;
    }
    let mut stack = named_children(root)
        .into_iter()
        .map(|node| (node, package_bytes))
        .collect::<Vec<_>>();
    while let Some((node, owner_bytes)) = stack.pop() {
        let declaration = matches!(
            node.kind(),
            "class_declaration"
                | "object_declaration"
                | "companion_object"
                | "type_alias"
                | "function_declaration"
                | "property_declaration"
        );
        let name_bytes = if node.kind() == "companion_object" {
            node.child_by_field_name("name")
                .map_or("Companion".len(), |name| {
                    node_source_text_trimmed(name, source).len()
                })
        } else if declaration {
            node.child_by_field_name("name")
                .or_else(|| first_named_child_of_kind(node, "type_identifier"))
                .or_else(|| first_named_child_of_kind(node, "simple_identifier"))
                .map_or(0, |name| node_source_text_trimmed(name, source).len())
        } else {
            0
        };
        let qualified_bytes = owner_bytes
            .saturating_add(usize::from(owner_bytes != 0 && name_bytes != 0))
            .saturating_add(name_bytes);
        if qualified_bytes > MAX_QUALIFIED_NAME_BYTES {
            return false;
        }
        let nested_owner = if matches!(
            node.kind(),
            "class_declaration" | "object_declaration" | "companion_object"
        ) {
            qualified_bytes
        } else {
            owner_bytes
        };
        stack.extend(
            named_children(node)
                .into_iter()
                .map(|child| (child, nested_owner)),
        );
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn entry_facts(
    entry: &str,
    source: &str,
    tree: &Tree,
    parsed: &ParsedFile,
    known_types: &KnownTypes,
    max_signature_depth: usize,
    signature_limit_hit: &mut bool,
    remaining: &mut usize,
    limit_hit: &mut bool,
) -> (Vec<TypeFact>, Vec<MemberFact>) {
    let parents = parent_index(parsed);
    let mut declarations = parsed.declarations().iter().collect::<Vec<_>>();
    declarations.sort_unstable_by_key(|unit| unit.fq_name());
    let mut types = Vec::new();
    let mut type_ids = HashMap::default();
    let mut type_kinds = HashMap::default();

    if !parsed.package_name.is_empty()
        && parsed.package_name.len() <= MAX_QUALIFIED_NAME_BYTES
        && take_record(remaining, limit_hit)
    {
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
        if name.len() > MAX_QUALIFIED_NAME_BYTES {
            continue;
        }
        let id = type_declaration_id(TypeIdentity {
            ecosystem: "jvm",
            name: &name,
        });
        let kind = type_kind(node, parsed.type_aliases.contains(declaration));
        type_ids.insert(declaration.clone(), id.clone());
        type_kinds.insert(declaration.clone(), kind);
        let hierarchy_owners = lexical_type_owners(
            node,
            source,
            &parsed.package_name,
            max_signature_depth,
            signature_limit_hit,
        );
        types.push(TypeFact {
            id,
            name: name.clone(),
            type_kind: kind,
            visibility,
            is_abstract: kind == TypeKind::Interface || modifier_present(node, source, "abstract"),
            is_sealed: modifier_present(node, source, "sealed"),
            has_explicit_type_terms: false,
            type_parameters: type_parameters(node, source),
            type_parameter_constraints: Vec::new(),
            underlying_type: (kind == TypeKind::TypeAlias)
                .then(|| {
                    direct_alias_type(node).map(|value| StructuredTypeExpression {
                        display: bounded_text(node_source_text_trimmed(value, source)),
                        referenced_types: vec![qualified_type_ref(
                            value,
                            source,
                            parsed,
                            known_types,
                            max_signature_depth,
                            signature_limit_hit,
                        )],
                    })
                })
                .flatten(),
            embedded_types: Vec::new(),
            hierarchy: parsed
                .raw_supertypes
                .get(declaration)
                .into_iter()
                .flatten()
                .filter_map(|name| {
                    qualified_type_name(name, parsed, known_types, &hierarchy_owners)
                })
                .map(|name| HierarchyFact {
                    hierarchy_kind: HierarchyKind::Extends,
                    target: named_type(name),
                    declaration_ordinal: None,
                })
                .collect(),
            aliases: Vec::new(),
            extension_surfaces: Vec::new(),
            locator: Locator::Source {
                path: entry.to_owned(),
                symbol: None,
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
    let mut cached_lexical_owners: Option<(usize, Vec<String>)> = None;
    for declaration in declarations.into_iter().filter(|unit| {
        (unit.is_function() || unit.is_field()) && !parsed.type_aliases.contains(*unit)
    }) {
        if *remaining == 0 {
            *limit_hit = true;
            break;
        }
        if declaration.fq_name().len() > MAX_QUALIFIED_NAME_BYTES {
            continue;
        }
        let owner = parents.get(declaration);
        let Some(owner_id) = owner
            .and_then(|value| type_ids.get(value))
            .cloned()
            .or_else(|| package_owner.clone())
        else {
            continue;
        };
        let constructor = declaration.is_function()
            && declaration.is_synthetic()
            && owner.is_some_and(|value| value.identifier() == declaration.identifier());
        let kind = if constructor {
            MemberKind::Constructor
        } else if declaration.is_function() && owner.is_none() {
            MemberKind::Function
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
        let name = declaration.identifier().to_owned();
        let ranges = parsed.declaration_ranges(declaration);
        let metadata = parsed.signature_metadata.get(declaration);
        for (ordinal, range) in ranges.iter().enumerate() {
            let Some(node) = exact_node(tree.root_node(), range.start_byte, range.end_byte) else {
                continue;
            };
            let Some(visibility) =
                effective_member_visibility(tree, source, parsed, declaration, node, &parents)
            else {
                continue;
            };
            if !take_record(remaining, limit_hit) {
                break;
            }
            let lexical_owner_key = nearest_type_owner_id(node).unwrap_or(0);
            if cached_lexical_owners
                .as_ref()
                .is_none_or(|(key, _)| *key != lexical_owner_key)
            {
                cached_lexical_owners = Some((
                    lexical_owner_key,
                    lexical_type_owners(
                        node,
                        source,
                        &parsed.package_name,
                        max_signature_depth,
                        signature_limit_hit,
                    ),
                ));
            }
            let lexical_owners = &cached_lexical_owners
                .as_ref()
                .expect("lexical owners initialized")
                .1;
            let signature = signature(
                node,
                source,
                parsed,
                metadata.and_then(|values| values.get(ordinal)),
                known_types,
                lexical_owners,
                max_signature_depth,
                signature_limit_hit,
            );
            let declaration_type_parameters = type_parameters(node, source);
            let extension_receiver = node.child_by_field_name("receiver").map(|receiver| {
                qualified_type_ref_with_parameters_in_scope(
                    receiver,
                    source,
                    parsed,
                    known_types,
                    &declaration_type_parameters,
                    lexical_owners,
                    max_signature_depth,
                    signature_limit_hit,
                )
            });
            let extension_receiver_constraints = extension_receiver
                .as_ref()
                .map(|receiver| {
                    extension_receiver_constraints(
                        receiver,
                        node,
                        source,
                        parsed,
                        known_types,
                        &declaration_type_parameters,
                        lexical_owners,
                        max_signature_depth,
                        signature_limit_hit,
                    )
                })
                .unwrap_or_default();
            let mut identity_types = extension_receiver.iter().cloned().collect::<Vec<_>>();
            identity_types.extend(extension_receiver_constraints.iter().cloned());
            identity_types.extend(signature.as_ref().into_iter().flat_map(|value| {
                value
                    .parameters
                    .iter()
                    .map(|parameter| parameter.r#type.clone())
            }));
            let has_body = first_named_child_of_kind(node, "function_body").is_some();
            let explicitly_final = modifier_present(node, source, "final");
            let explicitly_virtual = !explicitly_final
                && (owner_kind == TypeKind::Interface
                    || modifier_present(node, source, "open")
                    || modifier_present(node, source, "override")
                    || modifier_present(node, source, "abstract"));
            let is_abstract = modifier_present(node, source, "abstract")
                || (owner_kind == TypeKind::Interface && !has_body);
            let id = member_declaration_id(MemberIdentity {
                owner_id: &owner_id,
                kind,
                is_static,
                parameter_arity: signature.as_ref().map_or(0, |value| value.parameters.len()),
                name: &name,
                generic_arity: signature
                    .as_ref()
                    .map_or(0, |value| value.type_parameters.len()),
                parameter_types: &identity_types,
                parameter_variadics: &[],
                return_type: signature.as_ref().and_then(|value| value.returns.as_ref()),
            });
            members.push(MemberFact {
                id,
                owner: owner_id.clone(),
                name: name.clone(),
                member_kind: kind,
                visibility,
                is_static,
                is_abstract,
                is_virtual: kind == MemberKind::Method && !is_static && explicitly_virtual,
                signature,
                receiver: None,
                extension_receiver,
                extension_receiver_constraints,
                aliases: Vec::new(),
                locator: Locator::Source {
                    path: entry.to_owned(),
                    symbol: None,
                },
            });
        }
    }
    apply_extension_surfaces(&mut types, parsed, tree, source, &parents, known_types);
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
        aliases: vec![KOTLIN_PACKAGE_MARKER.to_owned()],
        extension_surfaces: Vec::new(),
        locator: Locator::Source {
            path: entry.to_owned(),
            symbol: None,
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

fn effective_member_visibility(
    tree: &Tree,
    source: &str,
    parsed: &ParsedFile,
    declaration: &CodeUnit,
    node: Node<'_>,
    parents: &HashMap<CodeUnit, CodeUnit>,
) -> Option<Visibility> {
    let mut visibility = match kotlin_declared_visibility(node, source) {
        KotlinDeclaredVisibility::Public => Visibility::Public,
        KotlinDeclaredVisibility::Protected => Visibility::Protected,
        KotlinDeclaredVisibility::Internal | KotlinDeclaredVisibility::Private => return None,
    };
    let mut current = parents.get(declaration);
    while let Some(owner) = current {
        match kotlin_declared_visibility(declaration_node(tree, parsed, owner)?, source) {
            KotlinDeclaredVisibility::Public => {}
            KotlinDeclaredVisibility::Protected => visibility = Visibility::Protected,
            KotlinDeclaredVisibility::Internal | KotlinDeclaredVisibility::Private => return None,
        }
        current = parents.get(owner);
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

#[allow(clippy::too_many_arguments)]
fn signature(
    node: Node<'_>,
    source: &str,
    parsed: &ParsedFile,
    metadata: Option<&SignatureMetadata>,
    known_types: &KnownTypes,
    lexical_owners: &[String],
    max_depth: usize,
    depth_limit_hit: &mut bool,
) -> Option<Signature> {
    let type_parameters = type_parameters(node, source);
    let parameters = metadata
        .into_iter()
        .flat_map(|value| value.parameters())
        .filter_map(|parameter| {
            let parameter_node = exact_node(node, parameter.start_byte(), parameter.end_byte())?;
            let name = first_named_child_of_kind(parameter_node, "simple_identifier")
                .map(|value| node_source_text_trimmed(value, source))
                .filter(|value| value.len() <= MAX_QUALIFIED_NAME_BYTES)
                .map(str::to_owned);
            Some(Parameter {
                name,
                r#type: first_type_descendant(parameter_node).map_or_else(any_type, |value| {
                    qualified_type_ref_with_parameters_in_scope(
                        value,
                        source,
                        parsed,
                        known_types,
                        &type_parameters,
                        lexical_owners,
                        max_depth,
                        depth_limit_hit,
                    )
                }),
                optional: parameter_is_optional(parameter_node),
                variadic: parameter_is_variadic(parameter_node, source),
            })
        })
        .collect();
    Some(Signature {
        type_parameters: type_parameters.clone(),
        parameters,
        returns: direct_return_type(node).map(|value| {
            qualified_type_ref_with_parameters_in_scope(
                value,
                source,
                parsed,
                known_types,
                &type_parameters,
                lexical_owners,
                max_depth,
                depth_limit_hit,
            )
        }),
    })
}

fn direct_alias_type(node: Node<'_>) -> Option<Node<'_>> {
    named_children(node)
        .into_iter()
        .find(|child| TYPE_KINDS.contains(&child.kind()))
}

fn parameter_is_optional(parameter: Node<'_>) -> bool {
    if parameter.kind() == "class_parameter" {
        let mut cursor = parameter.walk();
        return parameter
            .children(&mut cursor)
            .any(|child| child.kind() == "=");
    }
    let Some(list) = parameter.parent() else {
        return false;
    };
    let mut selected = false;
    for child in list.children(&mut list.walk()) {
        if child.id() == parameter.id() {
            selected = true;
        } else if selected && child.kind() == "=" {
            return true;
        } else if selected && child.is_named() && child.kind() == "parameter" {
            return false;
        }
    }
    false
}

fn parameter_is_variadic(parameter: Node<'_>, source: &str) -> bool {
    if modifier_present(parameter, source, "vararg") {
        return true;
    }
    let Some(list) = parameter.parent() else {
        return false;
    };
    let mut pending_vararg = false;
    for child in list.children(&mut list.walk()) {
        if child.id() == parameter.id() {
            return pending_vararg;
        }
        if child.is_named() && child.kind() == "parameter_modifiers" {
            pending_vararg = node_source_text_trimmed(child, source) == "vararg"
                || named_children(child)
                    .into_iter()
                    .any(|modifier| node_source_text_trimmed(modifier, source) == "vararg");
        } else if child.is_named() && child.kind() == "parameter" {
            pending_vararg = false;
        }
    }
    false
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

fn type_ref_with_parameters(
    node: Node<'_>,
    source: &str,
    type_parameters: &[String],
    remaining_depth: usize,
    depth_limit_hit: &mut bool,
) -> TypeRef {
    if remaining_depth == 0 {
        *depth_limit_hit = true;
        return any_type();
    }
    let next_depth = remaining_depth - 1;
    let value = match node.kind() {
        "nullable_type" | "not_nullable_type" | "parenthesized_type" | "receiver_type" => {
            named_children(node)
                .into_iter()
                .find(|child| TYPE_KINDS.contains(&child.kind()))
                .map_or_else(any_type, |child| {
                    type_ref_with_parameters(
                        child,
                        source,
                        type_parameters,
                        next_depth,
                        depth_limit_hit,
                    )
                })
        }
        "user_type" => {
            let name = kotlin_user_type_segments(node)
                .into_iter()
                .map(|segment| node_source_text_trimmed(segment, source))
                .collect::<Vec<_>>()
                .join(".");
            if type_parameters.iter().any(|parameter| parameter == &name) {
                TypeRef::TypeParameter { name }
            } else {
                let arguments = first_named_child_of_kind(node, "type_arguments")
                    .into_iter()
                    .flat_map(named_children)
                    .filter(|projection| projection.kind() == "type_projection")
                    .map(|projection| {
                        first_type_descendant(projection).map_or_else(any_type, |argument| {
                            type_ref_with_parameters(
                                argument,
                                source,
                                type_parameters,
                                next_depth,
                                depth_limit_hit,
                            )
                        })
                    })
                    .collect();
                TypeRef::Named {
                    name,
                    arguments,
                    nullable: false,
                }
            }
        }
        "function_type" => {
            let mut arguments = Vec::new();
            if let Some(parameters) = first_named_child_of_kind(node, "function_type_parameters") {
                for child in named_children(parameters) {
                    if let Some(parameter_type) = first_type_descendant(child)
                        .or_else(|| TYPE_KINDS.contains(&child.kind()).then_some(child))
                    {
                        arguments.push(type_ref_with_parameters(
                            parameter_type,
                            source,
                            type_parameters,
                            next_depth,
                            depth_limit_hit,
                        ));
                    }
                }
            }
            let return_type = named_children(node)
                .into_iter()
                .rev()
                .find(|child| TYPE_KINDS.contains(&child.kind()))
                .map_or_else(any_type, |child| {
                    type_ref_with_parameters(
                        child,
                        source,
                        type_parameters,
                        next_depth,
                        depth_limit_hit,
                    )
                });
            let arity = arguments.len();
            arguments.push(return_type);
            TypeRef::Named {
                name: format!("kotlin.Function{arity}"),
                arguments,
                nullable: false,
            }
        }
        _ => kotlin_type_spelling(node, source).map_or_else(any_type, named_type),
    };
    if contains_nullable_wrapper(node) {
        nullable(value)
    } else {
        value
    }
}

fn contains_nullable_wrapper(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(found) = stack.pop() {
        if found.kind() == "nullable_type" {
            return true;
        }
        stack.extend(named_children(found));
    }
    false
}

fn valid_nominal_name(name: &str) -> bool {
    !name.is_empty()
        && !name.chars().any(char::is_whitespace)
        && !name
            .chars()
            .any(|value| matches!(value, '<' | '>' | '(' | ')' | '?' | ','))
}

fn qualified_type_ref(
    node: Node<'_>,
    source: &str,
    parsed: &ParsedFile,
    known_types: &KnownTypes,
    max_depth: usize,
    depth_limit_hit: &mut bool,
) -> TypeRef {
    qualified_type_ref_with_parameters(
        node,
        source,
        parsed,
        known_types,
        &[],
        max_depth,
        depth_limit_hit,
    )
}

fn qualified_type_ref_with_parameters(
    node: Node<'_>,
    source: &str,
    parsed: &ParsedFile,
    known_types: &KnownTypes,
    type_parameters: &[String],
    max_depth: usize,
    depth_limit_hit: &mut bool,
) -> TypeRef {
    let lexical_owners = lexical_type_owners(
        node,
        source,
        &parsed.package_name,
        max_depth,
        depth_limit_hit,
    );
    qualified_type_ref_with_parameters_in_scope(
        node,
        source,
        parsed,
        known_types,
        type_parameters,
        &lexical_owners,
        max_depth,
        depth_limit_hit,
    )
}

#[allow(clippy::too_many_arguments)]
fn qualified_type_ref_with_parameters_in_scope(
    node: Node<'_>,
    source: &str,
    parsed: &ParsedFile,
    known_types: &KnownTypes,
    type_parameters: &[String],
    lexical_owners: &[String],
    max_depth: usize,
    depth_limit_hit: &mut bool,
) -> TypeRef {
    let reference =
        type_ref_with_parameters(node, source, type_parameters, max_depth, depth_limit_hit);
    qualify_type_ref(
        reference,
        parsed,
        known_types,
        lexical_owners,
        max_depth,
        depth_limit_hit,
    )
}

fn lexical_type_owners(
    node: Node<'_>,
    source: &str,
    package_name: &str,
    max_depth: usize,
    depth_limit_hit: &mut bool,
) -> Vec<String> {
    if max_depth == 0 {
        *depth_limit_hit = true;
        return Vec::new();
    }
    let mut names = Vec::new();
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if matches!(
            ancestor.kind(),
            "class_declaration" | "object_declaration" | "companion_object"
        ) {
            let name = ancestor
                .child_by_field_name("name")
                .or_else(|| first_named_child_of_kind(ancestor, "type_identifier"))
                .map_or("Companion", |name| node_source_text_trimmed(name, source));
            names.push(name.to_owned());
            if names.len() == max_depth {
                if ancestor.parent().is_some() {
                    *depth_limit_hit = true;
                }
                break;
            }
        }
        current = ancestor.parent();
    }
    names.reverse();
    let mut owner = package_name.to_owned();
    let mut owners = Vec::with_capacity(names.len());
    for name in names {
        if !owner.is_empty() {
            owner.push('.');
        }
        owner.push_str(&name);
        owners.push(owner.clone());
    }
    owners.reverse();
    owners
}

fn nearest_type_owner_id(node: Node<'_>) -> Option<usize> {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if matches!(
            ancestor.kind(),
            "class_declaration" | "object_declaration" | "companion_object"
        ) {
            return Some(ancestor.id());
        }
        current = ancestor.parent();
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn extension_receiver_constraints(
    receiver: &TypeRef,
    declaration: Node<'_>,
    source: &str,
    parsed: &ParsedFile,
    known_types: &KnownTypes,
    type_parameters: &[String],
    lexical_owners: &[String],
    max_depth: usize,
    depth_limit_hit: &mut bool,
) -> Vec<TypeRef> {
    let TypeRef::TypeParameter { name } = &receiver else {
        return Vec::new();
    };
    let inline_bound = first_named_child_of_kind(declaration, "type_parameters")
        .into_iter()
        .flat_map(named_children)
        .filter(|parameter| parameter.kind() == "type_parameter")
        .find(|parameter| {
            first_named_child_of_kind(*parameter, "type_identifier")
                .is_some_and(|identifier| node_source_text_trimmed(identifier, source) == name)
        })
        .and_then(first_type_descendant);
    let where_bounds = first_named_child_of_kind(declaration, "type_constraints")
        .into_iter()
        .flat_map(named_children)
        .filter(|constraint| constraint.kind() == "type_constraint")
        .filter(|constraint| {
            first_named_descendant_of_kind(*constraint, "type_identifier")
                .is_some_and(|identifier| node_source_text_trimmed(identifier, source) == name)
        })
        .filter_map(first_type_descendant);
    let mut bounds = inline_bound
        .into_iter()
        .chain(where_bounds)
        .map(|bound| {
            qualified_type_ref_with_parameters_in_scope(
                bound,
                source,
                parsed,
                known_types,
                type_parameters,
                lexical_owners,
                max_depth,
                depth_limit_hit,
            )
        })
        .collect::<Vec<_>>();
    bounds.dedup();
    bounds
}

fn qualify_type_ref(
    reference: TypeRef,
    parsed: &ParsedFile,
    known_types: &KnownTypes,
    lexical_owners: &[String],
    remaining_depth: usize,
    depth_limit_hit: &mut bool,
) -> TypeRef {
    if remaining_depth == 0 {
        *depth_limit_hit = true;
        return any_type();
    }
    let next_depth = remaining_depth - 1;
    match reference {
        TypeRef::Named {
            name,
            arguments,
            nullable,
        } => TypeRef::Named {
            name: qualified_type_name(&name, parsed, known_types, lexical_owners).unwrap_or(name),
            arguments: arguments
                .into_iter()
                .map(|argument| {
                    qualify_type_ref(
                        argument,
                        parsed,
                        known_types,
                        lexical_owners,
                        next_depth,
                        depth_limit_hit,
                    )
                })
                .collect(),
            nullable,
        },
        TypeRef::Declared {
            id,
            arguments,
            nullable,
        } => TypeRef::Declared {
            id,
            arguments: arguments
                .into_iter()
                .map(|argument| {
                    qualify_type_ref(
                        argument,
                        parsed,
                        known_types,
                        lexical_owners,
                        next_depth,
                        depth_limit_hit,
                    )
                })
                .collect(),
            nullable,
        },
        other => other,
    }
}

fn qualified_type_name(
    name: &str,
    parsed: &ParsedFile,
    known_types: &KnownTypes,
    lexical_owners: &[String],
) -> Option<String> {
    if !valid_nominal_name(name) || name.len() > MAX_QUALIFIED_NAME_BYTES {
        return None;
    }
    let (head, tail) = name.split_once('.').unwrap_or((name, ""));
    if let Some(imported) = parsed.imports.iter().find(|import| {
        !import.is_wildcard && import.local_name().is_some_and(|local| local == head)
    }) && let Some(path) = &imported.path
    {
        let base = path.segments.join(".");
        let candidate = if tail.is_empty() {
            base
        } else {
            format!("{base}.{tail}")
        };
        return (candidate.len() <= MAX_QUALIFIED_NAME_BYTES).then_some(candidate);
    }
    if known_types.contains(name) {
        return Some(name.to_owned());
    }
    for owner in lexical_owners {
        let candidate = format!("{owner}.{name}");
        if candidate.len() <= MAX_QUALIFIED_NAME_BYTES && known_types.contains(&candidate) {
            return Some(candidate);
        }
    }
    let same_package = if parsed.package_name.is_empty() {
        name.to_owned()
    } else {
        format!("{}.{}", parsed.package_name, name)
    };
    if same_package.len() <= MAX_QUALIFIED_NAME_BYTES && known_types.contains(&same_package) {
        return Some(same_package);
    }
    let nested_suffix = format!(".{name}");
    let package_prefix = if parsed.package_name.is_empty() {
        String::new()
    } else {
        format!("{}.", parsed.package_name)
    };
    let mut nested = known_types
        .nested_candidates(name)
        .iter()
        .filter(|candidate| {
            candidate.starts_with(&package_prefix) && candidate.ends_with(&nested_suffix)
        })
        .cloned();
    if let Some(first) = nested.next()
        && nested.all(|candidate| candidate == first)
    {
        return Some(first);
    }
    let mut star_candidates = parsed
        .imports
        .iter()
        .filter(|import| import.is_wildcard)
        .filter_map(|import| import.path.as_ref())
        .map(|path| format!("{}.{}", path.segments.join("."), name))
        .filter(|candidate| candidate.len() <= MAX_QUALIFIED_NAME_BYTES)
        .filter(|candidate| known_types.contains(candidate));
    if let Some(first) = star_candidates.next() {
        return star_candidates
            .all(|candidate| candidate == first)
            .then_some(first);
    }
    let mut default_candidates = KOTLIN_DEFAULT_IMPORT_PACKAGES
        .iter()
        .map(|package| format!("{package}.{name}"))
        .filter(|candidate| candidate.len() <= MAX_QUALIFIED_NAME_BYTES)
        .filter(|candidate| known_types.contains(candidate));
    if let Some(first) = default_candidates.next() {
        return default_candidates
            .all(|candidate| candidate == first)
            .then_some(first);
    }
    kotlin_stable_default_type(name).map(str::to_owned)
}

fn kotlin_stable_default_type(name: &str) -> Option<&'static str> {
    match name {
        "Any" => Some("kotlin.Any"),
        "Nothing" => Some("kotlin.Nothing"),
        "Unit" => Some("kotlin.Unit"),
        "String" => Some("kotlin.String"),
        "CharSequence" => Some("kotlin.CharSequence"),
        "Throwable" => Some("kotlin.Throwable"),
        "Cloneable" => Some("kotlin.Cloneable"),
        "Number" => Some("kotlin.Number"),
        "Comparable" => Some("kotlin.Comparable"),
        "Enum" => Some("kotlin.Enum"),
        "Annotation" => Some("kotlin.Annotation"),
        "Boolean" => Some("kotlin.Boolean"),
        "Byte" => Some("kotlin.Byte"),
        "Short" => Some("kotlin.Short"),
        "Int" => Some("kotlin.Int"),
        "Long" => Some("kotlin.Long"),
        "Float" => Some("kotlin.Float"),
        "Double" => Some("kotlin.Double"),
        "Char" => Some("kotlin.Char"),
        "Array" => Some("kotlin.Array"),
        "Pair" => Some("kotlin.Pair"),
        "Triple" => Some("kotlin.Triple"),
        "Result" => Some("kotlin.Result"),
        "Iterable" => Some("kotlin.collections.Iterable"),
        "Iterator" => Some("kotlin.collections.Iterator"),
        "Collection" => Some("kotlin.collections.Collection"),
        "List" => Some("kotlin.collections.List"),
        "Set" => Some("kotlin.collections.Set"),
        "Map" => Some("kotlin.collections.Map"),
        "MutableIterable" => Some("kotlin.collections.MutableIterable"),
        "MutableIterator" => Some("kotlin.collections.MutableIterator"),
        "MutableCollection" => Some("kotlin.collections.MutableCollection"),
        "MutableList" => Some("kotlin.collections.MutableList"),
        "MutableSet" => Some("kotlin.collections.MutableSet"),
        "MutableMap" => Some("kotlin.collections.MutableMap"),
        "ListIterator" => Some("kotlin.collections.ListIterator"),
        "MutableListIterator" => Some("kotlin.collections.MutableListIterator"),
        "Sequence" => Some("kotlin.sequences.Sequence"),
        "Regex" => Some("kotlin.text.Regex"),
        "ClosedRange" => Some("kotlin.ranges.ClosedRange"),
        _ => None,
    }
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
    let Some(parameters) = first_named_descendant_of_kind(node, "type_parameters") else {
        return Vec::new();
    };
    named_children(parameters)
        .into_iter()
        .filter(|parameter| parameter.kind() == "type_parameter")
        .filter_map(|parameter| first_named_child_of_kind(parameter, "type_identifier"))
        .map(|name| node_source_text_trimmed(name, source))
        .filter(|name| name.len() <= MAX_QUALIFIED_NAME_BYTES)
        .map(str::to_owned)
        .collect()
}

fn first_named_descendant_of_kind<'tree>(node: Node<'tree>, expected: &str) -> Option<Node<'tree>> {
    let mut queue = std::collections::VecDeque::from(named_children(node));
    while let Some(found) = queue.pop_front() {
        if found.kind() == expected {
            return Some(found);
        }
        queue.extend(named_children(found));
    }
    None
}

fn bounded_text(value: &str) -> String {
    if value.len() <= MAX_QUALIFIED_NAME_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_QUALIFIED_NAME_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
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

fn apply_extension_surfaces(
    types: &mut [TypeFact],
    parsed: &ParsedFile,
    tree: &Tree,
    source: &str,
    parents: &HashMap<CodeUnit, CodeUnit>,
    known_types: &KnownTypes,
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
        if metadata.extension_receiver_type().is_none() {
            continue;
        }
        let owner_name = parents
            .get(declaration)
            .map(CodeUnit::fq_name)
            .unwrap_or_else(|| parsed.package_name.clone());
        let Some(owner_id) = ids.get(&owner_name) else {
            continue;
        };
        let receiver = declaration_node(tree, parsed, declaration)
            .and_then(|node| node.child_by_field_name("receiver"))
            .and_then(|node| kotlin_type_spelling(node, source))
            .and_then(|name| qualified_type_name(&name, parsed, known_types, &[]));
        let Some(receiver) = receiver else {
            continue;
        };
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
    types.sort_unstable_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
    let mut merged: Vec<TypeFact> = Vec::with_capacity(types.len());
    let mut indices: HashMap<String, usize> = HashMap::default();
    for mut fact in types.drain(..) {
        if let Some(index) = indices.get(&fact.id).copied() {
            let previous = &mut merged[index];
            previous
                .extension_surfaces
                .append(&mut fact.extension_surfaces);
            previous.hierarchy.append(&mut fact.hierarchy);
        } else {
            indices.insert(fact.id.clone(), merged.len());
            merged.push(fact);
        }
    }
    for fact in &mut merged {
        fact.extension_surfaces.sort_unstable();
        fact.extension_surfaces.dedup();
        fact.hierarchy
            .sort_unstable_by(|left, right| format!("{:?}", left).cmp(&format!("{:?}", right)));
        fact.hierarchy.dedup();
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
interface Marker
class Sequence<T>
class Dependency<T>(val value: T) : Contract, Sequence<T> {
    fun relay(input: String): String = input
    companion object {
        fun create(): Dependency<String> = TODO()
    }
}
object Registry {
    val name: String = "registry"
}
fun topLevelHelper(value: String): String = value
fun topLevelHelper(value: Int): String = value.toString()
fun String.relay(times: Int): String = repeat(times)
fun Int.relay(times: Int): String = toString().repeat(times)
fun <T> T.applyLike(): T = this
fun <T : Contract> T.contractLike(): String = inherited()
fun <T> T.whereContract(): String where T : Contract, T : Marker = inherited()
fun <T> T.outer(): T {
    fun <T> inner(value: T): T where T : Contract = value
    return this
}
class Outer {
    class Token
    open class Base
    class Child : Base()
    fun token(): Token = Token()
}
class Other {
    class Token
    open class Base
}
private fun hidden(): Unit = Unit
"#;

    #[test]
    fn produces_source_level_kotlin_api() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("dependency-sources.jar");
        write_zip(
            &archive,
            &[
                ("kotlin/example/Dependency.kt", SOURCE),
                (
                    "kotlin/Primitives.kt",
                    "package kotlin\nclass String\nclass Int",
                ),
                (
                    "kotlin/sequences/Sequence.kt",
                    "package kotlin.sequences\ninterface Sequence<T>",
                ),
                (
                    "consumer/UsesSequence.kt",
                    "package consumer\nclass UsesSequence : Sequence<String>",
                ),
            ],
        );
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
        assert_eq!(
            members
                .iter()
                .filter(|fact| fact.name == "topLevelHelper")
                .count(),
            2
        );
        assert!(members.iter().any(|fact| fact.name == "relay"));
        let dependency = types
            .iter()
            .find(|fact| fact.name == "kotlin.example.Dependency")
            .unwrap();
        assert!(
            dependency
                .hierarchy
                .iter()
                .any(|fact| fact.target == named_type("kotlin.example.Contract".to_owned()))
        );
        assert!(
            dependency
                .hierarchy
                .iter()
                .any(|fact| fact.target == named_type("kotlin.example.Sequence".to_owned()))
        );
        let extensions = members
            .iter()
            .filter(|fact| fact.name == "relay" && fact.extension_receiver.is_some())
            .collect::<Vec<_>>();
        assert_eq!(extensions.len(), 2);
        assert_ne!(extensions[0].id, extensions[1].id);
        assert!(extensions.iter().any(|fact| {
            fact.extension_receiver == Some(named_type("kotlin.String".to_owned()))
        }));
        let generic = members
            .iter()
            .find(|fact| fact.name == "applyLike")
            .unwrap();
        assert_eq!(
            generic.extension_receiver,
            Some(TypeRef::TypeParameter {
                name: "T".to_owned()
            })
        );
        let constrained = members
            .iter()
            .find(|fact| fact.name == "contractLike")
            .unwrap();
        assert_eq!(
            constrained.extension_receiver,
            Some(TypeRef::TypeParameter {
                name: "T".to_owned()
            })
        );
        assert_eq!(
            constrained.extension_receiver_constraints,
            vec![named_type("kotlin.example.Contract".to_owned())]
        );
        let where_constrained = members
            .iter()
            .find(|fact| fact.name == "whereContract")
            .unwrap();
        assert_eq!(where_constrained.extension_receiver_constraints.len(), 2);
        let outer = members.iter().find(|fact| fact.name == "outer").unwrap();
        assert!(outer.extension_receiver_constraints.is_empty());
        let nested_return = members
            .iter()
            .find(|fact| fact.name == "token")
            .and_then(|fact| fact.signature.as_ref())
            .and_then(|signature| signature.returns.as_ref());
        assert_eq!(
            nested_return,
            Some(&named_type("kotlin.example.Outer.Token".to_owned()))
        );
        let child = types
            .iter()
            .find(|fact| fact.name == "kotlin.example.Outer.Child")
            .unwrap();
        assert_eq!(
            child.hierarchy[0].target,
            named_type("kotlin.example.Outer.Base".to_owned())
        );
        let uses_sequence = types
            .iter()
            .find(|fact| fact.name == "consumer.UsesSequence")
            .unwrap();
        assert_eq!(
            uses_sequence.hierarchy[0].target,
            named_type("kotlin.sequences.Sequence".to_owned())
        );
        assert!(!members.iter().any(|fact| fact.name == "hidden"));
        assert!(!types.iter().any(|fact| fact.name.contains("Kt")));
        compile_pack(pack, &CompilerOptions::default()).unwrap();
    }

    #[test]
    fn normalizes_archive_entry_order_before_exact_activation() {
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
        write_zip(
            &second_path,
            &[
                ("a/A.kt", "package a\nclass A"),
                ("b/B.kt", "package b\nclass B"),
            ],
        );
        let first = KotlinSourceJarPackProducer
            .produce_exact_artifact(&request(first_path), &ArtifactProducerLimits::default());
        let second = KotlinSourceJarPackProducer
            .produce_exact_artifact(&request(second_path), &ArtifactProducerLimits::default());
        assert_eq!(
            first.pack.as_ref().unwrap().shards[0].payload,
            second.pack.as_ref().unwrap().shards[0].payload
        );
    }

    #[test]
    fn reports_depth_record_and_cancellation_limits() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("bounded.jar");
        write_zip(
            &archive,
            &[
                (
                    "example/Deep.kt",
                    "package example\nfun deep(value: List<List<List<String>>>): Unit = Unit",
                ),
                (
                    "kotlin/Builtins.kt",
                    "package kotlin\nclass String\nclass Unit",
                ),
                (
                    "kotlin/collections/List.kt",
                    "package kotlin.collections\nclass List<T>",
                ),
            ],
        );
        let mut limits = ArtifactProducerLimits {
            max_signature_depth: 2,
            ..ArtifactProducerLimits::default()
        };
        let production =
            KotlinSourceJarPackProducer.produce_exact_artifact(&request(archive.clone()), &limits);
        assert!(production.pack.is_some());
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.signature_depth")
        );

        limits.max_records = 0;
        let production =
            KotlinSourceJarPackProducer.produce_exact_artifact(&request(archive.clone()), &limits);
        assert!(production.pack.is_none());
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.records")
        );

        let exact =
            read_exact_artifact_while(&archive, &ArtifactProducerLimits::default(), || false)
                .unwrap();
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let production = KotlinSourceJarPackProducer.produce_loaded_artifact(
            &request(archive),
            &ArtifactProducerLimits::default(),
            Some(&cancellation),
            &exact,
        );
        assert_eq!(production.diagnostics[0].code, "artifact.cancelled");
    }

    #[test]
    fn rejects_names_that_would_amplify_during_declaration_parsing() {
        let root = tempfile::tempdir().unwrap();
        let archive = root.path().join("oversized-names.jar");
        let source = format!(
            "package example\nimport {}.X\nclass Safe",
            "a".repeat(MAX_QUALIFIED_NAME_BYTES + 1)
        );
        write_zip(&archive, &[("example/Oversized.kt", &source)]);
        let production = KotlinSourceJarPackProducer
            .produce_exact_artifact(&request(archive), &ArtifactProducerLimits::default());
        assert!(production.pack.is_none());
        assert!(
            production
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "kotlin.source.name_limit")
        );
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
