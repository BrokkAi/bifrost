use super::java_artifact::{
    MAX_ARCHIVE_ENTRIES, MAX_SOURCE_ENTRY_BYTES, MAX_TOTAL_ARCHIVE_BYTES, ZipDirectoryStatus,
    zip_directory_status,
};
use crate::CancellationToken;
use crate::analyzer::scala::declarations::{
    ScalaDeclarationVisibility, parse_scala_file, scala_declaration_visibility,
};
use crate::analyzer::scala::{language, scala_normalize_full_name};
use crate::analyzer::semantic_model::{
    ActivationSelector, ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest,
    AuthoredPayload, AuthoredSemanticModelPack, AuthoredShard, BoundedProducerDiagnostics,
    Completeness, ExactArtifact, ExternalArtifactKind, ExternalArtifactPackProducer, HierarchyFact,
    HierarchyKind, Locator, MemberFact, MemberIdentity, MemberKind, Parameter, Producer,
    ProducerDiagnostic, ProducerDiagnosticSeverity, Signature, TypeFact, TypeIdentity, TypeKind,
    TypeRef, Visibility, member_declaration_id, read_exact_artifact_while, type_declaration_id,
};
use crate::analyzer::tree_sitter_analyzer::ParsedFile;
use crate::analyzer::{CodeUnit, ProjectFile};
use crate::hash::HashMap;
use brokk_bifrost_jvm::scala::graph::syntax::{
    ScalaCallableRole, ScalaCallableSourceAlternative, ScalaSourceFacts, ScalaTypeExpressionPath,
    scala_source_facts_from_tree,
};
use std::io::{Cursor, Read};
use tree_sitter::{Node, Parser, Tree};
use zip::ZipArchive;

#[derive(Debug, Clone, Copy, Default)]
pub struct ScalaSourceJarPackProducer;

impl ExternalArtifactPackProducer for ScalaSourceJarPackProducer {
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

impl ScalaSourceJarPackProducer {
    fn produce(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::ScalaSourceJar {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "artifact.kind".to_owned(),
                    location: None,
                    message: "Scala producer requires a Scala source JAR artifact".to_owned(),
                },
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
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "limit.archive_directory".to_owned(),
                    location: None,
                    message: "Scala JAR central directory exceeds bounded entry or byte limits"
                        .to_owned(),
                },
                limits,
            );
        }
        let mut archive = match ZipArchive::new(Cursor::new(artifact.bytes())) {
            Ok(archive) => archive,
            Err(_) => {
                return ArtifactProduction::failed(
                    ProducerDiagnostic {
                        severity: ProducerDiagnosticSeverity::Error,
                        code: "scala.archive.invalid".to_owned(),
                        location: None,
                        message: "artifact is not a readable ZIP/JAR archive".to_owned(),
                    },
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
                return cancelled_production(limits);
            }
            let Ok(mut entry) = archive.by_index(index) else {
                diagnostics.warning(
                    "scala.archive.entry",
                    None,
                    format!("could not read archive entry at index {index}"),
                );
                continue;
            };
            let entry_name = entry.name().to_owned();
            if !entry_name.ends_with(".scala") {
                continue;
            }
            let next_total = total_bytes.saturating_add(entry.size());
            if entry.size() > MAX_SOURCE_ENTRY_BYTES || next_total > MAX_TOTAL_ARCHIVE_BYTES {
                diagnostics.warning(
                    "limit.archive_bytes",
                    Some(entry_name),
                    "archive entry exceeded the bounded Scala extraction budget",
                );
                continue;
            }
            total_bytes = next_total;
            let mut bytes = Vec::with_capacity(entry.size() as usize);
            if entry
                .by_ref()
                .take(MAX_SOURCE_ENTRY_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
                .is_err()
                || bytes.len() as u64 > MAX_SOURCE_ENTRY_BYTES
            {
                diagnostics.warning(
                    "scala.archive.entry_read",
                    Some(entry_name),
                    "could not read bounded archive entry bytes",
                );
                continue;
            }
            match String::from_utf8(bytes) {
                Ok(source) => entries.push((entry_name, source)),
                Err(_) => diagnostics.warning(
                    "scala.source.encoding",
                    Some(entry_name),
                    "Scala source entry is not valid UTF-8",
                ),
            }
        }
        entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

        let mut types = Vec::new();
        let mut members = Vec::new();
        let mut extension_surfaces = Vec::new();
        let mut constructor_names_by_owner = HashMap::default();
        let mut remaining_records = limits.max_records;
        let mut record_limit_hit = false;
        for (entry_name, source) in entries {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return cancelled_production(limits);
            }
            if remaining_records == 0 {
                record_limit_hit = true;
                break;
            }
            let Some(parsed) = parse_source_entry(&entry_name, &source, &mut diagnostics) else {
                continue;
            };
            let mut entry_facts = scala_entry_facts(
                &entry_name,
                &parsed.tree,
                &parsed.parsed,
                &parsed.source_facts,
                &mut remaining_records,
                &mut record_limit_hit,
            );
            types.append(&mut entry_facts.types);
            members.append(&mut entry_facts.members);
            extension_surfaces.append(&mut entry_facts.extension_surfaces);
            for (owner, name) in entry_facts.constructor_names_by_owner {
                if let Some(previous) = constructor_names_by_owner.insert(owner, name.clone()) {
                    debug_assert_eq!(previous, name);
                }
            }
        }
        let owners_with_constructors = members
            .iter()
            .filter(|member| member.member_kind == MemberKind::Constructor)
            .map(|member| member.owner.clone())
            .collect::<crate::hash::HashSet<_>>();
        for (owner, name) in constructor_names_by_owner {
            if owners_with_constructors.contains(&owner) {
                continue;
            }
            if !take_record(&mut remaining_records, &mut record_limit_hit) {
                break;
            }
            let fact = types
                .iter()
                .find(|fact| fact.id == owner)
                .expect("constructor owner was produced with its source type");
            members.push(empty_constructor_fact(fact, name));
        }
        if record_limit_hit {
            diagnostics.warning(
                "limit.records",
                None,
                format!(
                    "producer stopped after {} declaration records",
                    limits.max_records
                ),
            );
        }
        apply_extension_surfaces(&mut types, extension_surfaces);
        types.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        members.sort_unstable_by(|left, right| {
            (&left.owner, &left.name, &left.id).cmp(&(&right.owner, &right.name, &right.id))
        });
        for pair in members.windows(2) {
            debug_assert_ne!(pair[0].id, pair[1].id, "duplicate Scala members: {pair:#?}");
        }
        finish_production(request, artifact.sha256(), types, members, diagnostics)
    }
}

struct ParsedScalaEntry {
    tree: Tree,
    parsed: ParsedFile,
    source_facts: ScalaSourceFacts,
}

fn parse_source_entry(
    entry_name: &str,
    source: &str,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Option<ParsedScalaEntry> {
    let mut parser = Parser::new();
    parser
        .set_language(&language::LANGUAGE.into())
        .expect("tree-sitter Scala language must load");
    let Some(tree) = parser.parse(source, None) else {
        diagnostics.warning(
            "scala.source.parse",
            Some(entry_name.to_owned()),
            "Scala source entry could not be parsed",
        );
        return None;
    };
    if tree.root_node().has_error() {
        diagnostics.warning(
            "scala.source.parse",
            Some(entry_name.to_owned()),
            "Scala source entry contains unsupported or malformed syntax",
        );
        return None;
    }
    let synthetic_file = ProjectFile::new(std::env::temp_dir(), "external.scala");
    let parsed = parse_scala_file(&synthetic_file, source, &tree);
    let source_facts = scala_source_facts_from_tree(&tree, source);
    Some(ParsedScalaEntry {
        tree,
        parsed,
        source_facts,
    })
}

struct ScalaEntryFacts {
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
    extension_surfaces: Vec<(Vec<String>, String)>,
    constructor_names_by_owner: HashMap<String, String>,
}

fn scala_entry_facts(
    entry_name: &str,
    tree: &Tree,
    parsed: &ParsedFile,
    source_facts: &ScalaSourceFacts,
    remaining_records: &mut usize,
    record_limit_hit: &mut bool,
) -> ScalaEntryFacts {
    let parent_by_child = parent_index(parsed);
    let mut declarations = parsed.declarations().iter().collect::<Vec<_>>();
    declarations.sort_unstable_by_key(|unit| unit.fq_name());
    let mut types = Vec::new();
    let mut type_index_by_name = HashMap::default();
    let mut type_ids = HashMap::default();
    let mut type_kinds = HashMap::default();
    let mut type_parameters_by_declaration = HashMap::default();
    let mut constructor_names_by_owner = HashMap::default();
    for declaration in declarations
        .iter()
        .copied()
        .filter(|declaration| declaration.is_class() || parsed.type_aliases.contains(*declaration))
    {
        let Some(visibility) = effective_visibility(tree, parsed, declaration, &parent_by_child)
        else {
            continue;
        };
        let Some(node) = declaration_node(tree, parsed, declaration) else {
            continue;
        };
        let name = scala_normalize_full_name(&declaration.fq_name());
        let type_kind = scala_type_kind(node, parsed.type_aliases.contains(declaration));
        let type_id = type_declaration_id(TypeIdentity {
            ecosystem: "jvm",
            name: &name,
        });
        let range_key = (node.start_byte(), node.end_byte());
        let generic_facts = source_facts.generic_owner_facts_by_range.get(&range_key);
        let type_parameters = generic_facts
            .map(|facts| facts.type_parameters.clone())
            .unwrap_or_default();
        let hierarchy = generic_facts
            .map(|facts| {
                facts
                    .supertypes
                    .iter()
                    .map(|supertype| HierarchyFact {
                        hierarchy_kind: HierarchyKind::Extends,
                        target: scala_type_ref(supertype, &type_parameters),
                        declaration_ordinal: None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        type_ids.insert(declaration.clone(), type_id.clone());
        type_kinds.insert(declaration.clone(), type_kind);
        if matches!(type_kind, TypeKind::Class | TypeKind::Enum) {
            constructor_names_by_owner.insert(type_id.clone(), declaration.identifier().to_owned());
        }
        type_parameters_by_declaration.insert(declaration.clone(), type_parameters.clone());
        let fact = TypeFact {
            id: type_id,
            name,
            type_kind,
            visibility,
            is_abstract: type_kind == TypeKind::Trait || has_modifier(node, "abstract"),
            is_sealed: has_modifier(node, "sealed"),
            has_explicit_type_terms: false,
            type_parameters,
            type_parameter_constraints: Vec::new(),
            underlying_type: None,
            embedded_types: Vec::new(),
            hierarchy,
            aliases: Vec::new(),
            extension_surfaces: Vec::new(),
            locator: Locator::Source {
                path: entry_name.to_owned(),
                symbol: Some(declaration.fq_name()),
            },
        };
        if let Some(&existing_index) = type_index_by_name.get(&fact.name) {
            let existing: &mut TypeFact = &mut types[existing_index];
            if existing.type_kind == TypeKind::Module && fact.type_kind != TypeKind::Module {
                *existing = fact;
            }
            continue;
        }
        if !take_record(remaining_records, record_limit_hit) {
            break;
        }
        type_index_by_name.insert(fact.name.clone(), types.len());
        types.push(fact);
    }

    let mut members = Vec::new();
    let mut extension_surfaces = Vec::new();
    for declaration in declarations.into_iter().filter(|declaration| {
        (declaration.is_function() || declaration.is_field())
            && !parsed.type_aliases.contains(*declaration)
    }) {
        let Some(owner) = parent_by_child.get(declaration) else {
            continue;
        };
        let Some(owner_id) = type_ids.get(owner) else {
            continue;
        };
        let Some(visibility) = effective_visibility(tree, parsed, declaration, &parent_by_child)
        else {
            continue;
        };
        if !take_record(remaining_records, record_limit_hit) {
            break;
        }
        let Some(node) = declaration_node(tree, parsed, declaration) else {
            continue;
        };
        let range_key = (node.start_byte(), node.end_byte());
        let callable = source_facts.callable_alternatives_by_range.get(&range_key);
        let member_kind = scala_member_kind(declaration, callable);
        let signature = callable.and_then(|callable| {
            scala_signature(
                callable,
                source_facts.generic_owner_facts_by_range.get(&range_key),
                type_parameters_by_declaration
                    .get(owner)
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            )
        });
        let parameter_types = signature
            .as_ref()
            .map(|signature| {
                signature
                    .parameters
                    .iter()
                    .map(|parameter| parameter.r#type.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let parameter_variadics = signature
            .as_ref()
            .map(|signature| {
                signature
                    .parameters
                    .iter()
                    .map(|parameter| parameter.variadic)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let generic_arity = signature
            .as_ref()
            .map_or(0, |signature| signature.type_parameters.len());
        let name = declaration.identifier().to_owned();
        let owner_kind = type_kinds.get(owner).copied().unwrap_or(TypeKind::Class);
        let is_static = owner_kind == TypeKind::Module;
        let parameter_arity = signature.as_ref().map_or_else(
            || {
                callable.map_or(0, |callable| {
                    callable
                        .shape
                        .iter()
                        .map(|parameters| parameters.arity.total())
                        .sum()
                })
            },
            |signature| signature.parameters.len(),
        );
        let id = member_declaration_id(MemberIdentity {
            owner_id,
            kind: member_kind,
            is_static,
            parameter_arity,
            name: &name,
            generic_arity,
            parameter_types: &parameter_types,
            parameter_variadics: &parameter_variadics,
            return_type: signature
                .as_ref()
                .and_then(|signature| signature.returns.as_ref()),
        });
        if let Some(receiver) =
            callable.and_then(|callable| callable.extension_receiver_type_path.as_ref().cloned())
        {
            extension_surfaces.push((receiver, scala_normalize_full_name(&owner.fq_name())));
        }
        members.push(MemberFact {
            id,
            owner: owner_id.clone(),
            name,
            member_kind,
            visibility,
            is_static,
            is_abstract: source_facts.abstract_callable_ranges.contains(&range_key),
            is_virtual: member_kind == MemberKind::Method
                && !is_static
                && !has_modifier(node, "final"),
            signature,
            receiver: None,
            extension_receiver: None,
            extension_receiver_constraints: Vec::new(),
            aliases: Vec::new(),
            locator: Locator::Source {
                path: entry_name.to_owned(),
                symbol: Some(declaration.fq_name()),
            },
        });
    }
    ScalaEntryFacts {
        types,
        members,
        extension_surfaces,
        constructor_names_by_owner,
    }
}

fn empty_constructor_fact(owner: &TypeFact, name: String) -> MemberFact {
    MemberFact {
        id: member_declaration_id(MemberIdentity {
            owner_id: &owner.id,
            kind: MemberKind::Constructor,
            is_static: false,
            parameter_arity: 0,
            name: &name,
            generic_arity: 0,
            parameter_types: &[],
            parameter_variadics: &[],
            return_type: None,
        }),
        owner: owner.id.clone(),
        name,
        member_kind: MemberKind::Constructor,
        visibility: owner.visibility,
        is_static: false,
        is_abstract: false,
        is_virtual: false,
        signature: Some(Signature {
            type_parameters: Vec::new(),
            parameters: Vec::new(),
            returns: None,
        }),
        receiver: None,
        extension_receiver: None,
        extension_receiver_constraints: Vec::new(),
        aliases: Vec::new(),
        locator: owner.locator.clone(),
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
    parsed: &ParsedFile,
    declaration: &CodeUnit,
    parents: &HashMap<CodeUnit, CodeUnit>,
) -> Option<Visibility> {
    let mut visibility = Visibility::Public;
    let mut current = Some(declaration);
    while let Some(candidate) = current {
        let node = declaration_node(tree, parsed, candidate)?;
        match scala_declaration_visibility(node) {
            ScalaDeclarationVisibility::Public => {}
            ScalaDeclarationVisibility::Protected => visibility = Visibility::Protected,
            ScalaDeclarationVisibility::NonApi => return None,
        }
        current = parents.get(candidate);
    }
    Some(visibility)
}

fn scala_type_kind(node: Node<'_>, type_alias: bool) -> TypeKind {
    if type_alias {
        return TypeKind::TypeAlias;
    }
    match node.kind() {
        "trait_definition" => TypeKind::Trait,
        "object_definition" => TypeKind::Module,
        "enum_definition" | "full_enum_case" => TypeKind::Enum,
        _ => TypeKind::Class,
    }
}

fn scala_member_kind(
    declaration: &CodeUnit,
    callable: Option<&ScalaCallableSourceAlternative>,
) -> MemberKind {
    if declaration.is_field() {
        return MemberKind::Property;
    }
    if callable.is_some_and(|callable| {
        matches!(
            callable.role,
            ScalaCallableRole::PrimaryConstructor | ScalaCallableRole::SecondaryConstructor
        )
    }) {
        MemberKind::Constructor
    } else {
        MemberKind::Method
    }
}

fn scala_signature(
    callable: &ScalaCallableSourceAlternative,
    callable_generic_facts: Option<
        &brokk_bifrost_jvm::scala::graph::syntax::ScalaGenericOwnerSourceFacts,
    >,
    owner_type_parameters: &[String],
) -> Option<Signature> {
    if callable.parameter_type_expressions.len() != callable.parameter_defaults.len() {
        return None;
    }
    let type_parameters = callable_generic_facts
        .map(|facts| facts.type_parameters.clone())
        .unwrap_or_default();
    let mut available_type_parameters = owner_type_parameters.to_vec();
    available_type_parameters.extend(type_parameters.iter().cloned());
    let mut parameters = Vec::new();
    for (list_index, paths) in callable.parameter_type_expressions.iter().enumerate() {
        let defaults = callable.parameter_defaults.get(list_index)?;
        if paths.len() != defaults.len() {
            return None;
        }
        let repeated = callable
            .shape
            .get(list_index)
            .is_some_and(|shape| shape.arity.is_repeated());
        for (parameter_index, path) in paths.iter().enumerate() {
            let path = path.as_ref()?;
            parameters.push(Parameter {
                name: None,
                r#type: scala_type_ref(path, &available_type_parameters),
                optional: defaults[parameter_index],
                variadic: repeated && parameter_index + 1 == paths.len(),
            });
        }
    }
    let returns = callable
        .return_type_expression
        .as_ref()
        .map(|path| scala_type_ref(path, &available_type_parameters));
    Some(Signature {
        type_parameters,
        parameters,
        returns,
    })
}

fn scala_type_ref(path: &ScalaTypeExpressionPath, type_parameters: &[String]) -> TypeRef {
    if path.segments.len() == 1 && type_parameters.contains(&path.segments[0]) {
        return TypeRef::TypeParameter {
            name: path.segments[0].clone(),
        };
    }
    TypeRef::Named {
        name: path.segments.join("."),
        arguments: path
            .arguments
            .iter()
            .map(|argument| scala_type_ref(argument, type_parameters))
            .collect(),
        nullable: false,
    }
}

fn has_modifier(node: Node<'_>, modifier: &str) -> bool {
    let mut stack = vec![node];
    while let Some(candidate) = stack.pop() {
        if candidate.kind() == modifier {
            return true;
        }
        let mut cursor = candidate.walk();
        stack.extend(
            candidate
                .children(&mut cursor)
                .filter(|child| child.kind() == "modifiers"),
        );
    }
    false
}

fn apply_extension_surfaces(types: &mut [TypeFact], surfaces: Vec<(Vec<String>, String)>) {
    let mut exact = HashMap::default();
    let mut by_short: HashMap<String, Vec<usize>> = HashMap::default();
    for (index, fact) in types.iter().enumerate() {
        exact.insert(fact.name.clone(), index);
        let short = fact
            .name
            .rsplit('.')
            .next()
            .unwrap_or(&fact.name)
            .to_owned();
        by_short.entry(short).or_default().push(index);
    }
    for (receiver, surface) in surfaces {
        let joined = receiver.join(".");
        let target = exact.get(&joined).copied().or_else(|| {
            receiver
                .last()
                .and_then(|short| by_short.get(short))
                .filter(|candidates| candidates.len() == 1)
                .and_then(|candidates| candidates.first().copied())
        });
        if let Some(target) = target {
            types[target].extension_surfaces.push(surface);
        }
    }
    for fact in types {
        fact.extension_surfaces.sort_unstable();
        fact.extension_surfaces.dedup();
    }
}

fn take_record(remaining: &mut usize, record_limit_hit: &mut bool) -> bool {
    if *remaining == 0 {
        *record_limit_hit = true;
        return false;
    }
    *remaining -= 1;
    true
}

fn cancelled_production(limits: &ArtifactProducerLimits) -> ArtifactProduction {
    ArtifactProduction::failed(
        ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: "artifact.cancelled".to_owned(),
            location: None,
            message: "Scala archive production was cancelled".to_owned(),
        },
        limits,
    )
}

fn finish_production(
    request: &ArtifactProductionRequest,
    artifact_sha256: &str,
    types: Vec<TypeFact>,
    members: Vec<MemberFact>,
    mut diagnostics: BoundedProducerDiagnostics,
) -> ArtifactProduction {
    if types.is_empty() {
        diagnostics.error(
            "scala.archive.no_external_declarations",
            None,
            "JAR contains no externally visible Scala declarations",
        );
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        return ArtifactProduction {
            artifact_sha256: Some(artifact_sha256.to_owned()),
            pack: None,
            completeness: Completeness::Partial,
            diagnostics,
            suppressed_diagnostics,
        };
    }
    let mut activation: Vec<ActivationSelector> = request.activation.clone();
    for selector in &mut activation {
        selector.artifact_sha256 = Some(artifact_sha256.to_owned());
    }
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    let completeness = if diagnostics.is_empty() && suppressed_diagnostics == 0 {
        Completeness::Complete
    } else {
        Completeness::Partial
    };
    ArtifactProduction {
        artifact_sha256: Some(artifact_sha256.to_owned()),
        pack: Some(AuthoredSemanticModelPack {
            schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
            pack_id: request.pack_id.clone(),
            version: request.pack_version.clone(),
            producer: Producer {
                name: "bifrost-scala-source-jar".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            language: "scala".to_owned(),
            ecosystem: request.ecosystem.clone(),
            compatibility: request.compatibility.clone(),
            provenance: request.provenance.clone(),
            license: request.license.clone(),
            completeness,
            safety: request.safety.clone(),
            shards: vec![AuthoredShard {
                id: "declarations.scala.external".to_owned(),
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
    use crate::hash::HashSet;
    use std::io::Write;

    const SCALA_SOURCE: &str = r#"
package scala.sample

trait Base[A] {
  protected def transform(value: A): A
  def visible(value: A): A
  private def hidden(value: A): A
}

class Child extends Base[String] {
  override protected def transform(value: String): String = value
  val label: String = "child"
  def create: Child = this
}

object Child {
  def create: Child = new Child
  def `legal name`: String = "child"
}

trait Annotated[@specialized -A]
case class Data(value: Int)

object Syntax {
  extension (value: Child)
    def display: String = value.label
}
"#;

    fn request(path: std::path::PathBuf) -> ArtifactProductionRequest {
        request_for_version(path, "2.13.0")
    }

    fn request_for_version(path: std::path::PathBuf, version: &str) -> ArtifactProductionRequest {
        ArtifactProductionRequest {
            path,
            artifact_kind: ExternalArtifactKind::ScalaSourceJar,
            pack_id: "bifrost.scala.fixture".to_owned(),
            pack_version: version.to_owned(),
            ecosystem: "maven".to_owned(),
            compatibility: Compatibility {
                bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                toolchains: vec![crate::analyzer::semantic_model::VersionConstraint {
                    name: "scala".to_owned(),
                    requirement: format!("={version}"),
                }],
            },
            activation: vec![ActivationSelector {
                package: Some(NameSelector {
                    name: "org.scala-lang:scala-library".to_owned(),
                    version: Some(format!("={version}")),
                }),
                module: None,
                toolchain: Some(NameSelector {
                    name: "scala".to_owned(),
                    version: Some(format!("={version}")),
                }),
                targets: Vec::new(),
                configurations: Vec::new(),
                artifact_sha256: None,
            }],
            provenance: Provenance {
                source: "fixture source archive".to_owned(),
                revision: Some("fixture-v1".to_owned()),
            },
            license: "Apache-2.0".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
        }
    }

    fn source_jar(entries: &[(&str, &str)]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        {
            let mut archive = zip::ZipWriter::new(file.as_file_mut());
            for (name, source) in entries {
                archive
                    .start_file(*name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                archive.write_all(source.as_bytes()).unwrap();
            }
            archive.finish().unwrap();
        }
        file
    }

    #[test]
    fn scala_source_jar_produces_structured_public_and_protected_api() {
        let jar = source_jar(&[("scala/sample/Api.scala", SCALA_SOURCE)]);
        let production = ScalaSourceJarPackProducer.produce_exact_artifact(
            &request(jar.path().to_owned()),
            &ArtifactProducerLimits::default(),
        );

        assert_eq!(production.completeness, Completeness::Complete);
        let pack = production.pack.unwrap();
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload
        else {
            panic!("Scala producer should emit declaration facts");
        };
        assert!(
            types
                .iter()
                .any(|fact| fact.name == "scala.sample.Base" && fact.type_kind == TypeKind::Trait)
        );
        let child = types
            .iter()
            .find(|fact| fact.name == "scala.sample.Child")
            .unwrap();
        assert_eq!(
            types
                .iter()
                .filter(|fact| fact.name == "scala.sample.Child")
                .count(),
            1,
            "class and companion should share one source-level type surface"
        );
        assert!(
            child
                .hierarchy
                .iter()
                .any(|fact| matches!(&fact.target, TypeRef::Named { name, .. } if name == "Base"))
        );
        assert!(
            child
                .extension_surfaces
                .iter()
                .any(|surface| surface == "scala.sample.Syntax"),
            "types={types:#?}; members={members:#?}"
        );
        assert!(
            members
                .iter()
                .any(|fact| fact.name == "transform" && fact.visibility == Visibility::Protected)
        );
        assert!(
            members
                .iter()
                .any(|fact| fact.name == "visible" && fact.visibility == Visibility::Public)
        );
        assert!(!members.iter().any(|fact| fact.name == "hidden"));
        assert!(
            members
                .iter()
                .any(|fact| fact.name == "label" && fact.member_kind == MemberKind::Property)
        );
        assert!(
            members
                .iter()
                .any(|fact| fact.name == "display" && fact.is_static)
        );
        let creates = members
            .iter()
            .filter(|fact| fact.owner == child.id && fact.name == "create")
            .collect::<Vec<_>>();
        assert_eq!(creates.len(), 2);
        assert!(creates.iter().any(|fact| fact.is_static));
        assert!(creates.iter().any(|fact| !fact.is_static));
        assert_ne!(creates[0].id, creates[1].id);
        assert!(members.iter().any(|fact| fact.name == "`legal name`"));
        let child_constructors = members
            .iter()
            .filter(|fact| fact.owner == child.id && fact.member_kind == MemberKind::Constructor)
            .collect::<Vec<_>>();
        assert_eq!(child_constructors.len(), 1);
        assert_eq!(
            child_constructors[0]
                .signature
                .as_ref()
                .expect("primary constructor signature")
                .parameters
                .len(),
            0
        );
        let annotated = types
            .iter()
            .find(|fact| fact.name == "scala.sample.Annotated")
            .unwrap();
        assert_eq!(annotated.type_parameters, ["A"]);
        let data = types
            .iter()
            .find(|fact| fact.name == "scala.sample.Data")
            .unwrap();
        assert!(members.iter().any(|fact| {
            fact.owner == data.id
                && fact.member_kind == MemberKind::Constructor
                && fact
                    .signature
                    .as_ref()
                    .is_some_and(|signature| signature.parameters.len() == 1)
        }));
        assert!(!members.iter().any(|fact| {
            fact.owner == data.id && matches!(fact.name.as_str(), "copy" | "productElement")
        }));
        compile_pack(&pack, &Default::default()).unwrap();
    }

    #[test]
    fn scala_source_jar_preserves_compound_and_variadic_overload_identity() {
        let source = r#"
package sample
trait Overloads[A] {
  def select(value: List[A]): A
  def select(value: Vector[A]): A
  def append(value: A): Unit
  def append(values: A*): Unit
  def ensuring(cond: Boolean, msg: => Any): A
  def ensuring(cond: A => Boolean, msg: => Any): A
}
"#;
        let jar = source_jar(&[("sample/Overloads.scala", source)]);
        let pack = ScalaSourceJarPackProducer
            .produce_exact_artifact(
                &request(jar.path().to_owned()),
                &ArtifactProducerLimits::default(),
            )
            .pack
            .unwrap();
        let AuthoredPayload::DeclarationFacts { members, .. } = &pack.shards[0].payload else {
            panic!("Scala producer should emit declaration facts");
        };

        for name in ["select", "append", "ensuring"] {
            let overloads = members
                .iter()
                .filter(|member| member.name == name)
                .collect::<Vec<_>>();
            assert_eq!(overloads.len(), 2, "members={members:#?}");
            assert_ne!(overloads[0].id, overloads[1].id);
            assert!(overloads.iter().all(|member| member.signature.is_some()));
        }
        compile_pack(&pack, &Default::default()).unwrap();
    }

    #[test]
    fn scala_source_jar_is_deterministic_across_archive_order_and_path() {
        let first = source_jar(&[
            ("z/Second.scala", "package sample\nclass Second"),
            ("a/First.scala", "package sample\nclass First"),
        ]);
        let mut second = tempfile::NamedTempFile::new().unwrap();
        std::io::copy(&mut std::fs::File::open(first.path()).unwrap(), &mut second).unwrap();
        let first_pack = ScalaSourceJarPackProducer
            .produce_exact_artifact(
                &request(first.path().to_owned()),
                &ArtifactProducerLimits::default(),
            )
            .pack
            .unwrap();
        let second_pack = ScalaSourceJarPackProducer
            .produce_exact_artifact(
                &request(second.path().to_owned()),
                &ArtifactProducerLimits::default(),
            )
            .pack
            .unwrap();
        let first_compiled = compile_pack(&first_pack, &Default::default()).unwrap();
        let second_compiled = compile_pack(&second_pack, &Default::default()).unwrap();

        assert_eq!(
            first_compiled.manifest.semantic_sha256,
            second_compiled.manifest.semantic_sha256
        );
        assert_eq!(
            first_compiled.manifest_bytes,
            second_compiled.manifest_bytes
        );
        assert_eq!(first_compiled.shards, second_compiled.shards);
    }

    #[test]
    fn scala_visibility_uses_access_modifier_nodes() {
        let source = "class Surface { protected def inherited: Int = 1; private def hidden: Int = 2; def public: Int = 3 }";
        let mut parser = Parser::new();
        parser.set_language(&language::LANGUAGE.into()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut visibility = HashSet::default();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if matches!(node.kind(), "function_definition" | "function_declaration") {
                visibility.insert(scala_declaration_visibility(node));
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        assert!(visibility.contains(&ScalaDeclarationVisibility::Public));
        assert!(visibility.contains(&ScalaDeclarationVisibility::Protected));
        assert!(visibility.contains(&ScalaDeclarationVisibility::NonApi));
    }

    #[test]
    #[ignore = "requires BIFROST_SCALA_STDLIB_SOURCE_JAR pointing to a pinned source JAR"]
    fn pinned_scala_standard_library_source_smoke() {
        let path = std::env::var_os("BIFROST_SCALA_STDLIB_SOURCE_JAR")
            .map(std::path::PathBuf::from)
            .expect("set BIFROST_SCALA_STDLIB_SOURCE_JAR");
        let version = std::env::var("BIFROST_SCALA_STDLIB_VERSION")
            .expect("set BIFROST_SCALA_STDLIB_VERSION");
        let production = ScalaSourceJarPackProducer.produce_exact_artifact(
            &request_for_version(path, &version),
            &ArtifactProducerLimits::default(),
        );
        let pack = production.pack.expect("real Scala source JAR pack");
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload
        else {
            panic!("Scala source producer must emit declaration facts");
        };
        let compiled = compile_pack(&pack, &CompilerOptions::default()).unwrap_or_else(|errors| {
            for error in &errors {
                if let Some(index) = error
                    .path
                    .strip_prefix("$.shards[0].payload.members[")
                    .and_then(|path| path.split(']').next())
                    .and_then(|index| index.parse::<usize>().ok())
                {
                    eprintln!("invalid member: {:#?}", members[index]);
                }
                if let Some(index) = error
                    .path
                    .strip_prefix("$.shards[0].payload.types[")
                    .and_then(|path| path.split(']').next())
                    .and_then(|index| index.parse::<usize>().ok())
                {
                    eprintln!("invalid type: {:#?}", types[index]);
                }
            }
            panic!("pack compilation failed: {errors:#?}");
        });
        eprintln!(
            "Scala source smoke: types={}, members={}, stored_bytes={}, raw_bytes={}, completeness={:?}, diagnostics={:#?}",
            types.len(),
            members.len(),
            compiled
                .shards
                .iter()
                .map(|shard| shard.descriptor.stored_size)
                .sum::<u64>(),
            compiled
                .shards
                .iter()
                .map(|shard| shard.descriptor.raw_size)
                .sum::<u64>(),
            production.completeness,
            production.diagnostics
        );
        for expected in [
            "scala.Any",
            "scala.AnyRef",
            "scala.AnyVal",
            "scala.Predef",
            "scala.collection.Iterable",
        ] {
            assert!(
                types.iter().any(|fact| fact.name == expected),
                "missing {expected}; diagnostics={:#?}",
                production.diagnostics
            );
        }
        assert!(
            members.iter().any(|fact| fact.name == "hashCode"),
            "scala.Any.hashCode should come from source; diagnostics={:#?}",
            production.diagnostics
        );
    }
}
