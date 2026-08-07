use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest, AuthoredPayload,
    AuthoredSemanticModelPack, AuthoredShard, BoundedProducerDiagnostics, Completeness,
    ExactArtifact, ExternalArtifactKind, ExternalArtifactPackProducer, HierarchyFact,
    HierarchyKind, Locator, MemberFact, MemberIdentity, MemberKind, Parameter, Producer,
    ProducerDiagnostic, ProducerDiagnosticSeverity, Signature, TypeFact, TypeIdentity, TypeKind,
    TypeRef, Visibility, WildcardVariance, member_declaration_id, read_exact_artifact_while,
    type_declaration_id,
};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_jvm::java::declarations::{determine_package_name, node_text, parse_tree};
use jclassfile::attributes::{Attribute, NestedClassFlags};
use jclassfile::class_file::{ClassFile, ClassFlags};
use jclassfile::constant_pool::ConstantPool;
use jclassfile::fields::{FieldFlags, FieldInfo};
use jclassfile::methods::{MethodFlags, MethodInfo};
use std::io::{Cursor, Read};
use tree_sitter::Node;
use zip::ZipArchive;

pub(super) const MAX_ARCHIVE_ENTRIES: usize = 10_000;
pub(super) const MAX_SOURCE_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CLASS_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
pub(super) const MAX_TOTAL_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct JavaJarPackProducer;

#[derive(Debug)]
pub(super) struct JavaApiType {
    pub(super) name: String,
    pub(super) package_name: String,
    type_kind: TypeKind,
    pub(super) visibility: Visibility,
    is_abstract: bool,
    is_sealed: bool,
    type_parameters: Vec<String>,
    hierarchy: Vec<HierarchyFact>,
    locator: Locator,
    members: Vec<JavaApiMember>,
}

#[derive(Debug)]
struct JavaApiMember {
    name: String,
    member_kind: MemberKind,
    visibility: Visibility,
    is_static: bool,
    is_abstract: bool,
    is_virtual: bool,
    signature: Option<Signature>,
    locator: Locator,
}

impl ExternalArtifactPackProducer for JavaJarPackProducer {
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

impl JavaJarPackProducer {
    fn produce(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        if !matches!(
            request.artifact_kind,
            ExternalArtifactKind::JavaSourceJar | ExternalArtifactKind::JavaClassJar
        ) {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "artifact.kind".to_owned(),
                    location: None,
                    message: "Java producer requires a source or class JAR artifact".to_owned(),
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

    pub(crate) fn produce_loaded_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
    ) -> ArtifactProduction {
        let jar_name = match artifact.path().file_name().and_then(|name| name.to_str()) {
            Some(name) => name.to_owned(),
            None => {
                return ArtifactProduction::failed(
                    ProducerDiagnostic {
                        severity: ProducerDiagnosticSeverity::Error,
                        code: "artifact.path_encoding".to_owned(),
                        location: None,
                        message: "artifact filename is not valid UTF-8".to_owned(),
                    },
                    limits,
                );
            }
        };
        if zip_directory_status(artifact.bytes()) == ZipDirectoryStatus::Exceeded {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "limit.archive_directory".to_owned(),
                    location: None,
                    message: "JAR central directory exceeds bounded entry or byte limits"
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
                        code: "java.archive.invalid".to_owned(),
                        location: None,
                        message: "artifact is not a readable ZIP/JAR archive".to_owned(),
                    },
                    limits,
                );
            }
        };
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let mut declarations = Vec::new();
        let mut source_entries = Vec::new();
        let mut remaining_records = limits.max_records;
        let mut record_limit_hit = false;
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
                return ArtifactProduction::failed(
                    ProducerDiagnostic {
                        severity: ProducerDiagnosticSeverity::Error,
                        code: "artifact.cancelled".to_owned(),
                        location: None,
                        message: "Java archive production was cancelled".to_owned(),
                    },
                    limits,
                );
            }
            let Ok(mut entry) = archive.by_index(index) else {
                diagnostics.warning(
                    "java.archive.entry",
                    None,
                    format!("could not read archive entry at index {index}"),
                );
                continue;
            };
            let entry_name = entry.name().to_owned();
            let selected = match request.artifact_kind {
                ExternalArtifactKind::JavaSourceJar => entry_name.ends_with(".java"),
                ExternalArtifactKind::JavaClassJar => {
                    entry_name.ends_with(".class") && !entry_name.ends_with("module-info.class")
                }
                ExternalArtifactKind::ScalaSourceJar | ExternalArtifactKind::KotlinSourceJar => {
                    false
                }
                ExternalArtifactKind::JdkSourceZip => false,
                ExternalArtifactKind::DotNetAssembly => false,
                ExternalArtifactKind::NpmPackageManifest
                | ExternalArtifactKind::TypeScriptDeclarationFile
                | ExternalArtifactKind::RustdocJson
                | ExternalArtifactKind::GoSourceSet
                | ExternalArtifactKind::PythonStub
                | ExternalArtifactKind::PythonSource
                | ExternalArtifactKind::RubyGemArchive
                | ExternalArtifactKind::ComposerPackageSourceSet => false,
            };
            if !selected {
                continue;
            }
            let entry_limit = match request.artifact_kind {
                ExternalArtifactKind::JavaSourceJar => MAX_SOURCE_ENTRY_BYTES,
                ExternalArtifactKind::JavaClassJar => MAX_CLASS_ENTRY_BYTES,
                ExternalArtifactKind::ScalaSourceJar | ExternalArtifactKind::KotlinSourceJar => {
                    unreachable!()
                }
                ExternalArtifactKind::JdkSourceZip => unreachable!(),
                ExternalArtifactKind::DotNetAssembly => unreachable!(),
                ExternalArtifactKind::NpmPackageManifest
                | ExternalArtifactKind::TypeScriptDeclarationFile
                | ExternalArtifactKind::RustdocJson
                | ExternalArtifactKind::GoSourceSet
                | ExternalArtifactKind::PythonStub
                | ExternalArtifactKind::PythonSource
                | ExternalArtifactKind::RubyGemArchive
                | ExternalArtifactKind::ComposerPackageSourceSet => unreachable!(),
            };
            let next_total = total_bytes.saturating_add(entry.size());
            if entry.size() > entry_limit || next_total > MAX_TOTAL_ARCHIVE_BYTES {
                diagnostics.warning(
                    "limit.archive_bytes",
                    Some(entry_name),
                    "archive entry exceeded the bounded Java extraction budget",
                );
                continue;
            }
            total_bytes = next_total;
            let mut bytes = Vec::with_capacity(entry.size() as usize);
            if entry
                .by_ref()
                .take(entry_limit.saturating_add(1))
                .read_to_end(&mut bytes)
                .is_err()
                || bytes.len() as u64 > entry_limit
            {
                diagnostics.warning(
                    "java.archive.entry_read",
                    Some(entry_name),
                    "could not read bounded archive entry bytes",
                );
                continue;
            }
            match request.artifact_kind {
                ExternalArtifactKind::JavaSourceJar => match String::from_utf8(bytes) {
                    Ok(source) => source_entries.push((entry_name, source)),
                    Err(_) => diagnostics.warning(
                        "java.source.encoding",
                        Some(entry_name),
                        "Java source entry is not valid UTF-8",
                    ),
                },
                ExternalArtifactKind::JavaClassJar => match class_api_type(
                    &jar_name,
                    &entry_name,
                    &bytes,
                    limits.max_signature_depth,
                    &mut remaining_records,
                    &mut record_limit_hit,
                    &mut diagnostics,
                ) {
                    ClassEntryResult::Declaration(declaration) => declarations.push(declaration),
                    ClassEntryResult::Skipped => {}
                    ClassEntryResult::Invalid => diagnostics.warning(
                        "java.class.invalid",
                        Some(entry_name),
                        "class entry did not contain supported bounded metadata",
                    ),
                },
                ExternalArtifactKind::ScalaSourceJar | ExternalArtifactKind::KotlinSourceJar => {
                    unreachable!()
                }
                ExternalArtifactKind::JdkSourceZip => unreachable!(),
                ExternalArtifactKind::DotNetAssembly => unreachable!(),
                ExternalArtifactKind::NpmPackageManifest
                | ExternalArtifactKind::TypeScriptDeclarationFile
                | ExternalArtifactKind::RustdocJson
                | ExternalArtifactKind::GoSourceSet
                | ExternalArtifactKind::PythonStub
                | ExternalArtifactKind::PythonSource
                | ExternalArtifactKind::RubyGemArchive
                | ExternalArtifactKind::ComposerPackageSourceSet => unreachable!(),
            }
        }
        if request.artifact_kind == ExternalArtifactKind::JavaSourceJar {
            let known_types = source_entries
                .iter()
                .flat_map(|(_, source)| source_declared_type_names(source))
                .collect::<HashSet<_>>();
            for (entry_name, source) in source_entries {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return ArtifactProduction::failed(
                        ProducerDiagnostic {
                            severity: ProducerDiagnosticSeverity::Error,
                            code: "artifact.cancelled".to_owned(),
                            location: None,
                            message: "Java source production was cancelled".to_owned(),
                        },
                        limits,
                    );
                }
                declarations.extend(source_api_types(
                    &entry_name,
                    &source,
                    &known_types,
                    limits.max_signature_depth,
                    &mut remaining_records,
                    &mut record_limit_hit,
                    &mut diagnostics,
                ));
            }
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
        apply_enclosing_visibility(&mut declarations);
        declarations.retain(|declaration| {
            matches!(
                declaration.visibility,
                Visibility::Public | Visibility::Protected
            )
        });
        finish_production(
            request,
            limits,
            artifact.sha256(),
            declarations,
            diagnostics,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ZipDirectoryStatus {
    Valid,
    Invalid,
    Exceeded,
}

pub(super) fn zip_directory_status(bytes: &[u8]) -> ZipDirectoryStatus {
    zip_directory_status_with_limits(bytes, MAX_ARCHIVE_ENTRIES, MAX_CENTRAL_DIRECTORY_BYTES)
}

pub(super) fn zip_directory_status_with_limits(
    bytes: &[u8],
    max_entries: usize,
    max_directory_bytes: u64,
) -> ZipDirectoryStatus {
    const EOCD: &[u8; 4] = b"PK\x05\x06";
    const ZIP64_LOCATOR: &[u8; 4] = b"PK\x06\x07";
    const ZIP64_EOCD: &[u8; 4] = b"PK\x06\x06";
    let search_start = bytes.len().saturating_sub(u16::MAX as usize + 22);
    let Some(eocd) = (search_start..bytes.len().saturating_sub(3))
        .rev()
        .find(|offset| bytes.get(*offset..offset + 4) == Some(EOCD))
    else {
        return ZipDirectoryStatus::Invalid;
    };
    let Some(entries) = little_u16(bytes, eocd + 10) else {
        return ZipDirectoryStatus::Invalid;
    };
    let Some(directory_bytes) = little_u32(bytes, eocd + 12) else {
        return ZipDirectoryStatus::Invalid;
    };
    if entries != u16::MAX && directory_bytes != u32::MAX {
        return if usize::from(entries) <= max_entries
            && u64::from(directory_bytes) <= max_directory_bytes
        {
            ZipDirectoryStatus::Valid
        } else {
            ZipDirectoryStatus::Exceeded
        };
    }
    let locator_start = eocd.saturating_sub(20);
    if bytes.get(locator_start..locator_start + 4) != Some(ZIP64_LOCATOR) {
        return ZipDirectoryStatus::Invalid;
    }
    let Some(zip64_offset) =
        little_u64(bytes, locator_start + 8).and_then(|offset| usize::try_from(offset).ok())
    else {
        return ZipDirectoryStatus::Invalid;
    };
    if bytes.get(zip64_offset..zip64_offset + 4) != Some(ZIP64_EOCD) {
        return ZipDirectoryStatus::Invalid;
    }
    let Some(entries) = little_u64(bytes, zip64_offset + 32) else {
        return ZipDirectoryStatus::Invalid;
    };
    let Some(directory_bytes) = little_u64(bytes, zip64_offset + 40) else {
        return ZipDirectoryStatus::Invalid;
    };
    if entries <= max_entries as u64 && directory_bytes <= max_directory_bytes {
        ZipDirectoryStatus::Valid
    } else {
        ZipDirectoryStatus::Exceeded
    }
}

fn little_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn little_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn little_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

pub(super) fn apply_enclosing_visibility(declarations: &mut [JavaApiType]) {
    let visibility_by_name = declarations
        .iter()
        .map(|declaration| (declaration.name.clone(), declaration.visibility))
        .collect::<HashMap<_, _>>();
    for declaration in declarations {
        let mut current = declaration.name.as_str();
        while let Some((owner, _)) = current.rsplit_once('.') {
            let Some(visibility) = visibility_by_name.get(owner).copied() else {
                break;
            };
            declaration.visibility = restrict_visibility(declaration.visibility, visibility);
            current = owner;
        }
    }
}

fn finish_production(
    request: &ArtifactProductionRequest,
    limits: &ArtifactProducerLimits,
    artifact_sha256: &str,
    declarations: Vec<JavaApiType>,
    mut diagnostics: BoundedProducerDiagnostics,
) -> ArtifactProduction {
    let (types, members) = java_api_facts(declarations, limits.max_records, &mut diagnostics);
    if types.is_empty() {
        diagnostics.error(
            "java.archive.no_external_declarations",
            None,
            "JAR contains no externally visible Java declarations",
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
    let mut activation = request.activation.clone();
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
            schema_version: super::super::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
            pack_id: request.pack_id.clone(),
            version: request.pack_version.clone(),
            producer: Producer {
                name: "bifrost-java-jar".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            language: "java".to_owned(),
            ecosystem: request.ecosystem.clone(),
            compatibility: request.compatibility.clone(),
            provenance: request.provenance.clone(),
            license: request.license.clone(),
            completeness,
            safety: request.safety.clone(),
            shards: vec![AuthoredShard {
                id: "declarations.external".to_owned(),
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

pub(super) fn java_api_facts(
    declarations: Vec<JavaApiType>,
    max_records: usize,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> (Vec<TypeFact>, Vec<MemberFact>) {
    let mut type_ids = HashMap::default();
    for declaration in &declarations {
        type_ids.insert(
            declaration.name.clone(),
            type_declaration_id(TypeIdentity {
                ecosystem: "jvm",
                name: &declaration.name,
            }),
        );
    }
    let mut types = Vec::new();
    let mut members = Vec::new();
    for declaration in declarations {
        if types.len().saturating_add(members.len()) >= max_records {
            diagnostics.warning(
                "limit.records",
                None,
                format!("producer stopped after {} declaration records", max_records),
            );
            break;
        }
        let type_id = type_ids
            .get(&declaration.name)
            .expect("parsed Java type receives an id")
            .clone();
        types.push(TypeFact {
            id: type_id.clone(),
            name: declaration.name,
            type_kind: declaration.type_kind,
            visibility: declaration.visibility,
            is_abstract: declaration.is_abstract,
            is_sealed: declaration.is_sealed,
            has_explicit_type_terms: false,
            type_parameters: declaration.type_parameters,
            type_parameter_constraints: Vec::new(),
            underlying_type: None,
            embedded_types: Vec::new(),
            hierarchy: declaration.hierarchy,
            aliases: Vec::new(),
            extension_surfaces: Vec::new(),
            locator: declaration.locator,
        });
        for member in declaration.members {
            if types.len().saturating_add(members.len()) >= max_records {
                diagnostics.warning(
                    "limit.records",
                    None,
                    format!("producer stopped after {} declaration records", max_records),
                );
                break;
            }
            let parameter_types = member
                .signature
                .as_ref()
                .map(|signature| {
                    signature
                        .parameters
                        .iter()
                        .map(|parameter| parameter.r#type.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let generic_arity = member
                .signature
                .as_ref()
                .map_or(0, |signature| signature.type_parameters.len());
            let id = member_declaration_id(MemberIdentity {
                owner_id: &type_id,
                kind: member.member_kind,
                is_static: member.is_static,
                parameter_arity: parameter_types.len(),
                name: &member.name,
                generic_arity,
                parameter_types: &parameter_types,
                parameter_variadics: &[],
                return_type: member
                    .signature
                    .as_ref()
                    .and_then(|signature| signature.returns.as_ref()),
            });
            members.push(MemberFact {
                id,
                owner: type_id.clone(),
                name: member.name,
                member_kind: member.member_kind,
                visibility: member.visibility,
                is_static: member.is_static,
                is_abstract: member.is_abstract,
                is_virtual: member.is_virtual,
                signature: member.signature,
                receiver: None,
                extension_receiver: None,
                extension_receiver_constraints: Vec::new(),
                aliases: Vec::new(),
                locator: member.locator,
            });
        }
    }
    (types, members)
}

pub(super) fn source_api_types(
    source_path: &str,
    source: &str,
    known_types: &HashSet<String>,
    max_depth: usize,
    remaining_records: &mut usize,
    record_limit_hit: &mut bool,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Vec<JavaApiType> {
    let Some(tree) = parse_tree(source) else {
        diagnostics.warning(
            "java.source.parse",
            Some(source_path.to_owned()),
            "Java source entry could not be parsed",
        );
        return Vec::new();
    };
    if tree.root_node().has_error() {
        diagnostics.warning(
            "java.source.parse",
            Some(source_path.to_owned()),
            "Java source entry contains parse errors",
        );
    }
    let root = tree.root_node();
    let package_name = determine_package_name(root, source);
    let resolution = SourceTypeResolution::new(root, source, package_name.clone(), known_types);
    let mut result = Vec::new();
    let mut stack = Vec::new();
    for index in (0..root.named_child_count()).rev() {
        if let Some(child) = root.named_child(index)
            && source_type_kind(child.kind()).is_some()
        {
            stack.push((child, None::<String>, Visibility::Public, false));
        }
    }
    while let Some((node, parent_name, parent_visibility, parent_is_interface)) = stack.pop() {
        let Some(name_node) = node.child_by_field_name("name") else {
            continue;
        };
        let simple_name = node_text(name_node, source).trim();
        if simple_name.is_empty() {
            continue;
        }
        let nested_name = parent_name
            .as_deref()
            .map(|parent| format!("{parent}.{simple_name}"))
            .unwrap_or_else(|| simple_name.to_owned());
        let name = if package_name.is_empty() {
            nested_name.clone()
        } else {
            format!("{package_name}.{nested_name}")
        };
        let default_visibility = if parent_is_interface {
            Visibility::Public
        } else {
            Visibility::Package
        };
        let declared_visibility = source_visibility(node, source, default_visibility);
        let visibility = restrict_visibility(declared_visibility, parent_visibility);
        let type_kind = source_type_kind(node.kind()).expect("stack holds Java types");
        let modifiers = source_modifiers(node, source);
        let type_parameters = source_type_parameters(node, source);
        let hierarchy = source_hierarchy(
            node,
            source,
            &resolution,
            &type_parameters,
            max_depth,
            diagnostics,
            source_path,
        );
        if matches!(visibility, Visibility::Public | Visibility::Protected) {
            if !take_record(remaining_records, record_limit_hit) {
                break;
            }
            let members = source_members(
                node,
                source,
                &resolution,
                &name,
                type_kind,
                visibility,
                &type_parameters,
                max_depth,
                remaining_records,
                record_limit_hit,
                diagnostics,
                source_path,
            );
            result.push(JavaApiType {
                name: name.clone(),
                package_name: package_name.clone(),
                type_kind,
                visibility,
                is_abstract: modifiers.contains(&"abstract")
                    || matches!(type_kind, TypeKind::Interface | TypeKind::Annotation),
                is_sealed: modifiers.contains(&"final"),
                type_parameters,
                hierarchy,
                locator: Locator::Source {
                    path: source_path.to_owned(),
                    symbol: Some(name.clone()),
                },
                members,
            });
        }
        let Some(body) = node.child_by_field_name("body") else {
            continue;
        };
        for index in (0..body.named_child_count()).rev() {
            if let Some(child) = body.named_child(index)
                && source_type_kind(child.kind()).is_some()
            {
                stack.push((
                    child,
                    Some(nested_name.clone()),
                    visibility,
                    matches!(type_kind, TypeKind::Interface | TypeKind::Annotation),
                ));
            }
        }
    }
    result
}

#[allow(clippy::too_many_arguments)] // Source traversal carries explicit owner, limit, and diagnostic state.
fn source_members(
    owner: Node<'_>,
    source: &str,
    resolution: &SourceTypeResolution<'_>,
    owner_name: &str,
    owner_kind: TypeKind,
    owner_visibility: Visibility,
    owner_parameters: &[String],
    max_depth: usize,
    remaining_records: &mut usize,
    record_limit_hit: &mut bool,
    diagnostics: &mut BoundedProducerDiagnostics,
    source_path: &str,
) -> Vec<JavaApiMember> {
    let Some(body) = owner.child_by_field_name("body") else {
        return Vec::new();
    };
    let interface_owner = matches!(
        source_type_kind(owner.kind()),
        Some(TypeKind::Interface | TypeKind::Annotation)
    );
    let mut result = Vec::new();
    let mut has_constructor = false;
    for index in 0..body.named_child_count() {
        let Some(node) = body.named_child(index) else {
            continue;
        };
        match node.kind() {
            "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "annotation_type_element_declaration" => {
                let constructor = matches!(
                    node.kind(),
                    "constructor_declaration" | "compact_constructor_declaration"
                );
                has_constructor |= constructor;
                let Some(name_node) = node.child_by_field_name("name") else {
                    continue;
                };
                let declared_name = node_text(name_node, source).trim();
                let name = if constructor { "<init>" } else { declared_name };
                let default_visibility = if interface_owner {
                    Visibility::Public
                } else {
                    Visibility::Package
                };
                let visibility = source_visibility(node, source, default_visibility);
                if !matches!(visibility, Visibility::Public | Visibility::Protected) {
                    continue;
                }
                let type_parameters = source_type_parameters(node, source);
                let Some(parameters) = source_parameters(
                    node,
                    source,
                    resolution,
                    owner_parameters,
                    &type_parameters,
                    max_depth,
                    diagnostics,
                    source_path,
                ) else {
                    continue;
                };
                let returns = if constructor {
                    None
                } else {
                    node.child_by_field_name("type").and_then(|r#type| {
                        source_type_ref(
                            r#type,
                            source,
                            resolution,
                            owner_parameters,
                            &type_parameters,
                            0,
                            max_depth,
                        )
                    })
                };
                if !constructor
                    && node.child_by_field_name("type").is_some()
                    && returns.is_none()
                    && node
                        .child_by_field_name("type")
                        .is_none_or(|r#type| r#type.kind() != "void_type")
                {
                    diagnostics.warning(
                        "java.source.unsupported_return_type",
                        Some(source_path.to_owned()),
                        format!("could not represent return type for {owner_name}.{declared_name}"),
                    );
                    continue;
                }
                let modifiers = source_modifiers(node, source);
                if !take_record(remaining_records, record_limit_hit) {
                    break;
                }
                result.push(JavaApiMember {
                    name: name.to_owned(),
                    member_kind: if constructor {
                        MemberKind::Constructor
                    } else {
                        MemberKind::Method
                    },
                    visibility,
                    is_static: modifiers.contains(&"static"),
                    is_abstract: modifiers.contains(&"abstract")
                        || interface_owner && !modifiers.contains(&"default"),
                    is_virtual: !constructor
                        && !modifiers.contains(&"static")
                        && !modifiers.contains(&"final"),
                    signature: Some(Signature {
                        type_parameters,
                        parameters,
                        returns,
                    }),
                    locator: Locator::Source {
                        path: source_path.to_owned(),
                        symbol: Some(format!("{owner_name}.{declared_name}")),
                    },
                });
            }
            "field_declaration" | "constant_declaration" => {
                let Some(type_node) = node.child_by_field_name("type") else {
                    continue;
                };
                let Some(field_type) = source_type_ref(
                    type_node,
                    source,
                    resolution,
                    owner_parameters,
                    &[],
                    0,
                    max_depth,
                ) else {
                    diagnostics.warning(
                        "java.source.unsupported_field_type",
                        Some(source_path.to_owned()),
                        format!("could not represent field type in {owner_name}"),
                    );
                    continue;
                };
                let default_visibility = if interface_owner {
                    Visibility::Public
                } else {
                    Visibility::Package
                };
                let visibility = source_visibility(node, source, default_visibility);
                if !matches!(visibility, Visibility::Public | Visibility::Protected) {
                    continue;
                }
                let modifiers = source_modifiers(node, source);
                for child_index in 0..node.named_child_count() {
                    let Some(declarator) = node.named_child(child_index) else {
                        continue;
                    };
                    if declarator.kind() != "variable_declarator" {
                        continue;
                    }
                    let Some(name_node) = declarator.child_by_field_name("name") else {
                        continue;
                    };
                    let name = node_text(name_node, source).trim();
                    if !take_record(remaining_records, record_limit_hit) {
                        break;
                    }
                    result.push(JavaApiMember {
                        name: name.to_owned(),
                        member_kind: if node.kind() == "constant_declaration" {
                            MemberKind::Constant
                        } else {
                            MemberKind::Field
                        },
                        visibility,
                        is_static: interface_owner || modifiers.contains(&"static"),
                        is_abstract: false,
                        is_virtual: false,
                        signature: Some(Signature {
                            type_parameters: Vec::new(),
                            parameters: Vec::new(),
                            returns: Some(field_type.clone()),
                        }),
                        locator: Locator::Source {
                            path: source_path.to_owned(),
                            symbol: Some(format!("{owner_name}.{name}")),
                        },
                    });
                }
            }
            _ => {}
        }
    }
    if owner_kind == TypeKind::Record {
        let components = source_parameters(
            owner,
            source,
            resolution,
            owner_parameters,
            &[],
            max_depth,
            diagnostics,
            source_path,
        )
        .unwrap_or_default();
        if !has_constructor {
            push_generated_member(
                &mut result,
                remaining_records,
                record_limit_hit,
                generated_java_member(
                    "<init>",
                    MemberKind::Constructor,
                    owner_visibility,
                    false,
                    components.clone(),
                    None,
                    owner_name,
                    source_path,
                ),
            );
        }
        for component in components {
            let Some(name) = component.name.clone() else {
                continue;
            };
            push_generated_member(
                &mut result,
                remaining_records,
                record_limit_hit,
                generated_java_member(
                    &name,
                    MemberKind::Method,
                    Visibility::Public,
                    false,
                    Vec::new(),
                    Some(component.r#type),
                    owner_name,
                    source_path,
                ),
            );
        }
        for (name, parameters, returns) in [
            (
                "equals",
                vec![Parameter {
                    name: Some("other".to_owned()),
                    r#type: named_type("java.lang.Object".to_owned()),
                    optional: false,
                    variadic: false,
                }],
                named_type("boolean".to_owned()),
            ),
            ("hashCode", Vec::new(), named_type("int".to_owned())),
            (
                "toString",
                Vec::new(),
                named_type("java.lang.String".to_owned()),
            ),
        ] {
            push_generated_member(
                &mut result,
                remaining_records,
                record_limit_hit,
                generated_java_member(
                    name,
                    MemberKind::Method,
                    Visibility::Public,
                    false,
                    parameters,
                    Some(returns),
                    owner_name,
                    source_path,
                ),
            );
        }
    } else if owner_kind == TypeKind::Enum {
        push_generated_member(
            &mut result,
            remaining_records,
            record_limit_hit,
            generated_java_member(
                "values",
                MemberKind::Method,
                Visibility::Public,
                true,
                Vec::new(),
                Some(TypeRef::Array {
                    element: Box::new(named_type(owner_name.to_owned())),
                }),
                owner_name,
                source_path,
            ),
        );
        push_generated_member(
            &mut result,
            remaining_records,
            record_limit_hit,
            generated_java_member(
                "valueOf",
                MemberKind::Method,
                Visibility::Public,
                true,
                vec![Parameter {
                    name: Some("name".to_owned()),
                    r#type: named_type("java.lang.String".to_owned()),
                    optional: false,
                    variadic: false,
                }],
                Some(named_type(owner_name.to_owned())),
                owner_name,
                source_path,
            ),
        );
    } else if owner_kind == TypeKind::Class && !has_constructor {
        push_generated_member(
            &mut result,
            remaining_records,
            record_limit_hit,
            JavaApiMember {
                name: "<init>".to_owned(),
                member_kind: MemberKind::Constructor,
                visibility: owner_visibility,
                is_static: false,
                is_abstract: false,
                is_virtual: false,
                signature: Some(Signature {
                    type_parameters: Vec::new(),
                    parameters: Vec::new(),
                    returns: None,
                }),
                locator: Locator::Source {
                    path: source_path.to_owned(),
                    symbol: Some(format!("{owner_name}.<init>")),
                },
            },
        );
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn generated_java_member(
    name: &str,
    member_kind: MemberKind,
    visibility: Visibility,
    is_static: bool,
    parameters: Vec<Parameter>,
    returns: Option<TypeRef>,
    owner_name: &str,
    source_path: &str,
) -> JavaApiMember {
    JavaApiMember {
        name: name.to_owned(),
        member_kind,
        visibility,
        is_static,
        is_abstract: false,
        is_virtual: !is_static && member_kind == MemberKind::Method,
        signature: Some(Signature {
            type_parameters: Vec::new(),
            parameters,
            returns,
        }),
        locator: Locator::Source {
            path: source_path.to_owned(),
            symbol: Some(format!("{owner_name}.{name}")),
        },
    }
}

fn push_generated_member(
    result: &mut Vec<JavaApiMember>,
    remaining_records: &mut usize,
    record_limit_hit: &mut bool,
    member: JavaApiMember,
) {
    if take_record(remaining_records, record_limit_hit) {
        result.push(member);
    }
}

#[allow(clippy::too_many_arguments)]
fn source_parameters(
    node: Node<'_>,
    source: &str,
    resolution: &SourceTypeResolution<'_>,
    owner_parameters: &[String],
    member_parameters: &[String],
    max_depth: usize,
    diagnostics: &mut BoundedProducerDiagnostics,
    source_path: &str,
) -> Option<Vec<Parameter>> {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return Some(Vec::new());
    };
    let mut result = Vec::new();
    for index in 0..parameters.named_child_count() {
        let Some(parameter) = parameters.named_child(index) else {
            continue;
        };
        if !matches!(parameter.kind(), "formal_parameter" | "spread_parameter") {
            continue;
        }
        let variable_declarator = (parameter.kind() == "spread_parameter").then(|| {
            (0..parameter.named_child_count())
                .filter_map(|index| parameter.named_child(index))
                .find(|child| child.kind() == "variable_declarator")
        });
        let variable_declarator = variable_declarator.flatten();
        let type_node = parameter.child_by_field_name("type").or_else(|| {
            (0..parameter.named_child_count())
                .filter_map(|index| parameter.named_child(index))
                .find(|child| is_source_type_node(child.kind()))
        });
        let Some(type_node) = type_node else {
            continue;
        };
        let Some(mut r#type) = source_type_ref(
            type_node,
            source,
            resolution,
            owner_parameters,
            member_parameters,
            0,
            max_depth,
        ) else {
            diagnostics.warning(
                "java.source.unsupported_parameter_type",
                Some(source_path.to_owned()),
                "could not represent Java parameter type",
            );
            return None;
        };
        let trailing_dimensions = parameter
            .child_by_field_name("dimensions")
            .map_or(0, dimension_count)
            + variable_declarator
                .and_then(|declarator| declarator.child_by_field_name("dimensions"))
                .map_or(0, dimension_count);
        let array_depth = usize::from(parameter.kind() == "spread_parameter") + trailing_dimensions;
        for _ in 0..array_depth {
            r#type = TypeRef::Array {
                element: Box::new(r#type),
            };
        }
        let name = parameter
            .child_by_field_name("name")
            .or_else(|| {
                variable_declarator.and_then(|declarator| declarator.child_by_field_name("name"))
            })
            .map(|name| node_text(name, source).trim().to_owned());
        result.push(Parameter {
            name,
            r#type,
            optional: false,
            variadic: parameter.kind() == "spread_parameter",
        });
    }
    Some(result)
}

fn dimension_count(dimensions: Node<'_>) -> usize {
    let count = (0..dimensions.child_count())
        .filter_map(|index| dimensions.child(index))
        .filter(|child| child.kind() == "[")
        .count();
    debug_assert!(
        count > 0,
        "Java dimensions node contains an array dimension"
    );
    count
}

fn source_hierarchy(
    node: Node<'_>,
    source: &str,
    resolution: &SourceTypeResolution<'_>,
    type_parameters: &[String],
    max_depth: usize,
    diagnostics: &mut BoundedProducerDiagnostics,
    source_path: &str,
) -> Vec<HierarchyFact> {
    let mut result = Vec::new();
    for (field, hierarchy_kind) in [
        ("superclass", HierarchyKind::Extends),
        ("interfaces", HierarchyKind::Implements),
    ] {
        let Some(container) = node.child_by_field_name(field) else {
            continue;
        };
        for candidate in hierarchy_type_nodes(container) {
            if let Some(target) = source_type_ref(
                candidate,
                source,
                resolution,
                type_parameters,
                &[],
                0,
                max_depth,
            ) {
                result.push(HierarchyFact {
                    hierarchy_kind,
                    target,
                    declaration_ordinal: None,
                });
            } else {
                diagnostics.warning(
                    "java.source.unsupported_hierarchy_type",
                    Some(source_path.to_owned()),
                    "could not represent Java hierarchy type",
                );
            }
        }
    }
    result
}

fn hierarchy_type_nodes(container: Node<'_>) -> Vec<Node<'_>> {
    if is_source_type_node(container.kind()) {
        return vec![container];
    }
    (0..container.named_child_count())
        .filter_map(|index| container.named_child(index))
        .flat_map(|child| {
            if is_source_type_node(child.kind()) {
                vec![child]
            } else {
                hierarchy_type_nodes(child)
            }
        })
        .collect()
}

fn source_type_ref(
    node: Node<'_>,
    source: &str,
    resolution: &SourceTypeResolution<'_>,
    owner_parameters: &[String],
    member_parameters: &[String],
    depth: usize,
    max_depth: usize,
) -> Option<TypeRef> {
    if depth >= max_depth {
        return None;
    }
    match node.kind() {
        "void_type" => None,
        "array_type" => {
            let element = node
                .child_by_field_name("element")
                .or_else(|| node.child_by_field_name("type"))?;
            let mut r#type = source_type_ref(
                element,
                source,
                resolution,
                owner_parameters,
                member_parameters,
                depth + 1,
                max_depth,
            )?;
            let dimensions = node
                .child_by_field_name("dimensions")
                .map_or(1, dimension_count);
            for _ in 0..dimensions {
                r#type = TypeRef::Array {
                    element: Box::new(r#type),
                };
            }
            Some(r#type)
        }
        "generic_type" => {
            let base = node
                .child_by_field_name("type")
                .or_else(|| node.named_child(0))?;
            let name = compact_type_name(node_text(base, source));
            let arguments = node
                .child_by_field_name("type_arguments")
                .or_else(|| {
                    (0..node.named_child_count())
                        .filter_map(|index| node.named_child(index))
                        .find(|child| child.kind() == "type_arguments")
                })
                .into_iter()
                .flat_map(|arguments| {
                    (0..arguments.named_child_count())
                        .filter_map(move |index| arguments.named_child(index))
                })
                .map(|argument| {
                    source_type_ref(
                        argument,
                        source,
                        resolution,
                        owner_parameters,
                        member_parameters,
                        depth + 1,
                        max_depth,
                    )
                })
                .collect::<Option<Vec<_>>>()?;
            Some(TypeRef::Named {
                name: resolution.resolve(&name)?,
                arguments,
                nullable: false,
            })
        }
        "annotated_type" => source_type_ref(
            node.child_by_field_name("type")?,
            source,
            resolution,
            owner_parameters,
            member_parameters,
            depth + 1,
            max_depth,
        ),
        "wildcard" => {
            let variance = if (0..node.child_count())
                .filter_map(|index| node.child(index))
                .any(|child| child.kind() == "super")
            {
                WildcardVariance::Super
            } else if (0..node.child_count())
                .filter_map(|index| node.child(index))
                .any(|child| child.kind() == "extends")
            {
                WildcardVariance::Extends
            } else {
                WildcardVariance::Any
            };
            let bound = (0..node.named_child_count())
                .filter_map(|index| node.named_child(index))
                .find(|child| is_source_type_node(child.kind()))
                .map(|bound| {
                    source_type_ref(
                        bound,
                        source,
                        resolution,
                        owner_parameters,
                        member_parameters,
                        depth + 1,
                        max_depth,
                    )
                    .map(Box::new)
                });
            let bound = match bound {
                Some(bound) => Some(bound?),
                None => None,
            };
            Some(TypeRef::Wildcard { variance, bound })
        }
        "type_identifier" => {
            let name = compact_type_name(node_text(node, source));
            if owner_parameters.iter().any(|parameter| parameter == &name)
                || member_parameters.iter().any(|parameter| parameter == &name)
            {
                Some(TypeRef::TypeParameter { name })
            } else {
                Some(TypeRef::Named {
                    name: resolution.resolve(&name)?,
                    arguments: Vec::new(),
                    nullable: false,
                })
            }
        }
        "integral_type" | "floating_point_type" | "boolean_type" | "primitive_type" => {
            Some(TypeRef::Named {
                name: compact_type_name(node_text(node, source)),
                arguments: Vec::new(),
                nullable: false,
            })
        }
        "scoped_type_identifier" => Some(TypeRef::Named {
            name: resolution.resolve(&compact_type_name(node_text(node, source)))?,
            arguments: Vec::new(),
            nullable: false,
        }),
        _ if node.named_child_count() == 1 => source_type_ref(
            node.named_child(0)?,
            source,
            resolution,
            owner_parameters,
            member_parameters,
            depth + 1,
            max_depth,
        ),
        _ => None,
    }
}

fn source_type_parameters(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(parameters) = node.child_by_field_name("type_parameters").or_else(|| {
        (0..node.named_child_count())
            .filter_map(|index| node.named_child(index))
            .find(|child| child.kind() == "type_parameters")
    }) else {
        return Vec::new();
    };
    (0..parameters.named_child_count())
        .filter_map(|index| parameters.named_child(index))
        .filter(|parameter| parameter.kind() == "type_parameter")
        .filter_map(|parameter| {
            parameter
                .child_by_field_name("name")
                .or_else(|| parameter.named_child(0))
        })
        .map(|name| node_text(name, source).trim().to_owned())
        .collect()
}

fn source_modifiers<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let Some(modifiers) = (0..node.named_child_count())
        .filter_map(|index| node.named_child(index))
        .find(|child| child.kind() == "modifiers")
    else {
        return Vec::new();
    };
    node_text(modifiers, source)
        .split(|character: char| !character.is_ascii_alphabetic())
        .filter(|modifier| !modifier.is_empty())
        .collect()
}

fn source_visibility(node: Node<'_>, source: &str, default: Visibility) -> Visibility {
    let modifiers = source_modifiers(node, source);
    if modifiers.contains(&"public") {
        Visibility::Public
    } else if modifiers.contains(&"protected") {
        Visibility::Protected
    } else if modifiers.contains(&"private") {
        Visibility::Private
    } else {
        default
    }
}

fn restrict_visibility(declared: Visibility, enclosing: Visibility) -> Visibility {
    match (declared, enclosing) {
        (Visibility::Private, _) | (_, Visibility::Private) => Visibility::Private,
        (Visibility::Package, _) | (_, Visibility::Package) => Visibility::Package,
        (Visibility::Protected, _) | (_, Visibility::Protected) => Visibility::Protected,
        _ => Visibility::Public,
    }
}

fn source_type_kind(kind: &str) -> Option<TypeKind> {
    match kind {
        "class_declaration" => Some(TypeKind::Class),
        "interface_declaration" => Some(TypeKind::Interface),
        "enum_declaration" => Some(TypeKind::Enum),
        "annotation_type_declaration" => Some(TypeKind::Annotation),
        "record_declaration" => Some(TypeKind::Record),
        _ => None,
    }
}

fn is_source_type_node(kind: &str) -> bool {
    matches!(
        kind,
        "type_identifier"
            | "scoped_type_identifier"
            | "generic_type"
            | "array_type"
            | "annotated_type"
            | "integral_type"
            | "floating_point_type"
            | "boolean_type"
            | "primitive_type"
            | "wildcard"
    )
}

fn compact_type_name(name: &str) -> String {
    name.chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}

struct SourceTypeResolution<'a> {
    package_name: String,
    explicit_imports: HashMap<String, String>,
    wildcard_imports: Vec<String>,
    known_types: &'a HashSet<String>,
}

impl<'a> SourceTypeResolution<'a> {
    fn new(
        root: Node<'_>,
        source: &str,
        package_name: String,
        known_types: &'a HashSet<String>,
    ) -> Self {
        let mut explicit_imports = HashMap::default();
        let mut wildcard_imports = Vec::new();
        for index in 0..root.named_child_count() {
            let Some(import) = root.named_child(index) else {
                continue;
            };
            if import.kind() != "import_declaration"
                || (0..import.child_count())
                    .filter_map(|index| import.child(index))
                    .any(|child| child.kind() == "static")
            {
                continue;
            }
            let imported_name = (0..import.named_child_count())
                .filter_map(|index| import.named_child(index))
                .find(|child| matches!(child.kind(), "identifier" | "scoped_identifier"));
            let Some(imported_name) = imported_name else {
                continue;
            };
            let qualified = compact_type_name(node_text(imported_name, source));
            let wildcard = (0..import.named_child_count())
                .filter_map(|index| import.named_child(index))
                .any(|child| child.kind() == "asterisk");
            if wildcard {
                wildcard_imports.push(qualified);
            } else if let Some(simple) = terminal_identifier(imported_name, source) {
                explicit_imports.insert(simple, qualified);
            }
        }
        Self {
            package_name,
            explicit_imports,
            wildcard_imports,
            known_types,
        }
    }

    fn resolve(&self, name: &str) -> Option<String> {
        if name.contains('.') {
            return Some(name.to_owned());
        }
        if let Some(imported) = self.explicit_imports.get(name) {
            return Some(imported.clone());
        }
        let same_package = if self.package_name.is_empty() {
            name.to_owned()
        } else {
            format!("{}.{name}", self.package_name)
        };
        if self.known_types.contains(&same_package) {
            return Some(same_package);
        }
        if JAVA_LANG_TYPES.contains(&name) {
            return Some(format!("java.lang.{name}"));
        }
        let mut candidates = self
            .wildcard_imports
            .iter()
            .map(|package| format!("{package}.{name}"))
            .filter(|candidate| self.known_types.contains(candidate));
        let candidate = candidates.next()?;
        candidates.next().is_none().then_some(candidate)
    }
}

const JAVA_LANG_TYPES: &[&str] = &[
    "Boolean",
    "Byte",
    "Character",
    "Class",
    "ClassLoader",
    "Cloneable",
    "Comparable",
    "Double",
    "Enum",
    "Error",
    "Exception",
    "Float",
    "Integer",
    "Iterable",
    "Long",
    "Math",
    "Number",
    "Object",
    "Record",
    "RuntimeException",
    "Short",
    "String",
    "StringBuilder",
    "System",
    "Thread",
    "Throwable",
    "Void",
];

fn terminal_identifier(node: Node<'_>, source: &str) -> Option<String> {
    let mut current = node;
    loop {
        if current.kind() == "identifier" {
            return Some(node_text(current, source).trim().to_owned());
        }
        current = current
            .child_by_field_name("name")
            .or_else(|| current.named_child(current.named_child_count().checked_sub(1)?))?;
    }
}

pub(super) struct JavaSourceDeclarationIndex {
    pub(super) package_name: String,
    pub(super) type_names: Vec<String>,
}

pub(super) fn source_declaration_index(source: &str) -> Option<JavaSourceDeclarationIndex> {
    let tree = parse_tree(source)?;
    let root = tree.root_node();
    let package_name = determine_package_name(root, source);
    let mut result = Vec::new();
    let mut stack = Vec::new();
    for index in (0..root.named_child_count()).rev() {
        if let Some(node) = root.named_child(index)
            && source_type_kind(node.kind()).is_some()
        {
            stack.push((node, None::<String>));
        }
    }
    while let Some((node, parent)) = stack.pop() {
        let Some(name_node) = node.child_by_field_name("name") else {
            continue;
        };
        let simple = node_text(name_node, source).trim();
        let nested = parent
            .as_deref()
            .map(|parent| format!("{parent}.{simple}"))
            .unwrap_or_else(|| simple.to_owned());
        result.push(if package_name.is_empty() {
            nested.clone()
        } else {
            format!("{package_name}.{nested}")
        });
        if let Some(body) = node.child_by_field_name("body") {
            for index in (0..body.named_child_count()).rev() {
                if let Some(child) = body.named_child(index)
                    && source_type_kind(child.kind()).is_some()
                {
                    stack.push((child, Some(nested.clone())));
                }
            }
        }
    }
    Some(JavaSourceDeclarationIndex {
        package_name,
        type_names: result,
    })
}

pub(super) fn source_declared_type_names(source: &str) -> Vec<String> {
    source_declaration_index(source)
        .map(|index| index.type_names)
        .unwrap_or_default()
}

enum ClassEntryResult {
    Declaration(JavaApiType),
    Skipped,
    Invalid,
}

fn class_api_type(
    jar_name: &str,
    class_entry: &str,
    bytes: &[u8],
    max_depth: usize,
    remaining_records: &mut usize,
    record_limit_hit: &mut bool,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> ClassEntryResult {
    if !take_record(remaining_records, record_limit_hit) {
        return ClassEntryResult::Skipped;
    }
    let Ok(class_file) = jclassfile::class_file::parse(bytes) else {
        return ClassEntryResult::Invalid;
    };
    let flags = class_file.access_flags();
    if flags.contains(ClassFlags::ACC_MODULE) {
        return ClassEntryResult::Skipped;
    }
    let Some(internal_name) = class_name_at(&class_file, class_file.this_class()) else {
        return ClassEntryResult::Invalid;
    };
    let name = binary_declared_class_name(&class_file, &internal_name);
    let visibility = binary_class_visibility(&class_file, &internal_name);
    let class_signature =
        signature_attribute(class_file.attributes(), &class_file).and_then(|signature| {
            let mut cursor = SignatureCursor::new(signature.as_bytes(), max_depth);
            cursor.parse_class_signature().filter(|_| cursor.at_end())
        });
    let class_signature_decoded = class_signature.is_some();
    let (type_parameters, mut hierarchy) = match class_signature {
        Some(value) => value,
        None => {
            let mut hierarchy = Vec::new();
            if class_file.super_class() != 0
                && let Some(superclass) = class_name_at(&class_file, class_file.super_class())
                && superclass != "java/lang/Object"
                && superclass != "java/lang/Enum"
                && superclass != "java/lang/Record"
            {
                hierarchy.push(HierarchyFact {
                    hierarchy_kind: HierarchyKind::Extends,
                    target: named_type(binary_declared_class_name(&class_file, &superclass)),
                    declaration_ordinal: None,
                });
            }
            for interface in class_file.interfaces() {
                if let Some(interface) = class_name_at(&class_file, *interface) {
                    hierarchy.push(HierarchyFact {
                        hierarchy_kind: HierarchyKind::Implements,
                        target: named_type(binary_declared_class_name(&class_file, &interface)),
                        declaration_ordinal: None,
                    });
                }
            }
            (Vec::new(), hierarchy)
        }
    };
    for relation in &mut hierarchy {
        normalize_binary_type_ref(&mut relation.target, &class_file);
    }
    if signature_attribute(class_file.attributes(), &class_file).is_some()
        && !class_signature_decoded
    {
        diagnostics.warning(
            "java.class.unsupported_signature",
            Some(class_entry.to_owned()),
            "could not fully decode generic class signature; erased hierarchy was retained",
        );
    }
    let mut members = Vec::new();
    for field in class_file.fields() {
        if let Some(member) = class_field_member(
            jar_name,
            class_entry,
            &name,
            &class_file,
            field,
            max_depth,
            diagnostics,
        ) {
            if !take_record(remaining_records, record_limit_hit) {
                break;
            }
            members.push(member);
        }
    }
    for method in class_file.methods() {
        if *record_limit_hit {
            break;
        }
        if let Some(member) = class_method_member(
            jar_name,
            class_entry,
            &name,
            &class_file,
            method,
            max_depth,
            diagnostics,
        ) {
            if !take_record(remaining_records, record_limit_hit) {
                break;
            }
            members.push(member);
        }
    }
    let type_kind = if class_file
        .attributes()
        .iter()
        .any(|attribute| matches!(attribute, Attribute::Record { .. }))
    {
        TypeKind::Record
    } else if flags.contains(ClassFlags::ACC_ANNOTATION) {
        TypeKind::Annotation
    } else if flags.contains(ClassFlags::ACC_ENUM) {
        TypeKind::Enum
    } else if flags.contains(ClassFlags::ACC_INTERFACE) {
        TypeKind::Interface
    } else {
        TypeKind::Class
    };
    ClassEntryResult::Declaration(JavaApiType {
        name: name.clone(),
        package_name: internal_name
            .rsplit_once('/')
            .map_or_else(String::new, |(package, _)| package.replace('/', ".")),
        type_kind,
        visibility,
        is_abstract: flags.contains(ClassFlags::ACC_ABSTRACT),
        is_sealed: flags.contains(ClassFlags::ACC_FINAL),
        type_parameters,
        hierarchy,
        locator: Locator::Artifact {
            path: jar_name.to_owned(),
            symbol: class_entry.to_owned(),
        },
        members,
    })
}

fn take_record(remaining_records: &mut usize, record_limit_hit: &mut bool) -> bool {
    if *remaining_records == 0 {
        *record_limit_hit = true;
        return false;
    }
    *remaining_records -= 1;
    true
}

#[allow(clippy::too_many_arguments)]
fn class_field_member(
    jar_name: &str,
    class_entry: &str,
    owner_name: &str,
    class_file: &ClassFile,
    field: &FieldInfo,
    max_depth: usize,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Option<JavaApiMember> {
    let flags = field.access_flags();
    let visibility = field_visibility(flags);
    if !matches!(visibility, Visibility::Public | Visibility::Protected)
        || flags.contains(FieldFlags::ACC_SYNTHETIC)
    {
        return None;
    }
    let name = utf8_at(class_file, field.name_index())?.to_owned();
    let descriptor = utf8_at(class_file, field.descriptor_index())?;
    let mut decoded = signature_attribute(field.attributes(), class_file).and_then(|signature| {
        let mut cursor = SignatureCursor::new(signature.as_bytes(), max_depth);
        cursor.parse_type(0).filter(|_| cursor.at_end())
    });
    if decoded.is_none() {
        let mut cursor = SignatureCursor::new(descriptor.as_bytes(), max_depth);
        decoded = cursor.parse_type(0).filter(|_| cursor.at_end());
    }
    let Some(mut field_type) = decoded else {
        diagnostics.warning(
            "java.class.unsupported_field_signature",
            Some(class_entry.to_owned()),
            format!("could not decode field signature for {owner_name}.{name}"),
        );
        return None;
    };
    normalize_binary_type_ref(&mut field_type, class_file);
    Some(JavaApiMember {
        name: name.clone(),
        member_kind: if flags.contains(FieldFlags::ACC_FINAL)
            && flags.contains(FieldFlags::ACC_STATIC)
        {
            MemberKind::Constant
        } else {
            MemberKind::Field
        },
        visibility,
        is_static: flags.contains(FieldFlags::ACC_STATIC),
        is_abstract: false,
        is_virtual: false,
        signature: Some(Signature {
            type_parameters: Vec::new(),
            parameters: Vec::new(),
            returns: Some(field_type),
        }),
        locator: Locator::Artifact {
            path: jar_name.to_owned(),
            symbol: format!("{class_entry}#{name}:{descriptor}"),
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn class_method_member(
    jar_name: &str,
    class_entry: &str,
    owner_name: &str,
    class_file: &ClassFile,
    method: &MethodInfo,
    max_depth: usize,
    diagnostics: &mut BoundedProducerDiagnostics,
) -> Option<JavaApiMember> {
    let flags = method.access_flags();
    let visibility = method_visibility(flags);
    if !matches!(visibility, Visibility::Public | Visibility::Protected)
        || flags.intersects(MethodFlags::ACC_SYNTHETIC | MethodFlags::ACC_BRIDGE)
    {
        return None;
    }
    let binary_name = utf8_at(class_file, method.name_index())?;
    if binary_name == "<clinit>" {
        return None;
    }
    let descriptor = utf8_at(class_file, method.descriptor_index())?;
    let generic = signature_attribute(method.attributes(), class_file).and_then(|signature| {
        let mut cursor = SignatureCursor::new(signature.as_bytes(), max_depth);
        cursor.parse_method_signature().filter(|_| cursor.at_end())
    });
    let (type_parameters, mut parameter_types, mut returns) = match generic {
        Some(value) => value,
        None => {
            let mut cursor = SignatureCursor::new(descriptor.as_bytes(), max_depth);
            let Some((parameters, returns)) =
                cursor.parse_method_descriptor().filter(|_| cursor.at_end())
            else {
                diagnostics.warning(
                    "java.class.unsupported_method_signature",
                    Some(class_entry.to_owned()),
                    format!("could not decode method signature for {owner_name}.{binary_name}"),
                );
                return None;
            };
            (Vec::new(), parameters, returns)
        }
    };
    for parameter in &mut parameter_types {
        normalize_binary_type_ref(parameter, class_file);
    }
    if let Some(returns) = &mut returns {
        normalize_binary_type_ref(returns, class_file);
    }
    let parameter_names = method
        .attributes()
        .iter()
        .find_map(|attribute| match attribute {
            Attribute::MethodParameters { parameters } => Some(
                parameters
                    .iter()
                    .map(|parameter| {
                        (parameter.name_index() != 0)
                            .then(|| utf8_at(class_file, parameter.name_index()).map(str::to_owned))
                            .flatten()
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .unwrap_or_default();
    let parameter_count = parameter_types.len();
    let parameters = parameter_types
        .into_iter()
        .enumerate()
        .map(|(index, r#type)| Parameter {
            name: parameter_names.get(index).cloned().flatten(),
            r#type,
            optional: false,
            variadic: flags.contains(MethodFlags::ACC_VARARGS) && index + 1 == parameter_count,
        })
        .collect();
    let constructor = binary_name == "<init>";
    Some(JavaApiMember {
        name: binary_name.to_owned(),
        member_kind: if constructor {
            MemberKind::Constructor
        } else {
            MemberKind::Method
        },
        visibility,
        is_static: flags.contains(MethodFlags::ACC_STATIC),
        is_abstract: flags.contains(MethodFlags::ACC_ABSTRACT),
        is_virtual: !constructor
            && !flags.contains(MethodFlags::ACC_STATIC)
            && !flags.contains(MethodFlags::ACC_FINAL),
        signature: Some(Signature {
            type_parameters,
            parameters,
            returns,
        }),
        locator: Locator::Artifact {
            path: jar_name.to_owned(),
            symbol: format!("{class_entry}#{binary_name}{descriptor}"),
        },
    })
}

fn signature_attribute<'a>(attributes: &[Attribute], class_file: &'a ClassFile) -> Option<&'a str> {
    attributes.iter().find_map(|attribute| match attribute {
        Attribute::Signature { signature_index } => utf8_at(class_file, *signature_index),
        _ => None,
    })
}

fn utf8_at(class_file: &ClassFile, index: u16) -> Option<&str> {
    let ConstantPool::Utf8 { value } = class_file.constant_pool().get(index as usize)? else {
        return None;
    };
    Some(value)
}

fn class_name_at(class_file: &ClassFile, index: u16) -> Option<String> {
    let ConstantPool::Class { name_index } = class_file.constant_pool().get(index as usize)? else {
        return None;
    };
    utf8_at(class_file, *name_index).map(str::to_owned)
}

fn binary_declared_class_name(class_file: &ClassFile, internal_name: &str) -> String {
    for attribute in class_file.attributes() {
        let Attribute::InnerClasses { classes } = attribute else {
            continue;
        };
        for class in classes {
            let Some(candidate) = class_name_at(class_file, class.inner_class_info_index()) else {
                continue;
            };
            if candidate != internal_name
                || class.outer_class_info_index() == 0
                || class.inner_name_index() == 0
            {
                continue;
            }
            let Some(outer) = class_name_at(class_file, class.outer_class_info_index()) else {
                continue;
            };
            let Some(inner) = utf8_at(class_file, class.inner_name_index()) else {
                continue;
            };
            return format!(
                "{}.{}",
                binary_declared_class_name(class_file, &outer),
                inner
            );
        }
    }
    internal_name.replace('/', ".")
}

fn normalize_binary_type_ref(r#type: &mut TypeRef, class_file: &ClassFile) {
    match r#type {
        TypeRef::Named {
            name, arguments, ..
        } => {
            let internal_name = name.replace('.', "/");
            *name = binary_declared_class_name(class_file, &internal_name);
            for argument in arguments {
                normalize_binary_type_ref(argument, class_file);
            }
        }
        TypeRef::Array { element }
        | TypeRef::ByRef { element }
        | TypeRef::Pointer { element }
        | TypeRef::Slice { element }
        | TypeRef::FixedArray { element, .. }
        | TypeRef::Channel { element, .. } => {
            normalize_binary_type_ref(element, class_file);
        }
        TypeRef::Map { key, value } => {
            normalize_binary_type_ref(key, class_file);
            normalize_binary_type_ref(value, class_file);
        }
        TypeRef::Wildcard { bound, .. } => {
            if let Some(bound) = bound {
                normalize_binary_type_ref(bound, class_file);
            }
        }
        TypeRef::Tuple { elements } => {
            for element in elements {
                normalize_binary_type_ref(element, class_file);
            }
        }
        TypeRef::Function { parameters, result } => {
            for parameter in parameters {
                normalize_binary_type_ref(&mut parameter.r#type, class_file);
            }
            if let Some(result) = result {
                normalize_binary_type_ref(result, class_file);
            }
        }
        TypeRef::Declared { .. } | TypeRef::TypeParameter { .. } => {}
    }
}

fn binary_class_visibility(class_file: &ClassFile, internal_name: &str) -> Visibility {
    let mut visibility = if class_file.access_flags().contains(ClassFlags::ACC_PUBLIC) {
        Visibility::Public
    } else {
        Visibility::Package
    };
    for attribute in class_file.attributes() {
        let Attribute::InnerClasses { classes } = attribute else {
            continue;
        };
        for class in classes {
            let Some(inner_name) = class_name_at(class_file, class.inner_class_info_index()) else {
                continue;
            };
            if inner_name == internal_name {
                visibility = nested_visibility(class.inner_class_access_flags());
            }
        }
    }
    visibility
}

fn nested_visibility(flags: &NestedClassFlags) -> Visibility {
    if flags.contains(NestedClassFlags::ACC_PUBLIC) {
        Visibility::Public
    } else if flags.contains(NestedClassFlags::ACC_PROTECTED) {
        Visibility::Protected
    } else if flags.contains(NestedClassFlags::ACC_PRIVATE) {
        Visibility::Private
    } else {
        Visibility::Package
    }
}

fn field_visibility(flags: &FieldFlags) -> Visibility {
    if flags.contains(FieldFlags::ACC_PUBLIC) {
        Visibility::Public
    } else if flags.contains(FieldFlags::ACC_PROTECTED) {
        Visibility::Protected
    } else if flags.contains(FieldFlags::ACC_PRIVATE) {
        Visibility::Private
    } else {
        Visibility::Package
    }
}

fn method_visibility(flags: &MethodFlags) -> Visibility {
    if flags.contains(MethodFlags::ACC_PUBLIC) {
        Visibility::Public
    } else if flags.contains(MethodFlags::ACC_PROTECTED) {
        Visibility::Protected
    } else if flags.contains(MethodFlags::ACC_PRIVATE) {
        Visibility::Private
    } else {
        Visibility::Package
    }
}

fn named_type(name: String) -> TypeRef {
    TypeRef::Named {
        name,
        arguments: Vec::new(),
        nullable: false,
    }
}

struct SignatureCursor<'a> {
    bytes: &'a [u8],
    position: usize,
    max_depth: usize,
}

impl<'a> SignatureCursor<'a> {
    fn new(bytes: &'a [u8], max_depth: usize) -> Self {
        Self {
            bytes,
            position: 0,
            max_depth,
        }
    }

    fn at_end(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn take(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        Some(byte)
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() != Some(expected) {
            return false;
        }
        self.position += 1;
        true
    }

    fn parse_class_signature(&mut self) -> Option<(Vec<String>, Vec<HierarchyFact>)> {
        let type_parameters = self.parse_type_parameters(0)?;
        let superclass = self.parse_type(0)?;
        let mut hierarchy = Vec::new();
        if !matches!(&superclass, TypeRef::Named { name, .. } if name == "java.lang.Object") {
            hierarchy.push(HierarchyFact {
                hierarchy_kind: HierarchyKind::Extends,
                target: superclass,
                declaration_ordinal: None,
            });
        }
        while !self.at_end() {
            hierarchy.push(HierarchyFact {
                hierarchy_kind: HierarchyKind::Implements,
                target: self.parse_type(0)?,
                declaration_ordinal: None,
            });
        }
        Some((type_parameters, hierarchy))
    }

    fn parse_method_signature(&mut self) -> Option<(Vec<String>, Vec<TypeRef>, Option<TypeRef>)> {
        let type_parameters = self.parse_type_parameters(0)?;
        let (parameters, returns) = self.parse_method_descriptor()?;
        while self.consume(b'^') {
            self.parse_type(0)?;
        }
        Some((type_parameters, parameters, returns))
    }

    fn parse_method_descriptor(&mut self) -> Option<(Vec<TypeRef>, Option<TypeRef>)> {
        if !self.consume(b'(') {
            return None;
        }
        let mut parameters = Vec::new();
        while self.peek()? != b')' {
            parameters.push(self.parse_type(0)?);
        }
        self.take();
        let returns = if self.consume(b'V') {
            None
        } else {
            Some(self.parse_type(0)?)
        };
        Some((parameters, returns))
    }

    fn parse_type_parameters(&mut self, depth: usize) -> Option<Vec<String>> {
        if !self.consume(b'<') {
            return Some(Vec::new());
        }
        if depth >= self.max_depth {
            return None;
        }
        let mut parameters = Vec::new();
        while self.peek()? != b'>' {
            let start = self.position;
            while self.peek()? != b':' {
                self.position += 1;
            }
            let name = std::str::from_utf8(self.bytes.get(start..self.position)?)
                .ok()?
                .to_owned();
            if name.is_empty() {
                return None;
            }
            parameters.push(name);
            self.take();
            if self.peek()? != b':' {
                self.parse_type(depth + 1)?;
            }
            while self.consume(b':') {
                self.parse_type(depth + 1)?;
            }
        }
        self.take();
        Some(parameters)
    }

    fn parse_type(&mut self, depth: usize) -> Option<TypeRef> {
        if depth >= self.max_depth {
            return None;
        }
        match self.take()? {
            b'B' => Some(named_type("byte".to_owned())),
            b'C' => Some(named_type("char".to_owned())),
            b'D' => Some(named_type("double".to_owned())),
            b'F' => Some(named_type("float".to_owned())),
            b'I' => Some(named_type("int".to_owned())),
            b'J' => Some(named_type("long".to_owned())),
            b'S' => Some(named_type("short".to_owned())),
            b'Z' => Some(named_type("boolean".to_owned())),
            b'[' => Some(TypeRef::Array {
                element: Box::new(self.parse_type(depth + 1)?),
            }),
            b'T' => {
                let name = self.parse_identifier_until(b';')?;
                Some(TypeRef::TypeParameter { name })
            }
            b'L' => self.parse_class_type(depth + 1),
            _ => None,
        }
    }

    fn parse_class_type(&mut self, depth: usize) -> Option<TypeRef> {
        if depth >= self.max_depth {
            return None;
        }
        let mut name = String::new();
        let mut arguments = Vec::new();
        loop {
            match self.peek()? {
                b';' => {
                    self.take();
                    break;
                }
                b'<' => {
                    self.take();
                    while self.peek()? != b'>' {
                        match self.peek()? {
                            b'*' => {
                                self.take();
                                arguments.push(TypeRef::Wildcard {
                                    variance: WildcardVariance::Any,
                                    bound: None,
                                });
                            }
                            b'+' => {
                                self.take();
                                arguments.push(TypeRef::Wildcard {
                                    variance: WildcardVariance::Extends,
                                    bound: Some(Box::new(self.parse_type(depth + 1)?)),
                                });
                            }
                            b'-' => {
                                self.take();
                                arguments.push(TypeRef::Wildcard {
                                    variance: WildcardVariance::Super,
                                    bound: Some(Box::new(self.parse_type(depth + 1)?)),
                                });
                            }
                            _ => arguments.push(self.parse_type(depth + 1)?),
                        }
                    }
                    self.take();
                }
                b'/' | b'.' => {
                    self.take();
                    name.push('.');
                }
                b'$' => {
                    self.take();
                    name.push('$');
                }
                byte if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') => {
                    self.take();
                    name.push(byte as char);
                }
                _ => return None,
            }
        }
        (!name.is_empty()).then_some(TypeRef::Named {
            name,
            arguments,
            nullable: false,
        })
    }

    fn parse_identifier_until(&mut self, delimiter: u8) -> Option<String> {
        let start = self.position;
        while self.peek()? != delimiter {
            self.position += 1;
        }
        let value = std::str::from_utf8(self.bytes.get(start..self.position)?)
            .ok()?
            .to_owned();
        self.take();
        (!value.is_empty()).then_some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        ActivationSelector, Compatibility, CompilerOptions, NameSelector, Provenance, Safety,
        compile_pack,
    };
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use zip::write::SimpleFileOptions;

    const SURFACE_SOURCE: &str = "package fixture.api;\n\
        import java.util.List;\n\
        public class Surface<T> extends Base implements Contract {\n\
          public T value;\n\
          public Surface() {}\n\
          protected List<T> copy(T input) { return null; }\n\
          public <U> U convert(U value) { return value; }\n\
          public void arrays(int value) {}\n\
          public void arrays(int[] value) {}\n\
          public void arrays(int[][] value) {}\n\
          public void spread() {}\n\
          public void spread(String... values) {}\n\
          public static class Nested {}\n\
          private static class Hidden { public static class Leaks {} }\n\
        }\n";
    const BASE_SOURCE: &str = "package fixture.api; public class Base {}\n";
    const CONTRACT_SOURCE: &str = "package fixture.api; public interface Contract {}\n";
    const PAIR_SOURCE: &str =
        "package fixture.api; public record Pair(String name, int count) {}\n";
    const FLAVOR_SOURCE: &str = "package fixture.api; public enum Flavor { VANILLA }\n";
    const DOLLAR_SOURCE: &str = "package fixture.api; public class Dollar$Type { public Dollar$Type self() { return this; } }\n";

    struct JavaFixture {
        _temp: tempfile::TempDir,
        source_jar: PathBuf,
        class_jar: PathBuf,
    }

    impl JavaFixture {
        fn new() -> Self {
            assert!(
                tool_available("javac") && tool_available("jar"),
                "Java producer parity tests require javac and jar"
            );
            let temp = tempfile::tempdir().unwrap();
            let source_root = temp.path().join("src");
            let package_root = source_root.join("fixture/api");
            let classes = temp.path().join("classes");
            fs::create_dir_all(&package_root).unwrap();
            fs::create_dir(&classes).unwrap();
            fs::write(package_root.join("Surface.java"), SURFACE_SOURCE).unwrap();
            fs::write(package_root.join("Base.java"), BASE_SOURCE).unwrap();
            fs::write(package_root.join("Contract.java"), CONTRACT_SOURCE).unwrap();
            fs::write(package_root.join("Pair.java"), PAIR_SOURCE).unwrap();
            fs::write(package_root.join("Flavor.java"), FLAVOR_SOURCE).unwrap();
            fs::write(package_root.join("Dollar$Type.java"), DOLLAR_SOURCE).unwrap();
            let source_jar = temp.path().join("fixture-sources.jar");
            write_source_jar(&source_jar);
            run(Command::new("javac")
                .arg("-parameters")
                .arg("-d")
                .arg(&classes)
                .arg(package_root.join("Surface.java"))
                .arg(package_root.join("Base.java"))
                .arg(package_root.join("Contract.java"))
                .arg(package_root.join("Pair.java"))
                .arg(package_root.join("Flavor.java"))
                .arg(package_root.join("Dollar$Type.java")));
            let class_jar = temp.path().join("fixture.jar");
            run(Command::new("jar")
                .current_dir(&classes)
                .arg("cf")
                .arg(&class_jar)
                .arg("."));
            Self {
                _temp: temp,
                source_jar,
                class_jar,
            }
        }
    }

    fn request(path: PathBuf, artifact_kind: ExternalArtifactKind) -> ArtifactProductionRequest {
        ArtifactProductionRequest {
            path,
            artifact_kind,
            pack_id: "fixture.java-api".to_owned(),
            pack_version: "1.0.0".to_owned(),
            ecosystem: "maven".to_owned(),
            compatibility: Compatibility {
                bifrost: ">=0.8.0, <1.0.0".to_owned(),
                toolchains: Vec::new(),
            },
            activation: vec![ActivationSelector {
                package: Some(NameSelector {
                    name: "fixture:java-api".to_owned(),
                    version: Some("1.0.0".to_owned()),
                }),
                module: None,
                toolchain: None,
                targets: Vec::new(),
                configurations: Vec::new(),
                artifact_sha256: None,
            }],
            provenance: Provenance {
                source: "generated fixture".to_owned(),
                revision: None,
            },
            license: "MIT".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
        }
    }

    #[test]
    fn source_and_class_jars_share_declaration_ids_and_keep_distinct_origins() {
        let fixture = JavaFixture::new();
        let source = JavaJarPackProducer.produce_exact_artifact(
            &request(
                fixture.source_jar.clone(),
                ExternalArtifactKind::JavaSourceJar,
            ),
            &ArtifactProducerLimits::default(),
        );
        let class = JavaJarPackProducer.produce_exact_artifact(
            &request(
                fixture.class_jar.clone(),
                ExternalArtifactKind::JavaClassJar,
            ),
            &ArtifactProducerLimits::default(),
        );
        assert_eq!(
            source.completeness,
            Completeness::Complete,
            "{:?}",
            source.diagnostics
        );
        assert!(source.diagnostics.is_empty(), "{:?}", source.diagnostics);
        assert_eq!(
            class.completeness,
            Completeness::Complete,
            "{:?}",
            class.diagnostics
        );
        assert!(class.diagnostics.is_empty(), "{:?}", class.diagnostics);
        let source_pack = source.pack.as_ref().unwrap();
        let class_pack = class.pack.as_ref().unwrap();
        compile_pack(source_pack, &CompilerOptions::default()).unwrap();
        compile_pack(class_pack, &CompilerOptions::default()).unwrap();
        let (source_types, source_members) = declarations(source_pack);
        let (class_types, class_members) = declarations(class_pack);

        let source_surface = source_types
            .iter()
            .find(|fact| fact.name == "fixture.api.Surface")
            .unwrap();
        let class_surface = class_types
            .iter()
            .find(|fact| fact.name == "fixture.api.Surface")
            .unwrap();
        assert_eq!(source_surface.id, class_surface.id);
        assert_eq!(source_surface.type_parameters, ["T"]);
        assert_eq!(class_surface.type_parameters, ["T"]);
        assert!(matches!(source_surface.locator, Locator::Source { .. }));
        assert!(matches!(class_surface.locator, Locator::Artifact { .. }));
        assert!(!source_types.iter().any(|fact| fact.name.contains("Hidden")));
        assert!(!class_types.iter().any(|fact| fact.name.contains("Hidden")));

        for member_name in ["<init>", "value", "copy", "convert"] {
            let source_member = source_members
                .iter()
                .find(|fact| fact.owner == source_surface.id && fact.name == member_name)
                .unwrap_or_else(|| panic!("missing source member {member_name}"));
            let class_member = class_members
                .iter()
                .find(|fact| fact.owner == class_surface.id && fact.name == member_name)
                .unwrap_or_else(|| panic!("missing class member {member_name}"));
            assert_eq!(
                source_member.id, class_member.id,
                "identity mismatch for {member_name}: source={:?}, class={:?}",
                source_member.signature, class_member.signature
            );
        }
        for (type_name, member_names) in [
            (
                "fixture.api.Pair",
                &["<init>", "name", "count", "equals", "hashCode", "toString"][..],
            ),
            ("fixture.api.Flavor", &["values", "valueOf"][..]),
            ("fixture.api.Dollar$Type", &["<init>", "self"][..]),
        ] {
            let source_type = source_types
                .iter()
                .find(|fact| fact.name == type_name)
                .unwrap();
            let class_type = class_types
                .iter()
                .find(|fact| fact.name == type_name)
                .unwrap();
            assert_eq!(source_type.id, class_type.id);
            for member_name in member_names {
                let source_member = source_members
                    .iter()
                    .find(|fact| fact.owner == source_type.id && fact.name == *member_name)
                    .unwrap_or_else(|| panic!("missing source member {type_name}.{member_name}"));
                let class_member = class_members
                    .iter()
                    .find(|fact| fact.owner == class_type.id && fact.name == *member_name)
                    .unwrap_or_else(|| panic!("missing class member {type_name}.{member_name}"));
                assert_eq!(
                    source_member.id, class_member.id,
                    "identity mismatch for {type_name}.{member_name}: source={:?}, class={:?}",
                    source_member.signature, class_member.signature
                );
            }
        }
    }

    #[test]
    fn signature_cursor_is_depth_bounded() {
        let mut cursor = SignatureCursor::new(b"[[[[I", 3);
        assert!(cursor.parse_type(0).is_none());
    }

    #[test]
    fn source_jar_limits_and_diagnostics_are_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let source_jar = temp.path().join("fixture-sources.jar");
        write_source_jar(&source_jar);
        let limited = JavaJarPackProducer.produce_exact_artifact(
            &request(source_jar, ExternalArtifactKind::JavaSourceJar),
            &ArtifactProducerLimits {
                max_records: 1,
                ..ArtifactProducerLimits::default()
            },
        );
        assert_eq!(limited.completeness, Completeness::Partial);
        assert!(limited.pack.is_some());
        assert!(
            limited
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "limit.records")
        );

        let invalid_jar = temp.path().join("invalid-sources.jar");
        let file = fs::File::create(&invalid_jar).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        for index in 0..3 {
            zip.start_file(
                format!("fixture/Invalid{index}.java"),
                SimpleFileOptions::default(),
            )
            .unwrap();
            zip.write_all(&[0xff]).unwrap();
        }
        zip.finish().unwrap();
        let invalid = JavaJarPackProducer.produce_exact_artifact(
            &request(invalid_jar, ExternalArtifactKind::JavaSourceJar),
            &ArtifactProducerLimits {
                max_diagnostics: 1,
                ..ArtifactProducerLimits::default()
            },
        );
        assert_eq!(invalid.diagnostics.len(), 1);
        assert!(invalid.suppressed_diagnostics >= 2);
        assert!(invalid.pack.is_none());
    }

    #[test]
    fn malformed_jar_returns_one_failed_production() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp.path(), b"not a jar").unwrap();
        let production = JavaJarPackProducer.produce_exact_artifact(
            &request(
                temp.path().to_path_buf(),
                ExternalArtifactKind::JavaClassJar,
            ),
            &ArtifactProducerLimits::default(),
        );
        assert!(production.pack.is_none());
        assert!(matches!(
            production.diagnostics[0].code.as_str(),
            "java.archive.invalid" | "limit.archive_directory"
        ));
    }

    fn declarations(pack: &AuthoredSemanticModelPack) -> (&[TypeFact], &[MemberFact]) {
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &pack.shards[0].payload
        else {
            panic!("Java producer must emit declarations");
        };
        (types, members)
    }

    fn write_source_jar(path: &Path) {
        let file = fs::File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        for (name, source) in [
            ("fixture/api/Surface.java", SURFACE_SOURCE),
            ("fixture/api/Base.java", BASE_SOURCE),
            ("fixture/api/Contract.java", CONTRACT_SOURCE),
            ("fixture/api/Pair.java", PAIR_SOURCE),
            ("fixture/api/Flavor.java", FLAVOR_SOURCE),
            ("fixture/api/Dollar$Type.java", DOLLAR_SOURCE),
        ] {
            zip.start_file(name, SimpleFileOptions::default()).unwrap();
            zip.write_all(source.as_bytes()).unwrap();
        }
        zip.finish().unwrap();
    }

    fn tool_available(tool: &str) -> bool {
        Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn run(command: &mut Command) {
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "command failed: {command:?}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
