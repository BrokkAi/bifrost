use super::java_artifact::{
    MAX_SOURCE_ENTRY_BYTES, ZipDirectoryStatus, apply_enclosing_visibility, java_api_facts,
    source_api_types, source_declaration_index, zip_directory_status_with_limits,
};
use crate::CancellationToken;
use crate::analyzer::semantic_model::{
    ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest, AuthoredPayload,
    AuthoredSemanticModelPack, AuthoredShard, BoundedProducerDiagnostics, Completeness,
    ExternalArtifactKind, ExternalArtifactPackProducer, NameSelector, Producer, ProducerDiagnostic,
    ProducerDiagnosticSeverity, Visibility, read_exact_artifact_while,
};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_jvm::java::declarations::{node_text, parse_tree};
use std::io::{Cursor, Read};
use std::path::{Component, Path};
use zip::ZipArchive;

const MAX_JDK_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_JDK_TOTAL_SOURCE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_JDK_CENTRAL_DIRECTORY_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JdkSourceArchiveLayout {
    ModulePrefixed,
    Flat,
}

#[derive(Debug, Clone, Copy)]
pub struct JdkSourceArchivePackProducer {
    layout: JdkSourceArchiveLayout,
}

impl JdkSourceArchivePackProducer {
    pub const fn new(layout: JdkSourceArchiveLayout) -> Self {
        Self { layout }
    }

    fn produce(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
    ) -> ArtifactProduction {
        if request.artifact_kind != ExternalArtifactKind::JdkSourceZip {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "artifact.kind".to_owned(),
                    location: None,
                    message: "JDK producer requires a JDK source ZIP artifact".to_owned(),
                },
                limits,
            );
        }
        if request.activation.is_empty() {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "jdk.activation.missing".to_owned(),
                    location: None,
                    message: "JDK production requires an exact toolchain activation selector"
                        .to_owned(),
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
        artifact: &crate::analyzer::semantic_model::ExactArtifact,
    ) -> ArtifactProduction {
        if zip_directory_status_with_limits(
            artifact.bytes(),
            MAX_JDK_ARCHIVE_ENTRIES,
            MAX_JDK_CENTRAL_DIRECTORY_BYTES,
        ) == ZipDirectoryStatus::Exceeded
        {
            return ArtifactProduction::failed(
                ProducerDiagnostic {
                    severity: ProducerDiagnosticSeverity::Error,
                    code: "limit.archive_directory".to_owned(),
                    location: None,
                    message: "JDK ZIP central directory exceeds bounded entry or byte limits"
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
                        code: "jdk.archive.invalid".to_owned(),
                        location: None,
                        message: "artifact is not a readable JDK source ZIP".to_owned(),
                    },
                    limits,
                );
            }
        };
        let mut diagnostics = BoundedProducerDiagnostics::new(limits);
        let mut entries = Vec::new();
        let mut module_markers = HashSet::default();
        let mut exports_by_module = HashMap::default();
        let mut layout_error = false;
        let mut total_bytes = 0u64;
        let entry_limit = archive.len().min(MAX_JDK_ARCHIVE_ENTRIES);
        if archive.len() > MAX_JDK_ARCHIVE_ENTRIES {
            diagnostics.warning(
                "limit.archive_entries",
                None,
                format!("producer inspected at most {MAX_JDK_ARCHIVE_ENTRIES} archive entries"),
            );
        }
        for index in 0..entry_limit {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return cancelled_production(limits);
            }
            let Ok(mut entry) = archive.by_index(index) else {
                diagnostics.warning(
                    "jdk.archive.entry",
                    None,
                    format!("could not read archive entry at index {index}"),
                );
                continue;
            };
            let entry_name = entry.name().to_owned();
            if !entry_name.ends_with(".java") {
                continue;
            }
            let Some(components) = archive_path_components(&entry_name) else {
                diagnostics.error(
                    "jdk.archive.path",
                    Some(entry_name),
                    "JDK source entry has a non-relative or non-UTF-8 archive path",
                );
                layout_error = true;
                continue;
            };
            let (module, is_module_marker) = match self.layout {
                JdkSourceArchiveLayout::ModulePrefixed => {
                    if components.len() < 2 || !valid_module_name(components[0]) {
                        diagnostics.error(
                            "jdk.layout.module_prefixed",
                            Some(entry_name),
                            "module-prefixed JDK sources require <module>/<source path>.java",
                        );
                        layout_error = true;
                        continue;
                    }
                    let module = components[0].to_owned();
                    let marker = components.len() == 2 && components[1] == "module-info.java";
                    (module, marker)
                }
                JdkSourceArchiveLayout::Flat => {
                    if components.len() == 2 && components[1] == "module-info.java" {
                        diagnostics.error(
                            "jdk.layout.flat",
                            Some(entry_name),
                            "flat JDK sources must not contain module-prefixed module-info.java entries",
                        );
                        layout_error = true;
                        continue;
                    }
                    (
                        "java.base".to_owned(),
                        components.len() == 1 && components[0] == "module-info.java",
                    )
                }
            };
            if is_module_marker {
                let next_total = total_bytes.saturating_add(entry.size());
                if entry.size() > MAX_SOURCE_ENTRY_BYTES || next_total > MAX_JDK_TOTAL_SOURCE_BYTES
                {
                    diagnostics.error(
                        "jdk.module_info.bytes",
                        Some(entry_name),
                        "module-info.java exceeded the bounded JDK source extraction budget",
                    );
                    layout_error = true;
                    continue;
                }
                total_bytes = next_total;
                let mut source = String::new();
                if entry
                    .by_ref()
                    .take(MAX_SOURCE_ENTRY_BYTES.saturating_add(1))
                    .read_to_string(&mut source)
                    .is_err()
                    || source.len() as u64 > MAX_SOURCE_ENTRY_BYTES
                {
                    diagnostics.error(
                        "jdk.module_info.read",
                        Some(entry_name),
                        "could not read bounded module-info.java source",
                    );
                    layout_error = true;
                    continue;
                }
                let Some(exports) = exported_module_packages(&source) else {
                    diagnostics.error(
                        "jdk.module_info.parse",
                        Some(entry_name),
                        "could not parse module-info.java exports structurally",
                    );
                    layout_error = true;
                    continue;
                };
                module_markers.insert(module.clone());
                exports_by_module.insert(module, exports);
                continue;
            }
            let next_total = total_bytes.saturating_add(entry.size());
            if entry.size() > MAX_SOURCE_ENTRY_BYTES || next_total > MAX_JDK_TOTAL_SOURCE_BYTES {
                diagnostics.warning(
                    "limit.archive_bytes",
                    Some(entry_name),
                    "archive entry exceeded the bounded JDK source extraction budget",
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
                    "jdk.archive.entry_read",
                    Some(entry_name),
                    "could not read bounded JDK source entry bytes",
                );
                continue;
            }
            match String::from_utf8(bytes) {
                Ok(source) => {
                    let Some(declarations) = source_declaration_index(&source) else {
                        diagnostics.warning(
                            "jdk.source.parse",
                            Some(entry_name),
                            "could not index JDK source package and declared names",
                        );
                        continue;
                    };
                    entries.push(JdkSourceEntry {
                        archive_index: index,
                        module,
                        source_path: entry_name,
                        package_name: declarations.package_name,
                        type_names: declarations.type_names,
                    });
                }
                Err(_) => diagnostics.warning(
                    "jdk.source.encoding",
                    Some(entry_name),
                    "JDK source entry is not valid UTF-8",
                ),
            }
        }
        if layout_error {
            return failed_with_diagnostics(artifact.sha256(), diagnostics);
        }
        if self.layout == JdkSourceArchiveLayout::ModulePrefixed {
            let source_modules = entries
                .iter()
                .map(|entry| entry.module.as_str())
                .collect::<HashSet<_>>();
            let missing_markers = source_modules
                .into_iter()
                .filter(|module| !module_markers.contains(*module))
                .collect::<Vec<_>>();
            if !missing_markers.is_empty() {
                diagnostics.error(
                    "jdk.layout.module_marker",
                    None,
                    format!(
                        "module-prefixed JDK sources are missing module-info.java for {missing_markers:?}"
                    ),
                );
                return failed_with_diagnostics(artifact.sha256(), diagnostics);
            }
            entries.retain(|entry| {
                exports_by_module
                    .get(&entry.module)
                    .is_some_and(|exports| exports.contains(&entry.package_name))
            });
        }
        entries.sort_unstable_by(|left, right| {
            (&left.module, &left.source_path).cmp(&(&right.module, &right.source_path))
        });
        let known_types = entries
            .iter()
            .flat_map(|entry| entry.type_names.iter().cloned())
            .collect::<HashSet<_>>();
        let mut by_module = HashMap::<String, Vec<JdkSourceEntry>>::default();
        for entry in entries {
            by_module
                .entry(entry.module.clone())
                .or_default()
                .push(entry);
        }
        let mut modules = by_module.into_iter().collect::<Vec<_>>();
        modules.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let mut remaining_records = limits.max_records;
        let mut record_limit_hit = false;
        let mut shards = Vec::new();
        for (module, entries) in modules {
            let mut declarations = Vec::new();
            for entry in entries {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return cancelled_production(limits);
                }
                let Ok(mut archive_entry) = archive.by_index(entry.archive_index) else {
                    diagnostics.warning(
                        "jdk.archive.entry",
                        Some(entry.source_path),
                        "could not reread JDK source entry for structured production",
                    );
                    continue;
                };
                let mut source = String::new();
                if archive_entry
                    .by_ref()
                    .take(MAX_SOURCE_ENTRY_BYTES.saturating_add(1))
                    .read_to_string(&mut source)
                    .is_err()
                    || source.len() as u64 > MAX_SOURCE_ENTRY_BYTES
                {
                    diagnostics.warning(
                        "jdk.archive.entry_read",
                        Some(entry.source_path),
                        "could not reread bounded JDK source entry bytes",
                    );
                    continue;
                }
                declarations.extend(source_api_types(
                    &entry.source_path,
                    &source,
                    &known_types,
                    limits.max_signature_depth,
                    &mut remaining_records,
                    &mut record_limit_hit,
                    &mut diagnostics,
                ));
            }
            apply_enclosing_visibility(&mut declarations);
            if self.layout == JdkSourceArchiveLayout::ModulePrefixed {
                let exports = exports_by_module
                    .get(&module)
                    .expect("validated source module has a descriptor");
                declarations.retain(|declaration| exports.contains(&declaration.package_name));
            }
            declarations.retain(|declaration| {
                matches!(
                    declaration.visibility,
                    Visibility::Public | Visibility::Protected
                )
            });
            declarations.sort_unstable_by(|left, right| left.name.cmp(&right.name));
            let (types, members) =
                java_api_facts(declarations, limits.max_records, &mut diagnostics);
            if types.is_empty() {
                continue;
            }
            let mut activation = request.activation.clone();
            for selector in &mut activation {
                selector.module = Some(NameSelector {
                    name: module.clone(),
                    version: None,
                });
                selector.artifact_sha256 = Some(artifact.sha256().to_owned());
            }
            shards.push(AuthoredShard {
                id: format!("declarations.jdk.{module}"),
                activation,
                payload: AuthoredPayload::DeclarationFacts {
                    types,
                    members,
                    relations: Vec::new(),
                },
            });
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
        if shards.is_empty() {
            diagnostics.error(
                "jdk.archive.no_external_declarations",
                None,
                "JDK ZIP contains no externally visible Java declarations",
            );
            return failed_with_diagnostics(artifact.sha256(), diagnostics);
        }
        let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
        let completeness = if diagnostics.is_empty() && suppressed_diagnostics == 0 {
            Completeness::Complete
        } else {
            Completeness::Partial
        };
        ArtifactProduction {
            artifact_sha256: Some(artifact.sha256().to_owned()),
            pack: Some(AuthoredSemanticModelPack {
                schema_version: crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
                pack_id: request.pack_id.clone(),
                version: request.pack_version.clone(),
                producer: Producer {
                    name: "bifrost-jdk-source-zip".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                language: "java".to_owned(),
                ecosystem: request.ecosystem.clone(),
                compatibility: request.compatibility.clone(),
                provenance: request.provenance.clone(),
                license: request.license.clone(),
                completeness,
                safety: request.safety.clone(),
                shards,
            }),
            completeness,
            diagnostics,
            suppressed_diagnostics,
        }
    }
}

pub fn detect_jdk_source_archive_layout(
    artifact: &crate::analyzer::semantic_model::ExactArtifact,
) -> Result<JdkSourceArchiveLayout, ProducerDiagnostic> {
    if zip_directory_status_with_limits(
        artifact.bytes(),
        MAX_JDK_ARCHIVE_ENTRIES,
        MAX_JDK_CENTRAL_DIRECTORY_BYTES,
    ) == ZipDirectoryStatus::Exceeded
    {
        return Err(ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: "limit.archive_directory".to_owned(),
            location: Some(artifact.path().to_string_lossy().into_owned()),
            message: "JDK ZIP central directory exceeds bounded entry or byte limits".to_owned(),
        });
    }
    let mut archive =
        ZipArchive::new(Cursor::new(artifact.bytes())).map_err(|_| ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: "jdk.archive.invalid".to_owned(),
            location: Some(artifact.path().to_string_lossy().into_owned()),
            message: "artifact is not a readable JDK source ZIP".to_owned(),
        })?;
    let mut module_prefixed = false;
    let mut flat = false;
    for index in 0..archive.len() {
        let Ok(entry) = archive.by_index(index) else {
            continue;
        };
        let Some(components) = archive_path_components(entry.name()) else {
            continue;
        };
        if components.len() == 1 && components[0] == "module-info.java" {
            flat = true;
        } else if components.len() == 2
            && components[1] == "module-info.java"
            && valid_module_name(components[0])
        {
            module_prefixed = true;
        }
    }
    if module_prefixed && flat {
        return Err(ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: "jdk.layout.ambiguous".to_owned(),
            location: Some(artifact.path().to_string_lossy().into_owned()),
            message: "JDK source ZIP mixes flat and module-prefixed module descriptors".to_owned(),
        });
    }
    Ok(if module_prefixed {
        JdkSourceArchiveLayout::ModulePrefixed
    } else {
        JdkSourceArchiveLayout::Flat
    })
}

impl ExternalArtifactPackProducer for JdkSourceArchivePackProducer {
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

struct JdkSourceEntry {
    archive_index: usize,
    module: String,
    source_path: String,
    package_name: String,
    type_names: Vec<String>,
}

fn archive_path_components(entry_name: &str) -> Option<Vec<&str>> {
    let mut result = Vec::new();
    for component in Path::new(entry_name).components() {
        match component {
            Component::Normal(value) => result.push(value.to_str()?),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!result.is_empty()).then_some(result)
}

fn valid_module_name(name: &str) -> bool {
    let mut segment_start = true;
    for character in name.chars() {
        if character == '.' {
            if segment_start {
                return false;
            }
            segment_start = true;
        } else if segment_start {
            if character != '_' && !character.is_ascii_alphabetic() {
                return false;
            }
            segment_start = false;
        } else if character != '_' && !character.is_ascii_alphanumeric() {
            return false;
        }
    }
    !segment_start
}

fn exported_module_packages(source: &str) -> Option<HashSet<String>> {
    let tree = parse_tree(source)?;
    if tree.root_node().has_error() {
        return None;
    }
    let mut exports = HashSet::default();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "exports_module_directive" {
            if node.child_by_field_name("modules").is_none() {
                let package = node.child_by_field_name("package")?;
                exports.insert(node_text(package, source).trim().to_owned());
            }
            continue;
        }
        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push(child);
            }
        }
    }
    Some(exports)
}

fn cancelled_production(limits: &ArtifactProducerLimits) -> ArtifactProduction {
    ArtifactProduction::failed(
        ProducerDiagnostic {
            severity: ProducerDiagnosticSeverity::Error,
            code: "artifact.cancelled".to_owned(),
            location: None,
            message: "JDK source production was cancelled".to_owned(),
        },
        limits,
    )
}

fn failed_with_diagnostics(
    artifact_sha256: &str,
    diagnostics: BoundedProducerDiagnostics,
) -> ArtifactProduction {
    let (diagnostics, suppressed_diagnostics) = diagnostics.finish();
    ArtifactProduction {
        artifact_sha256: Some(artifact_sha256.to_owned()),
        pack: None,
        completeness: Completeness::Partial,
        diagnostics,
        suppressed_diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic_model::{
        ActivationSelector, Compatibility, CompilerOptions, Provenance, Safety, compile_pack,
    };
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    #[test]
    fn module_prefixed_jdk_sources_produce_independent_module_shards() {
        let fixture = tempdir().unwrap();
        let archive = fixture.path().join("src.zip");
        write_zip(
            &archive,
            &[
                (
                    "java.sql/module-info.java",
                    "module java.sql { exports java.sql; }",
                ),
                (
                    "java.sql/java/sql/Driver.java",
                    "package java.sql; public interface Driver { int major(); }",
                ),
                (
                    "java.base/module-info.java",
                    "module java.base { exports java.lang; exports internal to java.sql; }",
                ),
                (
                    "java.base/java/lang/Object.java",
                    "package java.lang; public class Object { public int hashCode() { return 0; } }",
                ),
                (
                    "java.base/internal/Hidden.java",
                    "package internal; public class Hidden {}",
                ),
            ],
        );
        let renamed_archive = fixture.path().join("renamed-src.zip");
        std::fs::copy(&archive, &renamed_archive).unwrap();
        let production = JdkSourceArchivePackProducer::new(JdkSourceArchiveLayout::ModulePrefixed)
            .produce_exact_artifact(&request(archive), &ArtifactProducerLimits::default());
        let pack = production.pack.expect("JDK pack");
        let renamed_pack =
            JdkSourceArchivePackProducer::new(JdkSourceArchiveLayout::ModulePrefixed)
                .produce_exact_artifact(
                    &request(renamed_archive),
                    &ArtifactProducerLimits::default(),
                )
                .pack
                .expect("renamed JDK pack");
        let compiled = compile_pack(&pack, &CompilerOptions::default()).unwrap();
        let renamed_compiled = compile_pack(&renamed_pack, &CompilerOptions::default()).unwrap();
        assert_eq!(compiled.manifest_bytes, renamed_compiled.manifest_bytes);
        assert_eq!(compiled.shards, renamed_compiled.shards);
        assert_eq!(
            pack.shards
                .iter()
                .map(|shard| shard.id.as_str())
                .collect::<Vec<_>>(),
            vec!["declarations.jdk.java.base", "declarations.jdk.java.sql"]
        );
        for shard in &pack.shards {
            let module = shard.id.trim_start_matches("declarations.jdk.");
            assert!(shard.activation.iter().all(|selector| {
                selector
                    .module
                    .as_ref()
                    .is_some_and(|value| value.name == module)
                    && selector.artifact_sha256 == production.artifact_sha256
            }));
        }
        let java_base = pack
            .shards
            .iter()
            .find(|shard| shard.id == "declarations.jdk.java.base")
            .unwrap();
        let AuthoredPayload::DeclarationFacts { types, .. } = &java_base.payload else {
            panic!("JDK producer must emit declaration facts");
        };
        assert!(types.iter().all(|fact| fact.name != "internal.Hidden"));
    }

    #[test]
    fn flat_layout_assigns_sources_to_java_base_and_rejects_module_prefixes() {
        let fixture = tempdir().unwrap();
        let flat = fixture.path().join("flat.zip");
        write_zip(
            &flat,
            &[(
                "java/lang/Object.java",
                "package java.lang; public class Object {}",
            )],
        );
        let production = JdkSourceArchivePackProducer::new(JdkSourceArchiveLayout::Flat)
            .produce_exact_artifact(&request(flat), &ArtifactProducerLimits::default());
        let pack = production.pack.expect("flat JDK pack");
        assert_eq!(pack.shards.len(), 1);
        assert_eq!(pack.shards[0].id, "declarations.jdk.java.base");

        let module_prefixed = fixture.path().join("module.zip");
        write_zip(
            &module_prefixed,
            &[
                (
                    "java.base/module-info.java",
                    "module java.base { exports java.lang; }",
                ),
                (
                    "java.base/java/lang/Object.java",
                    "package java.lang; public class Object {}",
                ),
            ],
        );
        let rejected = JdkSourceArchivePackProducer::new(JdkSourceArchiveLayout::Flat)
            .produce_exact_artifact(
                &request(module_prefixed),
                &ArtifactProducerLimits::default(),
            );
        assert!(rejected.pack.is_none());
        assert!(
            rejected
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "jdk.layout.flat")
        );
    }

    #[test]
    #[ignore = "requires BIFROST_JDK_SOURCE_ZIP pointing to a pinned JDK src.zip"]
    fn pinned_jdk_source_archive_smoke() {
        let path = std::env::var_os("BIFROST_JDK_SOURCE_ZIP")
            .map(std::path::PathBuf::from)
            .expect("set BIFROST_JDK_SOURCE_ZIP");
        let version = std::env::var("BIFROST_JDK_VERSION").expect("set BIFROST_JDK_VERSION");
        let production = JdkSourceArchivePackProducer::new(JdkSourceArchiveLayout::ModulePrefixed)
            .produce_exact_artifact(
                &request_for_version(path, &version),
                &ArtifactProducerLimits::default(),
            );
        let pack = production.pack.expect("real JDK source pack");
        let compiled = compile_pack(&pack, &CompilerOptions::default()).unwrap_or_else(|errors| {
            for shard in &pack.shards {
                let AuthoredPayload::DeclarationFacts { members, .. } = &shard.payload else {
                    continue;
                };
                let mut by_id: HashMap<&str, Vec<_>> = HashMap::default();
                for member in members {
                    by_id.entry(&member.id).or_default().push(member);
                }
                for duplicates in by_id.values().filter(|members| members.len() > 1) {
                    eprintln!("duplicate JDK members in {}: {duplicates:#?}", shard.id);
                }
            }
            panic!("pack compilation failed: {errors:#?}");
        });
        assert!(pack.shards.len() > 1, "expected module shards");
        let java_base = pack
            .shards
            .iter()
            .find(|shard| shard.id == "declarations.jdk.java.base")
            .expect("java.base shard");
        let AuthoredPayload::DeclarationFacts { types, members, .. } = &java_base.payload else {
            panic!("JDK source producer must emit declaration facts");
        };
        eprintln!(
            "JDK source smoke: shards={}, java_base_types={}, java_base_members={}, stored_bytes={}, raw_bytes={}, completeness={:?}, diagnostics={:#?}",
            pack.shards.len(),
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
        for expected in ["java.lang.Object", "java.lang.String", "java.util.List"] {
            assert!(
                types.iter().any(|fact| fact.name == expected),
                "missing {expected}; diagnostics={:#?}",
                production.diagnostics
            );
        }
        assert!(
            members.iter().any(|fact| fact.name == "hashCode"),
            "java.lang.Object.hashCode should come from source; diagnostics={:#?}",
            production.diagnostics
        );
    }

    fn request(path: std::path::PathBuf) -> ArtifactProductionRequest {
        request_for_version(path, "21.0.2")
    }

    fn request_for_version(path: std::path::PathBuf, version: &str) -> ArtifactProductionRequest {
        ArtifactProductionRequest {
            path,
            artifact_kind: ExternalArtifactKind::JdkSourceZip,
            pack_id: "jdk-21".to_owned(),
            pack_version: version.to_owned(),
            ecosystem: "jdk".to_owned(),
            compatibility: Compatibility {
                bifrost: format!("={}", env!("CARGO_PKG_VERSION")),
                toolchains: vec![crate::analyzer::semantic_model::VersionConstraint {
                    name: "jdk".to_owned(),
                    requirement: format!("={version}"),
                }],
            },
            activation: vec![ActivationSelector {
                package: None,
                module: None,
                toolchain: Some(NameSelector {
                    name: "jdk".to_owned(),
                    version: Some(format!("={version}")),
                }),
                targets: Vec::new(),
                configurations: Vec::new(),
                artifact_sha256: None,
            }],
            provenance: Provenance {
                source: "OpenJDK".to_owned(),
                revision: Some(format!("jdk-{version}")),
            },
            license: "GPL-2.0-only WITH Classpath-exception-2.0".to_owned(),
            safety: Safety {
                generated_code_only: false,
                review_required: false,
            },
        }
    }

    fn write_zip(path: &Path, entries: &[(&str, &str)]) {
        let mut writer = zip::ZipWriter::new(File::create(path).unwrap());
        for (entry_name, source) in entries {
            writer
                .start_file(*entry_name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(source.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
    }
}
