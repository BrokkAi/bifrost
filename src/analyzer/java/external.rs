use super::declarations::{
    determine_package_name, is_class_like_declaration_kind, node_text, normalize_java_full_name,
    parse_tree,
};
use crate::analyzer::{JavaExternalArtifact, JavaExternalDependencies, JavaMavenCoordinate};
use crate::hash::HashMap;
use jclassfile::attributes::{Attribute, NestedClassFlags};
use jclassfile::class_file::{ClassFile, ClassFlags};
use jclassfile::constant_pool::ConstantPool;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

const MAX_ARCHIVE_ENTRIES: usize = 10_000;
const MAX_SOURCE_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CLASS_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub(crate) struct JavaExternalDeclarationIndex {
    types_by_fqn: HashMap<String, JavaExternalType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JavaExternalType {
    fqn: String,
    package_name: String,
    short_name: String,
    kind: JavaExternalTypeKind,
    visibility: JavaVisibility,
    source: JavaExternalDeclarationSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JavaExternalTypeKind {
    Class,
    Interface,
    Enum,
    Annotation,
    Record,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JavaVisibility {
    Public,
    Protected,
    PackagePrivate,
    Private,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JavaExternalDeclarationSource {
    SourceJar {
        artifact_path: PathBuf,
        source_path: String,
    },
    ClassFile {
        artifact_path: PathBuf,
        class_entry: String,
    },
}

#[derive(Debug, Clone)]
struct ResolvedJavaArtifact {
    artifact_path: PathBuf,
    source_artifact_path: Option<PathBuf>,
}

impl JavaExternalDeclarationIndex {
    pub(crate) fn build(config: &JavaExternalDependencies, project_root: &Path) -> Self {
        let artifacts = resolve_configured_artifacts(config, project_root);
        let mut index = Self::default();
        for artifact in artifacts {
            if is_source_jar(&artifact.artifact_path) {
                index.index_source_jar(&artifact.artifact_path);
                continue;
            }
            if let Some(source_artifact_path) = artifact.source_artifact_path.as_deref() {
                index.index_source_jar(source_artifact_path);
            }
            index.index_class_jar(&artifact.artifact_path);
        }
        index
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.types_by_fqn.is_empty()
    }

    pub(crate) fn get(&self, fqn: &str) -> Option<&JavaExternalType> {
        self.types_by_fqn.get(fqn)
    }

    pub(crate) fn resolve_explicit_import(
        &self,
        import_path: &str,
        access_package: &str,
    ) -> Option<&JavaExternalType> {
        self.get(import_path)
            .filter(|ty| ty.is_accessible_from_package(access_package))
    }

    pub(crate) fn resolve_wildcard_import(
        &self,
        package_name: &str,
        short_name: &str,
        access_package: &str,
    ) -> Option<&JavaExternalType> {
        self.get(&qualified_name(package_name, short_name))
            .filter(|ty| ty.is_accessible_from_package(access_package))
    }

    pub(crate) fn resolve_same_package(
        &self,
        package_name: &str,
        short_name: &str,
    ) -> Option<&JavaExternalType> {
        self.get(&qualified_name(package_name, short_name))
            .filter(|ty| ty.is_accessible_from_package(package_name))
    }

    pub(crate) fn resolve_java_lang(&self, short_name: &str) -> Option<&JavaExternalType> {
        self.get(&qualified_name("java.lang", short_name))
            .filter(|ty| ty.visibility == JavaVisibility::Public)
    }

    pub(crate) fn resolve_qualified_name(
        &self,
        fqn: &str,
        access_package: &str,
    ) -> Option<&JavaExternalType> {
        self.get(fqn)
            .filter(|ty| ty.is_accessible_from_package(access_package))
    }

    fn insert(&mut self, external_type: JavaExternalType) {
        match self.types_by_fqn.get(&external_type.fqn) {
            Some(existing)
                if matches!(
                    existing.source,
                    JavaExternalDeclarationSource::SourceJar { .. }
                ) =>
            {
                return;
            }
            _ => {}
        }
        self.types_by_fqn
            .insert(external_type.fqn.clone(), external_type);
    }

    fn index_source_jar(&mut self, artifact_path: &Path) {
        let Some(file) = open_artifact_file(artifact_path) else {
            return;
        };
        let Ok(mut archive) = ZipArchive::new(file) else {
            return;
        };
        let entry_count = archive.len().min(MAX_ARCHIVE_ENTRIES);
        let mut total_bytes = 0u64;
        for index in 0..entry_count {
            let Ok(entry) = archive.by_index(index) else {
                continue;
            };
            if !entry.name().ends_with(".java") {
                continue;
            }
            if !can_read_entry(entry.size(), MAX_SOURCE_ENTRY_BYTES, &mut total_bytes) {
                continue;
            }
            let source_path = entry.name().to_string();
            let mut source = String::new();
            if entry
                .take(MAX_SOURCE_ENTRY_BYTES + 1)
                .read_to_string(&mut source)
                .is_err()
                || source.len() as u64 > MAX_SOURCE_ENTRY_BYTES
            {
                continue;
            }
            for external_type in source_types(artifact_path, &source_path, &source) {
                self.insert(external_type);
            }
        }
    }

    fn index_class_jar(&mut self, artifact_path: &Path) {
        let Some(file) = open_artifact_file(artifact_path) else {
            return;
        };
        let Ok(mut archive) = ZipArchive::new(file) else {
            return;
        };
        let entry_count = archive.len().min(MAX_ARCHIVE_ENTRIES);
        let mut total_bytes = 0u64;
        for index in 0..entry_count {
            let Ok(entry) = archive.by_index(index) else {
                continue;
            };
            if !entry.name().ends_with(".class") || entry.name().ends_with("module-info.class") {
                continue;
            }
            if !can_read_entry(entry.size(), MAX_CLASS_ENTRY_BYTES, &mut total_bytes) {
                continue;
            }
            let class_entry = entry.name().to_string();
            let mut bytes = Vec::new();
            if entry
                .take(MAX_CLASS_ENTRY_BYTES + 1)
                .read_to_end(&mut bytes)
                .is_err()
                || bytes.len() as u64 > MAX_CLASS_ENTRY_BYTES
            {
                continue;
            }
            if let Some(external_type) = class_type(artifact_path, &class_entry, &bytes) {
                self.insert(external_type);
            }
        }
    }
}

#[allow(dead_code)]
impl JavaExternalType {
    pub(crate) fn package_name(&self) -> &str {
        &self.package_name
    }

    pub(crate) fn short_name(&self) -> &str {
        &self.short_name
    }

    pub(crate) fn kind(&self) -> JavaExternalTypeKind {
        self.kind
    }

    pub(crate) fn visibility(&self) -> JavaVisibility {
        self.visibility
    }

    pub(crate) fn source(&self) -> &JavaExternalDeclarationSource {
        &self.source
    }

    pub(crate) fn fqn(&self) -> &str {
        &self.fqn
    }

    fn is_accessible_from_package(&self, package_name: &str) -> bool {
        self.visibility == JavaVisibility::Public
            || (matches!(
                self.visibility,
                JavaVisibility::Protected | JavaVisibility::PackagePrivate
            ) && self.package_name == package_name)
    }
}

fn open_artifact_file(path: &Path) -> Option<File> {
    let metadata = path.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_BYTES {
        return None;
    }
    File::open(path).ok()
}

fn can_read_entry(entry_size: u64, max_entry_bytes: u64, total_bytes: &mut u64) -> bool {
    if entry_size > max_entry_bytes {
        return false;
    }
    let Some(next_total) = total_bytes.checked_add(entry_size) else {
        return false;
    };
    if next_total > MAX_TOTAL_ARCHIVE_BYTES {
        return false;
    }
    *total_bytes = next_total;
    true
}

fn resolve_configured_artifacts(
    config: &JavaExternalDependencies,
    project_root: &Path,
) -> Vec<ResolvedJavaArtifact> {
    let mut artifacts = Vec::new();
    for artifact in &config.artifact_paths {
        artifacts.push(resolve_explicit_artifact(artifact, project_root));
    }

    let repository_roots = repository_roots(config);
    for coordinate in &config.coordinates {
        for root in &repository_roots {
            if let Some(artifact) = resolve_coordinate(root, coordinate) {
                artifacts.push(artifact);
                break;
            }
        }
    }

    artifacts
}

fn resolve_explicit_artifact(
    artifact: &JavaExternalArtifact,
    project_root: &Path,
) -> ResolvedJavaArtifact {
    ResolvedJavaArtifact {
        artifact_path: resolve_path(project_root, &artifact.artifact_path),
        source_artifact_path: artifact
            .source_artifact_path
            .as_ref()
            .map(|path| resolve_path(project_root, path)),
    }
}

fn resolve_coordinate(
    repository_root: &Path,
    coordinate: &JavaMavenCoordinate,
) -> Option<ResolvedJavaArtifact> {
    if !is_safe_maven_coordinate(coordinate) {
        return None;
    }

    let repository_root = repository_root.canonicalize().ok()?;
    let mut directory = repository_root.clone();
    for segment in coordinate.group_id.split('.') {
        directory.push(segment);
    }
    directory.push(&coordinate.artifact_id);
    directory.push(&coordinate.version);

    let jar_name = format!("{}-{}.jar", coordinate.artifact_id, coordinate.version);
    let sources_name = format!(
        "{}-{}-sources.jar",
        coordinate.artifact_id, coordinate.version
    );
    let artifact_path = canonical_file_under(&repository_root, &directory.join(jar_name))?;
    if !artifact_path.is_file() {
        return None;
    }
    let source_artifact_path =
        canonical_file_under(&repository_root, &directory.join(sources_name));
    Some(ResolvedJavaArtifact {
        artifact_path,
        source_artifact_path,
    })
}

fn is_safe_maven_coordinate(coordinate: &JavaMavenCoordinate) -> bool {
    !coordinate.group_id.is_empty()
        && coordinate
            .group_id
            .split('.')
            .all(is_safe_maven_path_segment)
        && is_safe_maven_path_segment(&coordinate.artifact_id)
        && is_safe_maven_path_segment(&coordinate.version)
}

fn is_safe_maven_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && !segment.contains('/')
        && !segment.contains('\\')
}

fn canonical_file_under(root: &Path, path: &Path) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    canonical.starts_with(root).then_some(canonical)
}

fn is_source_jar(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with("-sources.jar"))
}

fn repository_roots(config: &JavaExternalDependencies) -> Vec<PathBuf> {
    if !config.repository_roots.is_empty() {
        return config.repository_roots.clone();
    }

    home_dir()
        .map(|home| vec![home.join(".m2").join("repository")])
        .unwrap_or_default()
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
}

fn resolve_path(project_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        project_root.join(path)
    }
}

fn source_types(artifact_path: &Path, source_path: &str, source: &str) -> Vec<JavaExternalType> {
    let Some(tree) = parse_tree(source) else {
        return Vec::new();
    };
    let root = tree.root_node();
    let package_name = determine_package_name(root, source);
    let mut result = Vec::new();
    let mut stack = Vec::new();
    for index in (0..root.named_child_count()).rev() {
        let Some(child) = root.named_child(index) else {
            continue;
        };
        if is_class_like_declaration_kind(child.kind()) {
            stack.push((child, None::<String>, true));
        }
    }

    while let Some((node, parent_short_name, parent_visible)) = stack.pop() {
        let Some(name_node) = node.child_by_field_name("name") else {
            continue;
        };
        let simple_name = node_text(name_node, source).trim();
        if simple_name.is_empty() {
            continue;
        }

        let short_name = parent_short_name
            .as_deref()
            .map(|parent| format!("{parent}.{simple_name}"))
            .unwrap_or_else(|| simple_name.to_string());
        let visibility = source_visibility(node, source);
        if parent_visible && visibility != JavaVisibility::Private {
            result.push(JavaExternalType {
                fqn: qualified_name(&package_name, &short_name),
                package_name: package_name.clone(),
                short_name: short_name.clone(),
                kind: source_kind(node.kind()),
                visibility,
                source: JavaExternalDeclarationSource::SourceJar {
                    artifact_path: artifact_path.to_path_buf(),
                    source_path: source_path.to_string(),
                },
            });
        }

        let child_parent_visible = parent_visible && visibility != JavaVisibility::Private;
        let Some(body) = node.child_by_field_name("body") else {
            continue;
        };
        for index in (0..body.named_child_count()).rev() {
            let Some(child) = body.named_child(index) else {
                continue;
            };
            if is_class_like_declaration_kind(child.kind()) {
                stack.push((child, Some(short_name.clone()), child_parent_visible));
            }
        }
    }

    result
}

fn source_visibility(node: tree_sitter::Node<'_>, source: &str) -> JavaVisibility {
    for index in 0..node.named_child_count() {
        let Some(child) = node.named_child(index) else {
            continue;
        };
        if child.kind() != "modifiers" {
            continue;
        }
        let modifiers = node_text(child, source);
        if modifier_present(modifiers, "public") {
            return JavaVisibility::Public;
        }
        if modifier_present(modifiers, "protected") {
            return JavaVisibility::Protected;
        }
        if modifier_present(modifiers, "private") {
            return JavaVisibility::Private;
        }
    }
    JavaVisibility::PackagePrivate
}

fn modifier_present(modifiers: &str, expected: &str) -> bool {
    modifiers
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .any(|token| token == expected)
}

fn class_type(artifact_path: &Path, class_entry: &str, bytes: &[u8]) -> Option<JavaExternalType> {
    let class_file = jclassfile::class_file::parse(bytes).ok()?;
    let flags = class_file.access_flags();
    if flags.contains(ClassFlags::ACC_MODULE) {
        return None;
    }
    let internal_name = class_internal_name(&class_file)?;
    let (package_name, short_name) = split_internal_class_name(&internal_name);
    if short_name.is_empty() {
        return None;
    }
    let fqn = qualified_name(&package_name, &short_name);
    let visibility = class_visibility(&class_file, &internal_name);
    if visibility == JavaVisibility::Private {
        return None;
    }
    Some(JavaExternalType {
        fqn,
        package_name,
        short_name,
        kind: class_kind(flags),
        visibility,
        source: JavaExternalDeclarationSource::ClassFile {
            artifact_path: artifact_path.to_path_buf(),
            class_entry: class_entry.to_string(),
        },
    })
}

fn class_internal_name(class_file: &ClassFile) -> Option<String> {
    let class_index = class_file.this_class() as usize;
    class_name_at_class_index(class_file, class_index)
}

fn class_name_at_class_index(class_file: &ClassFile, class_index: usize) -> Option<String> {
    let constant_pool = class_file.constant_pool();
    let ConstantPool::Class { name_index } = constant_pool.get(class_index)? else {
        return None;
    };
    let ConstantPool::Utf8 { value } = constant_pool.get(*name_index as usize)? else {
        return None;
    };
    Some(value.clone())
}

fn class_visibility(class_file: &ClassFile, internal_name: &str) -> JavaVisibility {
    let mut own_visibility = None;
    for attribute in class_file.attributes() {
        let Attribute::InnerClasses { classes } = attribute else {
            continue;
        };
        for class in classes {
            let Some(inner_name) =
                class_name_at_class_index(class_file, class.inner_class_info_index() as usize)
            else {
                continue;
            };
            if internal_name.starts_with(&format!("{inner_name}$"))
                && nested_class_visibility(class.inner_class_access_flags())
                    == JavaVisibility::Private
            {
                return JavaVisibility::Private;
            }
            if inner_name == internal_name {
                own_visibility = Some(nested_class_visibility(class.inner_class_access_flags()));
            }
        }
    }
    if let Some(visibility) = own_visibility {
        return visibility;
    }

    if class_file.access_flags().contains(ClassFlags::ACC_PUBLIC) {
        JavaVisibility::Public
    } else {
        JavaVisibility::PackagePrivate
    }
}

fn nested_class_visibility(flags: &NestedClassFlags) -> JavaVisibility {
    if flags.contains(NestedClassFlags::ACC_PUBLIC) {
        JavaVisibility::Public
    } else if flags.contains(NestedClassFlags::ACC_PROTECTED) {
        JavaVisibility::Protected
    } else if flags.contains(NestedClassFlags::ACC_PRIVATE) {
        JavaVisibility::Private
    } else {
        JavaVisibility::PackagePrivate
    }
}

fn class_kind(flags: &ClassFlags) -> JavaExternalTypeKind {
    if flags.contains(ClassFlags::ACC_ANNOTATION) {
        JavaExternalTypeKind::Annotation
    } else if flags.contains(ClassFlags::ACC_ENUM) {
        JavaExternalTypeKind::Enum
    } else if flags.contains(ClassFlags::ACC_INTERFACE) {
        JavaExternalTypeKind::Interface
    } else {
        JavaExternalTypeKind::Class
    }
}

fn source_kind(kind: &str) -> JavaExternalTypeKind {
    match kind {
        "interface_declaration" => JavaExternalTypeKind::Interface,
        "enum_declaration" => JavaExternalTypeKind::Enum,
        "annotation_type_declaration" => JavaExternalTypeKind::Annotation,
        "record_declaration" => JavaExternalTypeKind::Record,
        _ => JavaExternalTypeKind::Class,
    }
}

fn split_internal_class_name(internal_name: &str) -> (String, String) {
    let (package_path, class_name) = internal_name
        .rsplit_once('/')
        .unwrap_or(("", internal_name));
    (
        package_path.replace('/', "."),
        normalize_java_full_name(&class_name.replace('$', ".")),
    )
}

fn qualified_name(package_name: &str, short_name: &str) -> String {
    if package_name.is_empty() {
        short_name.to_string()
    } else {
        format!("{package_name}.{short_name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{
        AnalyzerConfig, JavaAnalyzer, JavaExternalArtifact, JavaExternalDependencies,
        JavaMavenCoordinate, Language, Project, ProjectFile, TestProject,
    };
    use std::fs;
    use std::io::Write;
    use std::process::Command;
    use zip::write::SimpleFileOptions;

    const GROUP_PATH: &str = "com/example/external-lib/1.2.3";
    const BINARY_JAR: &str = "external-lib-1.2.3.jar";
    const SOURCE_JAR: &str = "external-lib-1.2.3-sources.jar";

    #[test]
    fn java_external_declaration_indexes_coordinate_and_prefers_source_jar() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let config = fixture.coordinate_config();
        let index = JavaExternalDeclarationIndex::build(&config, fixture.project_root());

        let service = index.get("com.example.dep.ExternalService").unwrap();
        assert_eq!("com.example.dep", service.package_name());
        assert_eq!("ExternalService", service.short_name());
        assert_eq!(JavaExternalTypeKind::Class, service.kind());
        assert_eq!(JavaVisibility::Public, service.visibility());
        assert!(
            matches!(
                service.source(),
                JavaExternalDeclarationSource::SourceJar { source_path, .. }
                    if source_path == "com/example/dep/ExternalService.java"
            ),
            "{service:#?}"
        );

        assert!(
            index
                .get("com.example.dep.ExternalService.Nested")
                .is_some()
        );
        assert!(
            matches!(
                index
                    .get("com.example.dep.ExternalService.Nested")
                    .map(JavaExternalType::source),
                Some(JavaExternalDeclarationSource::SourceJar { .. })
            ),
            "nested source declarations should retain source-JAR provenance"
        );
        assert_eq!(
            Some(JavaVisibility::Protected),
            index
                .get("com.example.dep.ExternalService.ProtectedNested")
                .map(JavaExternalType::visibility)
        );
        assert!(
            index
                .get("com.example.dep.ExternalService.Hidden")
                .is_none(),
            "private nested classes should not be indexed as externally visible"
        );
        assert!(
            index
                .get("com.example.dep.ExternalService.Hidden.Leaks")
                .is_none(),
            "nested classes under a private parent should not be indexed as externally visible"
        );
        assert_eq!(
            Some(JavaVisibility::PackagePrivate),
            index
                .get("com.example.dep.PackageHelper")
                .map(JavaExternalType::visibility)
        );
        assert!(
            index
                .resolve_wildcard_import("com.example.dep", "ExternalService", "app")
                .is_some()
        );
    }

    #[test]
    fn java_external_declaration_uses_classfile_when_source_jar_is_missing() {
        let Some(fixture) = ExternalJarFixture::new(false) else {
            return;
        };
        let config = fixture.coordinate_config();
        let index = JavaExternalDeclarationIndex::build(&config, fixture.project_root());

        let service = index.get("com.example.dep.ExternalService").unwrap();
        assert!(
            matches!(
                service.source(),
                JavaExternalDeclarationSource::ClassFile { class_entry, .. }
                    if class_entry == "com/example/dep/ExternalService.class"
            ),
            "{service:#?}"
        );
        assert_eq!(
            Some(JavaVisibility::Protected),
            index
                .get("com.example.dep.ExternalService.ProtectedNested")
                .map(JavaExternalType::visibility)
        );
        assert_eq!(
            Some(JavaVisibility::PackagePrivate),
            index
                .get("com.example.dep.PackageHelper")
                .map(JavaExternalType::visibility)
        );
        let package_nested = index
            .get("com.example.dep.ExternalService.PackageNested")
            .unwrap();
        assert_eq!("com.example.dep", package_nested.package_name());
        assert_eq!("ExternalService.PackageNested", package_nested.short_name());
        assert_eq!(JavaVisibility::PackagePrivate, package_nested.visibility());
        assert!(
            index
                .get("com.example.dep.ExternalService.Hidden")
                .is_none(),
            "classfile fallback should respect InnerClasses private visibility"
        );
    }

    #[test]
    fn java_external_declaration_indexes_explicit_source_artifact_path() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let config = JavaExternalDependencies {
            artifact_paths: vec![JavaExternalArtifact {
                artifact_path: fixture.source_jar_path(),
                source_artifact_path: None,
            }],
            ..JavaExternalDependencies::default()
        };
        let index = JavaExternalDeclarationIndex::build(&config, fixture.project_root());

        let service = index.get("com.example.dep.ExternalService").unwrap();
        assert!(
            matches!(
                service.source(),
                JavaExternalDeclarationSource::SourceJar { source_path, .. }
                    if source_path == "com/example/dep/ExternalService.java"
            ),
            "{service:#?}"
        );
    }

    #[test]
    fn java_external_declaration_ignores_missing_and_malformed_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let malformed = root.join("bad.jar");
        fs::write(&malformed, b"not a zip").unwrap();

        let config = JavaExternalDependencies {
            artifact_paths: vec![
                JavaExternalArtifact {
                    artifact_path: malformed,
                    source_artifact_path: None,
                },
                JavaExternalArtifact {
                    artifact_path: root.join("missing.jar"),
                    source_artifact_path: None,
                },
            ],
            ..JavaExternalDependencies::default()
        };

        let index = JavaExternalDeclarationIndex::build(&config, &root);
        assert!(index.is_empty());
    }

    #[test]
    fn java_external_declaration_rejects_unsafe_coordinates() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let unsafe_coordinates = [
            JavaMavenCoordinate::new("..", "external-lib", "1.2.3"),
            JavaMavenCoordinate::new("com.example", "../external-lib", "1.2.3"),
            JavaMavenCoordinate::new("com.example", "external-lib", "../1.2.3"),
            JavaMavenCoordinate::new("com..example", "external-lib", "1.2.3"),
        ];

        for coordinate in unsafe_coordinates {
            assert!(
                resolve_coordinate(&root, &coordinate).is_none(),
                "unsafe coordinate should not resolve: {coordinate:?}"
            );
        }
    }

    #[test]
    fn java_external_declaration_skips_oversized_source_entries() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let oversized_source_jar = root.join("oversized-sources.jar");
        write_zip_entry(
            &oversized_source_jar,
            "com/example/dep/Oversized.java",
            &vec![b' '; MAX_SOURCE_ENTRY_BYTES as usize + 1],
        );
        let config = JavaExternalDependencies {
            artifact_paths: vec![JavaExternalArtifact {
                artifact_path: oversized_source_jar,
                source_artifact_path: None,
            }],
            ..JavaExternalDependencies::default()
        };

        let index = JavaExternalDeclarationIndex::build(&config, &root);
        assert!(index.is_empty());
    }

    #[test]
    fn java_external_declaration_skips_oversized_artifacts_before_zip_parse() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let oversized_jar = root.join("oversized.jar");
        File::create(&oversized_jar)
            .unwrap()
            .set_len(MAX_ARTIFACT_BYTES + 1)
            .unwrap();
        let config = JavaExternalDependencies {
            artifact_paths: vec![JavaExternalArtifact {
                artifact_path: oversized_jar,
                source_artifact_path: None,
            }],
            ..JavaExternalDependencies::default()
        };

        let index = JavaExternalDeclarationIndex::build(&config, &root);
        assert!(index.is_empty());
    }

    #[test]
    fn java_external_declaration_resolver_distinguishes_source_and_external_types() {
        let Some(fixture) = ExternalJarFixture::new(true) else {
            return;
        };
        let config = AnalyzerConfig {
            java_external_dependencies: fixture.coordinate_config(),
            ..AnalyzerConfig::default()
        };

        let app = ProjectFile::new(fixture.project_root().to_path_buf(), "src/App.java");
        app.write(
            "package app;\n\
             import com.example.dep.ExternalService;\n\
             import com.example.dep.ExternalHelper;\n\
             public class App { ExternalService one; ExternalService.Nested two; ExternalHelper helper; ExternalService.ProtectedNested blocked; }\n",
        )
        .unwrap();
        ProjectFile::new(fixture.project_root().to_path_buf(), "src/LocalType.java")
            .write("package app; public class LocalType {}")
            .unwrap();
        let same_package_app = ProjectFile::new(
            fixture.project_root().to_path_buf(),
            "src/com/example/dep/App.java",
        );
        same_package_app
            .write("package com.example.dep; public class App { PackageHelper helper; }\n")
            .unwrap();

        let project = TestProject::new(fixture.project_root().to_path_buf(), Language::Java);
        let analyzer = JavaAnalyzer::from_project_with_config(project.clone(), config);

        assert!(matches!(
            analyzer.resolve_type_name_with_external(&app, "LocalType"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::Source(
                _
            ))
        ));
        assert!(matches!(
            analyzer.resolve_type_name_with_external(&app, "ExternalService"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(matches!(
            analyzer.resolve_type_name_with_external(&app, "ExternalService.Nested"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(
            analyzer
                .resolve_type_name_with_external(&app, "ExternalService.ProtectedNested")
                .is_none(),
            "protected nested dependency types should not resolve from unrelated packages"
        );
        assert!(matches!(
            analyzer.resolve_type_name_with_external(&same_package_app, "PackageHelper"),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(matches!(
            analyzer.resolve_type_name_with_external(
                &same_package_app,
                "ExternalService.PackageNested"
            ),
            Some(crate::analyzer::java::imports::JavaTypeResolution::External(_))
        ));
        assert!(
            analyzer
                .resolve_type_name_in_file(&app, "ExternalService")
                .is_none(),
            "source-only resolution should not fabricate CodeUnits for dependency types"
        );
        assert!(
            project
                .all_files()
                .unwrap()
                .iter()
                .all(|file| !file.rel_path().to_string_lossy().contains(".jar"))
        );
    }

    struct ExternalJarFixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        workspace_root: PathBuf,
    }

    impl ExternalJarFixture {
        fn new(include_sources: bool) -> Option<Self> {
            if !jdk_tool_available("javac") || !jdk_tool_available("jar") {
                eprintln!(
                    "skipping Java external declaration fixture test: `javac` and `jar` are required"
                );
                return None;
            }

            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let workspace_root = root.join("workspace");
            let repo_dir = root.join("m2").join(GROUP_PATH);
            let source_dir = root.join("dep-src");
            let package_dir = source_dir.join("com/example/dep");
            let classes_dir = root.join("dep-classes");
            fs::create_dir_all(&workspace_root).unwrap();
            fs::create_dir_all(&repo_dir).unwrap();
            fs::create_dir_all(&package_dir).unwrap();
            fs::create_dir_all(&classes_dir).unwrap();

            fs::write(
                package_dir.join("ExternalService.java"),
                "package com.example.dep;\n\
                 public class ExternalService {\n\
                   public static class Nested {}\n\
                   protected static class ProtectedNested {}\n\
                   static class PackageNested {}\n\
                   private static class Hidden { public static class Leaks {} }\n\
                 }\n",
            )
            .unwrap();
            fs::write(
                package_dir.join("ExternalInterface.java"),
                "package com.example.dep; public interface ExternalInterface {}\n",
            )
            .unwrap();
            fs::write(
                package_dir.join("ExternalHelper.java"),
                "package com.example.dep; public class ExternalHelper {}\n",
            )
            .unwrap();
            fs::write(
                package_dir.join("PackageHelper.java"),
                "package com.example.dep; class PackageHelper {}\n",
            )
            .unwrap();

            run(Command::new("javac")
                .arg("-d")
                .arg(&classes_dir)
                .arg(package_dir.join("ExternalService.java"))
                .arg(package_dir.join("ExternalInterface.java"))
                .arg(package_dir.join("ExternalHelper.java"))
                .arg(package_dir.join("PackageHelper.java")));
            run(Command::new("jar")
                .current_dir(&classes_dir)
                .arg("cf")
                .arg(repo_dir.join(BINARY_JAR))
                .arg("."));
            if include_sources {
                run(Command::new("jar")
                    .current_dir(&source_dir)
                    .arg("cf")
                    .arg(repo_dir.join(SOURCE_JAR))
                    .arg("."));
            }

            Some(Self {
                _temp: temp,
                root,
                workspace_root,
            })
        }

        fn project_root(&self) -> &Path {
            &self.workspace_root
        }

        fn source_jar_path(&self) -> PathBuf {
            self.root.join("m2").join(GROUP_PATH).join(SOURCE_JAR)
        }

        fn coordinate_config(&self) -> JavaExternalDependencies {
            JavaExternalDependencies {
                coordinates: vec![JavaMavenCoordinate::new(
                    "com.example",
                    "external-lib",
                    "1.2.3",
                )],
                repository_roots: vec![self.root.join("m2")],
                ..JavaExternalDependencies::default()
            }
        }
    }

    fn jdk_tool_available(tool: &str) -> bool {
        Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn run(command: &mut Command) {
        let output = command
            .output()
            .unwrap_or_else(|err| panic!("failed to run JDK fixture command {command:?}: {err}"));
        assert!(
            output.status.success(),
            "JDK fixture command failed: {command:?}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn write_zip_entry(path: &Path, entry_name: &str, bytes: &[u8]) {
        let file = File::create(path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            entry_name,
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(bytes).unwrap();
        zip.finish().unwrap();
    }
}
