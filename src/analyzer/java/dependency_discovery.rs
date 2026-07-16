use crate::analyzer::{
    JavaDependencyDiscoveryConfig, JavaExternalArtifact, JavaExternalDependencies,
    JavaMavenCoordinate, Project, ProjectFile,
};
use crate::hash::{HashMap, HashSet};
use crate::process::{BoundedProcessRequest, read_limited, run_bounded_process};
use quick_xml::Reader;
use quick_xml::events::Event;
use serde::Deserialize;
use std::ffi::OsString;
use std::fs::File;
use std::path::{Component, Path, PathBuf};

const MAX_BUILD_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOOL_REPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_MAVEN_XML_DEPTH: usize = 128;
const MAX_MAVEN_XML_NODES: usize = 16 * 1024;
const MAX_MAVEN_PROPERTY_EXPANSION_WORK: usize = 4 * 1024;
const MAX_MAVEN_EXPANDED_VALUE_BYTES: usize = 64 * 1024;

const GRADLE_INIT_SCRIPT: &str = r#"
import groovy.json.JsonOutput
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

gradle.projectsEvaluated {
    def root = gradle.rootProject
    root.tasks.register("bifrostExternalDependencies") {
        doLast {
            def output = new File(System.getProperty("bifrost.output"))
            output.withPrintWriter("UTF-8") { writer ->
                root.allprojects.each { project ->
                    project.configurations.findAll { it.canBeResolved }.each { configuration ->
                        try {
                            configuration.incoming.artifactView { lenient true }.artifacts.artifacts.each { artifact ->
                                def component = artifact.id.componentIdentifier
                                if (component instanceof ModuleComponentIdentifier) {
                                    writer.println(JsonOutput.toJson([
                                        group: component.group,
                                        name: component.module,
                                        version: component.version,
                                        file: artifact.file.absolutePath
                                    ]))
                                }
                            }
                        } catch (Exception ignored) {
                            // One unresolved configuration must not hide the others.
                        }
                    }
                }
            }
        }
    }
}
"#;

#[derive(Debug, Default)]
pub(super) struct DiscoveredJavaDependencies {
    pub(super) artifact_paths: Vec<JavaExternalArtifact>,
    pub(super) coordinates: Vec<JavaMavenCoordinate>,
}

impl DiscoveredJavaDependencies {
    pub(super) fn merge_into(self, dependencies: &mut JavaExternalDependencies) {
        dependencies.artifact_paths.extend(self.artifact_paths);
        dependencies.coordinates.extend(self.coordinates);
        deduplicate_dependencies(dependencies);
    }
}

pub(super) fn discover_metadata(project: &dyn Project) -> DiscoveredJavaDependencies {
    let Ok(files) = project.all_files() else {
        return DiscoveredJavaDependencies::default();
    };
    let files: Vec<_> = files.into_iter().collect();
    let mut discovered = DiscoveredJavaDependencies::default();
    for file in files {
        if is_maven_pom(&file) {
            discover_maven_pom(project, &file, &mut discovered);
        } else if is_gradle_lockfile(&file) {
            discover_gradle_lockfile(project, &file, &mut discovered);
        }
    }
    deduplicate_discovered(&mut discovered);
    discovered
}

pub(super) fn discover_build_tools(
    project: &dyn Project,
    config: &JavaDependencyDiscoveryConfig,
) -> DiscoveredJavaDependencies {
    discover_build_tools_with_executor(project, config, &SystemDependencyCommandExecutor)
}

trait DependencyCommandExecutor {
    fn maven_report(
        &self,
        root: &Path,
        executable: &Path,
        config: &JavaDependencyDiscoveryConfig,
    ) -> Result<Vec<u8>, String>;

    fn gradle_report(
        &self,
        root: &Path,
        executable: &Path,
        config: &JavaDependencyDiscoveryConfig,
    ) -> Result<Vec<u8>, String>;
}

struct SystemDependencyCommandExecutor;

impl DependencyCommandExecutor for SystemDependencyCommandExecutor {
    fn maven_report(
        &self,
        root: &Path,
        executable: &Path,
        config: &JavaDependencyDiscoveryConfig,
    ) -> Result<Vec<u8>, String> {
        let temporary = tempfile::tempdir().map_err(|err| err.to_string())?;
        let report_path = temporary.path().join("maven-dependencies.txt");
        let args = maven_dependency_list_args(&report_path);
        run_dependency_process(
            executable,
            &args,
            root,
            config.timeout,
            "Maven dependency discovery",
        )?;
        let report = File::open(report_path).map_err(|err| err.to_string())?;
        read_limited(report, MAX_TOOL_REPORT_BYTES)
    }

    fn gradle_report(
        &self,
        root: &Path,
        executable: &Path,
        config: &JavaDependencyDiscoveryConfig,
    ) -> Result<Vec<u8>, String> {
        let temporary = tempfile::tempdir().map_err(|err| err.to_string())?;
        let init_path = temporary.path().join("bifrost.init.gradle");
        let report_path = temporary.path().join("gradle-dependencies.jsonl");
        std::fs::write(&init_path, GRADLE_INIT_SCRIPT).map_err(|err| err.to_string())?;
        let args = [
            "--offline".to_string(),
            "--no-daemon".to_string(),
            "--console=plain".to_string(),
            "-q".to_string(),
            "-I".to_string(),
            init_path.display().to_string(),
            format!("-Dbifrost.output={}", report_path.display()),
            "bifrostExternalDependencies".to_string(),
        ];
        run_dependency_process(
            executable,
            &args,
            root,
            config.timeout,
            "Gradle dependency discovery",
        )?;
        let report = File::open(report_path).map_err(|err| err.to_string())?;
        read_limited(report, MAX_TOOL_REPORT_BYTES)
    }
}

fn run_dependency_process(
    executable: &Path,
    args: &[String],
    root: &Path,
    timeout: std::time::Duration,
    description: &str,
) -> Result<(), String> {
    let request = BoundedProcessRequest {
        program: executable.as_os_str().to_os_string(),
        args: args.iter().map(OsString::from).collect(),
        env: Vec::new(),
        cwd: root.to_path_buf(),
        stdin: None,
        timeout,
        stdout_limit: MAX_TOOL_OUTPUT_BYTES,
        stderr_limit: MAX_TOOL_OUTPUT_BYTES,
        description: description.to_string(),
    };
    let output = run_bounded_process(&request, || false)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("{description} exited with {}", output.status))
    }
}

fn discover_build_tools_with_executor(
    project: &dyn Project,
    config: &JavaDependencyDiscoveryConfig,
    executor: &dyn DependencyCommandExecutor,
) -> DiscoveredJavaDependencies {
    let Ok(files) = project.all_files() else {
        return DiscoveredJavaDependencies::default();
    };
    let files: Vec<_> = files.into_iter().collect();
    let mut discovered = DiscoveredJavaDependencies::default();
    let maven_executable = config
        .maven_executable
        .clone()
        .unwrap_or_else(|| PathBuf::from("mvn"));
    for root in maven_build_roots(project, &files) {
        let Ok(report) = executor.maven_report(&root, &maven_executable, config) else {
            continue;
        };
        add_tool_records(parse_maven_dependency_list(&report), &mut discovered);
    }

    let gradle_executable = config
        .gradle_executable
        .clone()
        .unwrap_or_else(|| PathBuf::from("gradle"));
    for root in gradle_build_roots(&files) {
        let Ok(report) = executor.gradle_report(&root, &gradle_executable, config) else {
            continue;
        };
        add_tool_records(parse_gradle_dependency_jsonl(&report), &mut discovered);
    }
    deduplicate_discovered(&mut discovered);
    discovered
}

pub(crate) fn is_java_dependency_input(file: &ProjectFile) -> bool {
    let path = file.rel_path();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if matches!(
        file_name,
        "pom.xml"
            | "settings.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "settings.gradle"
            | "settings.gradle.kts"
            | "gradle.properties"
            | "gradle.lockfile"
            | "libs.versions.toml"
            | "gradle-wrapper.properties"
    ) {
        return true;
    }
    let normalized_name = file_name.to_ascii_lowercase();
    if normalized_name.ends_with(".gradle")
        || normalized_name.ends_with(".gradle.kts")
        || normalized_name.ends_with(".lockfile")
    {
        return true;
    }
    path.components().any(|component| {
        matches!(component, Component::Normal(name) if name == ".mvn" || name == "buildSrc")
    })
}

fn discover_maven_pom(
    project: &dyn Project,
    file: &ProjectFile,
    discovered: &mut DiscoveredJavaDependencies,
) {
    let Some(source) = read_bounded_source(project, file) else {
        return;
    };
    let Some(project_node) = parse_xml(&source) else {
        return;
    };
    if project_node.name != "project" {
        return;
    }

    let properties = maven_project_properties(&project_node);

    let Some(dependencies) = project_node.child("dependencies") else {
        return;
    };
    for dependency in dependencies.children_named("dependency") {
        let dependency_type = dependency.child_text("type").unwrap_or("jar").trim();
        let classifier = dependency.child_text("classifier").unwrap_or("").trim();
        let scope = dependency.child_text("scope").unwrap_or("compile").trim();
        if dependency_type != "jar" || !classifier.is_empty() {
            continue;
        }

        if !matches!(scope, "compile" | "runtime" | "provided" | "test") {
            continue;
        }

        let Some(group_id) = dependency
            .child_text("groupId")
            .and_then(|value| expand_maven_value(value, &properties))
        else {
            continue;
        };
        let Some(artifact_id) = dependency
            .child_text("artifactId")
            .and_then(|value| expand_maven_value(value, &properties))
        else {
            continue;
        };
        let Some(version) = dependency
            .child_text("version")
            .and_then(|value| expand_maven_value(value, &properties))
        else {
            continue;
        };
        if [group_id.as_str(), artifact_id.as_str(), version.as_str()]
            .iter()
            .any(|value| value.trim().is_empty())
        {
            continue;
        }
        discovered
            .coordinates
            .push(JavaMavenCoordinate::new(group_id, artifact_id, version));
    }
}

fn maven_project_properties(project_node: &XmlNode) -> HashMap<String, String> {
    let mut properties = HashMap::default();
    if let Some(property_node) = project_node.child("properties") {
        for child in &property_node.children {
            let value = child.text.trim();
            if !child.name.is_empty() && !value.is_empty() {
                properties.insert(child.name.clone(), value.to_string());
            }
        }
    }
    let parent = project_node.child("parent");
    let project_group = project_node
        .child_text("groupId")
        .or_else(|| parent.and_then(|node| node.child_text("groupId")));
    let project_artifact = project_node.child_text("artifactId");
    let project_version = project_node
        .child_text("version")
        .or_else(|| parent.and_then(|node| node.child_text("version")));
    for (key, value) in [
        ("project.groupId", project_group),
        ("pom.groupId", project_group),
        ("project.artifactId", project_artifact),
        ("pom.artifactId", project_artifact),
        ("project.version", project_version),
        ("pom.version", project_version),
    ] {
        if let Some(value) = value {
            properties.insert(key.to_string(), value.to_string());
        }
    }
    properties
}

fn discover_gradle_lockfile(
    project: &dyn Project,
    file: &ProjectFile,
    discovered: &mut DiscoveredJavaDependencies,
) {
    let Some(source) = read_bounded_source(project, file) else {
        return;
    };
    discovered
        .coordinates
        .extend(parse_gradle_lockfile(&source));
}

fn parse_gradle_lockfile(source: &str) -> Vec<JavaMavenCoordinate> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
                return None;
            }
            let (coordinate, _) = line.split_once('=')?;
            let mut parts = coordinate.split(':');
            let group_id = parts.next()?.trim();
            let artifact_id = parts.next()?.trim();
            let version = parts.next()?.trim();
            if parts.next().is_some()
                || group_id.is_empty()
                || artifact_id.is_empty()
                || version.is_empty()
            {
                return None;
            }
            Some(JavaMavenCoordinate::new(group_id, artifact_id, version))
        })
        .collect()
}

fn maven_dependency_list_args(report_path: &Path) -> Vec<String> {
    vec![
        "-o".to_string(),
        "-B".to_string(),
        "-ntp".to_string(),
        "dependency:list".to_string(),
        "-DincludeScope=test".to_string(),
        "-DoutputAbsoluteArtifactFilename=true".to_string(),
        "-DappendOutput=true".to_string(),
        format!("-DoutputFile={}", report_path.display()),
    ]
}

#[derive(Debug, PartialEq, Eq)]
struct ToolArtifactRecord {
    coordinate: JavaMavenCoordinate,
    artifact_path: PathBuf,
}

fn parse_maven_dependency_list(report: &[u8]) -> Vec<ToolArtifactRecord> {
    String::from_utf8_lossy(report)
        .lines()
        .filter_map(parse_maven_dependency_line)
        .collect()
}

fn parse_maven_dependency_line(line: &str) -> Option<ToolArtifactRecord> {
    let fields: Vec<_> = line.trim().split(':').collect();
    if fields.len() < 6 || fields.get(2)?.trim() != "jar" {
        return None;
    }
    let scope_index = (4..fields.len().min(7)).find(|&index| {
        matches!(
            fields[index].trim(),
            "compile" | "runtime" | "provided" | "test" | "system"
        )
    })?;
    let group_id = fields.first()?.trim();
    let artifact_id = fields.get(1)?.trim();
    let version = fields.get(scope_index.checked_sub(1)?)?.trim();
    let artifact_path = fields.get(scope_index + 1..)?.join(":");
    if group_id.is_empty()
        || artifact_id.is_empty()
        || version.is_empty()
        || artifact_path.trim().is_empty()
    {
        return None;
    }
    Some(ToolArtifactRecord {
        coordinate: JavaMavenCoordinate::new(group_id, artifact_id, version),
        artifact_path: PathBuf::from(artifact_path.trim()),
    })
}

#[derive(Deserialize)]
struct GradleArtifactRecord {
    group: String,
    name: String,
    version: String,
    file: String,
}

fn parse_gradle_dependency_jsonl(report: &[u8]) -> Vec<ToolArtifactRecord> {
    String::from_utf8_lossy(report)
        .lines()
        .filter_map(|line| {
            let record = serde_json::from_str::<GradleArtifactRecord>(line).ok()?;
            if record.group.trim().is_empty()
                || record.name.trim().is_empty()
                || record.version.trim().is_empty()
                || record.file.trim().is_empty()
            {
                return None;
            }
            Some(ToolArtifactRecord {
                coordinate: JavaMavenCoordinate::new(
                    record.group.trim(),
                    record.name.trim(),
                    record.version.trim(),
                ),
                artifact_path: PathBuf::from(record.file),
            })
        })
        .collect()
}

fn add_tool_records(records: Vec<ToolArtifactRecord>, discovered: &mut DiscoveredJavaDependencies) {
    for record in records {
        if !record.artifact_path.is_absolute()
            || !record.artifact_path.is_file()
            || !record
                .artifact_path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("jar"))
        {
            continue;
        }
        discovered.coordinates.push(record.coordinate);
        discovered.artifact_paths.push(JavaExternalArtifact {
            artifact_path: record.artifact_path,
            source_artifact_path: None,
        });
    }
}

fn maven_build_roots(project: &dyn Project, files: &[ProjectFile]) -> Vec<PathBuf> {
    let poms: Vec<_> = files.iter().filter(|file| is_maven_pom(file)).collect();
    let mut module_poms = HashSet::default();
    for pom in &poms {
        let Some(source) = read_bounded_source(project, pom) else {
            continue;
        };
        let Some(project_node) = parse_xml(&source) else {
            continue;
        };
        let Some(modules) = project_node.child("modules") else {
            continue;
        };
        let properties = maven_project_properties(&project_node);
        let pom_path = pom.abs_path();
        let Some(parent) = pom_path.parent() else {
            continue;
        };
        for module in modules.children_named("module") {
            let Some(module) = expand_maven_value(module.text.trim(), &properties) else {
                continue;
            };
            module_poms.insert(stable_path(parent.join(module).join("pom.xml")));
        }
    }
    let mut roots: Vec<_> = poms
        .into_iter()
        .filter_map(|pom| {
            let path = stable_path(pom.abs_path());
            (!module_poms.contains(&path)).then(|| path.parent().map(Path::to_path_buf))?
        })
        .collect();
    roots.sort();
    roots.dedup();
    roots
}

fn gradle_build_roots(files: &[ProjectFile]) -> Vec<PathBuf> {
    let mut settings_roots: Vec<_> = files
        .iter()
        .filter(|file| {
            file.rel_path()
                .file_name()
                .is_some_and(|name| name == "settings.gradle" || name == "settings.gradle.kts")
        })
        .filter_map(|file| file.abs_path().parent().map(stable_path))
        .collect();
    settings_roots.sort();
    settings_roots.dedup();

    let mut roots = settings_roots.clone();
    for file in files.iter().filter(|file| {
        file.rel_path()
            .file_name()
            .is_some_and(|name| name == "build.gradle" || name == "build.gradle.kts")
    }) {
        let Some(root) = file.abs_path().parent().map(stable_path) else {
            continue;
        };
        if !settings_roots
            .iter()
            .any(|settings_root| root.starts_with(settings_root))
        {
            roots.push(root);
        }
    }
    roots.sort();
    roots.dedup();
    roots
}

fn stable_path(path: impl AsRef<Path>) -> PathBuf {
    path.as_ref()
        .canonicalize()
        .unwrap_or_else(|_| path.as_ref().to_path_buf())
}

fn expand_maven_value(value: &str, properties: &HashMap<String, String>) -> Option<String> {
    enum Work {
        Value(String),
        Text(String),
        Property(String),
        LeaveProperty(String),
    }

    let mut active = HashSet::default();
    let mut work = vec![Work::Value(value.trim().to_string())];
    let mut result = String::new();
    let mut steps = 0usize;
    while let Some(next) = work.pop() {
        steps = steps.checked_add(1)?;
        if steps > MAX_MAVEN_PROPERTY_EXPANSION_WORK {
            return None;
        }
        match next {
            Work::LeaveProperty(key) => {
                active.remove(&key);
            }
            Work::Text(text) => {
                if result.len().checked_add(text.len())? > MAX_MAVEN_EXPANDED_VALUE_BYTES {
                    return None;
                }
                result.push_str(&text);
            }
            Work::Property(key) => {
                if !active.insert(key.clone()) {
                    return None;
                }
                let replacement = properties.get(&key)?.clone();
                work.push(Work::LeaveProperty(key));
                work.push(Work::Value(replacement));
            }
            Work::Value(value) => {
                let tokens = maven_value_tokens(&value)?;
                for token in tokens.into_iter().rev() {
                    match token {
                        MavenValueToken::Text(text) => {
                            work.push(Work::Text(text));
                        }
                        MavenValueToken::Property(key) => {
                            work.push(Work::Property(key));
                        }
                    }
                }
            }
        }
    }
    Some(result.trim().to_string())
}

enum MavenValueToken {
    Text(String),
    Property(String),
}

fn maven_value_tokens(value: &str) -> Option<Vec<MavenValueToken>> {
    let mut tokens = Vec::new();
    let mut remainder = value;
    while let Some(start) = remainder.find("${") {
        let text = &remainder[..start];
        if text.contains('}') {
            return None;
        }
        if !text.is_empty() {
            tokens.push(MavenValueToken::Text(text.to_string()));
        }
        let after_start = &remainder[start + 2..];
        let end = after_start.find('}')?;
        let key = after_start[..end].trim();
        if key.is_empty() {
            return None;
        }
        tokens.push(MavenValueToken::Property(key.to_string()));
        remainder = &after_start[end + 1..];
    }
    if remainder.contains("${") || remainder.contains('}') {
        return None;
    }
    if !remainder.is_empty() {
        tokens.push(MavenValueToken::Text(remainder.to_string()));
    }
    Some(tokens)
}

fn read_bounded_source(project: &dyn Project, file: &ProjectFile) -> Option<String> {
    project
        .read_source_limited(file, MAX_BUILD_METADATA_BYTES)
        .ok()
        .flatten()
}

fn is_maven_pom(file: &ProjectFile) -> bool {
    file.rel_path()
        .file_name()
        .is_some_and(|name| name == "pom.xml")
}

fn is_gradle_lockfile(file: &ProjectFile) -> bool {
    let path = file.rel_path();
    if path
        .file_name()
        .is_some_and(|name| name == "gradle.lockfile")
    {
        return true;
    }
    path.extension()
        .is_some_and(|extension| extension == "lockfile")
        && path
            .components()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|components| {
                matches!(components, [Component::Normal(left), Component::Normal(right)] if *left == "gradle" && *right == "dependency-locks")
            })
}

fn deduplicate_discovered(discovered: &mut DiscoveredJavaDependencies) {
    let mut coordinates = HashSet::default();
    discovered
        .coordinates
        .retain(|coordinate| coordinates.insert(coordinate.clone()));
    discovered.coordinates.sort_by(|left, right| {
        (&left.group_id, &left.artifact_id, &left.version).cmp(&(
            &right.group_id,
            &right.artifact_id,
            &right.version,
        ))
    });

    let mut artifacts = HashSet::default();
    discovered.artifact_paths.retain(|artifact| {
        artifacts.insert((
            artifact.artifact_path.clone(),
            artifact.source_artifact_path.clone(),
        ))
    });
    discovered
        .artifact_paths
        .sort_by(|left, right| left.artifact_path.cmp(&right.artifact_path));
}

fn deduplicate_dependencies(dependencies: &mut JavaExternalDependencies) {
    let mut discovered = DiscoveredJavaDependencies {
        artifact_paths: std::mem::take(&mut dependencies.artifact_paths),
        coordinates: std::mem::take(&mut dependencies.coordinates),
    };
    deduplicate_discovered(&mut discovered);
    dependencies.artifact_paths = discovered.artifact_paths;
    dependencies.coordinates = discovered.coordinates;
}

#[derive(Debug, Default)]
struct XmlNode {
    name: String,
    text: String,
    children: Vec<XmlNode>,
}

impl XmlNode {
    fn child(&self, name: &str) -> Option<&XmlNode> {
        self.children.iter().find(|child| child.name == name)
    }

    fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name)
            .map(|child| child.text.trim())
            .filter(|text| !text.is_empty())
    }

    fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlNode> {
        self.children.iter().filter(move |child| child.name == name)
    }
}

fn parse_xml(source: &str) -> Option<XmlNode> {
    let mut reader = Reader::from_str(source);
    reader.config_mut().trim_text(true);
    let mut stack = Vec::<XmlNode>::new();
    let mut root = None;
    let mut buffer = Vec::new();
    let mut nodes = 0usize;
    loop {
        match reader.read_event_into(&mut buffer).ok()? {
            Event::Start(start) => {
                nodes = nodes.checked_add(1)?;
                if nodes > MAX_MAVEN_XML_NODES || stack.len() >= MAX_MAVEN_XML_DEPTH {
                    return None;
                }
                stack.push(XmlNode {
                    name: local_xml_name(start.name().as_ref())?,
                    ..XmlNode::default()
                });
            }
            Event::Empty(empty) => {
                nodes = nodes.checked_add(1)?;
                if nodes > MAX_MAVEN_XML_NODES {
                    return None;
                }
                let node = XmlNode {
                    name: local_xml_name(empty.name().as_ref())?,
                    ..XmlNode::default()
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.replace(node).is_some() {
                    return None;
                }
            }
            Event::Text(text) => {
                let decoded = text.xml10_content().ok()?;
                let decoded = quick_xml::escape::unescape(&decoded).ok()?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&decoded);
                }
            }
            Event::CData(text) => {
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&text.decode().ok()?);
                }
            }
            Event::End(_) => {
                let node = stack.pop()?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.replace(node).is_some() {
                    return None;
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    stack.is_empty().then_some(root).flatten()
}

fn local_xml_name(name: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(name).ok()?;
    Some(
        name.rsplit_once(':')
            .map(|(_, local)| local)
            .unwrap_or(name)
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{Language, TestProject};
    use std::fs;
    use std::sync::Mutex;

    #[test]
    fn java_dependency_discovery_parses_exact_maven_dependencies_only() {
        let pom = r#"
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <groupId>com.example</groupId>
              <artifactId>app</artifactId>
              <version>1.0</version>
              <properties>
                <dep.version>2.3.4</dep.version>
                <dep.group>org.example</dep.group>
              </properties>
              <dependencyManagement><dependencies><dependency>
                <groupId>ignored</groupId><artifactId>managed</artifactId><version>9</version>
              </dependency></dependencies></dependencyManagement>
              <dependencies>
                <dependency>
                  <groupId>${dep.group}</groupId><artifactId>library</artifactId>
                  <version>${dep.version}</version>
                </dependency>
                <dependency>
                  <groupId>org.example</groupId><artifactId>missing-version</artifactId>
                </dependency>
                <dependency>
                  <groupId>org.example</groupId><artifactId>classified</artifactId>
                  <version>1</version><classifier>tests</classifier>
                </dependency>
              </dependencies>
            </project>
        "#;
        let project = project(&[("pom.xml", pom), ("src/App.java", "class App {}")]);
        let discovered = discover_metadata(&project);
        assert_eq!(
            vec![JavaMavenCoordinate::new("org.example", "library", "2.3.4")],
            discovered.coordinates
        );
    }

    #[test]
    fn java_dependency_discovery_rejects_cyclic_or_unknown_maven_properties() {
        let mut properties = HashMap::default();
        properties.insert("a".to_string(), "${b}".to_string());
        properties.insert("b".to_string(), "${a}".to_string());
        assert_eq!(None, expand_maven_value("${a}", &properties));
        assert_eq!(None, expand_maven_value("${missing}", &properties));
        properties.insert("version".to_string(), "1.2.3".to_string());
        assert_eq!(
            Some("release-1.2.3".to_string()),
            expand_maven_value("release-${version}", &properties)
        );
        assert_eq!(
            Some("1.2.3-1.2.3".to_string()),
            expand_maven_value("${version}-${version}", &properties)
        );
    }

    #[test]
    fn java_dependency_discovery_bounds_maven_property_expansion() {
        let mut chain = HashMap::default();
        for index in 0..=MAX_MAVEN_PROPERTY_EXPANSION_WORK {
            chain.insert(format!("p{index}"), format!("${{p{}}}", index + 1));
        }
        chain.insert(
            format!("p{}", MAX_MAVEN_PROPERTY_EXPANSION_WORK + 1),
            "resolved".to_string(),
        );
        assert_eq!(None, expand_maven_value("${p0}", &chain));

        let mut branching = HashMap::default();
        for index in 0..20 {
            branching.insert(
                format!("p{index}"),
                format!("${{p{}}}${{p{}}}", index + 1, index + 1),
            );
        }
        branching.insert("p20".to_string(), "x".to_string());
        assert_eq!(None, expand_maven_value("${p0}", &branching));
    }

    #[test]
    fn java_dependency_discovery_bounds_maven_xml_shape() {
        let source = format!(
            "{}{}",
            "<node>".repeat(MAX_MAVEN_XML_DEPTH + 1),
            "</node>".repeat(MAX_MAVEN_XML_DEPTH + 1)
        );
        assert!(parse_xml(&source).is_none());
    }

    #[test]
    fn java_dependency_discovery_skips_system_scope_dependencies() {
        let project = project(&[(
            "pom.xml",
            "<project><dependencies><dependency><groupId>org.example</groupId><artifactId>local</artifactId><version>1</version><scope>system</scope><systemPath>/outside/workspace.jar</systemPath></dependency></dependencies></project>",
        )]);
        let discovered = discover_metadata(&project);
        assert!(discovered.coordinates.is_empty());
        assert!(discovered.artifact_paths.is_empty());
    }

    #[test]
    fn java_dependency_discovery_appends_maven_reactor_reports() {
        let args = maven_dependency_list_args(Path::new("/tmp/maven-dependencies.txt"));
        assert!(args.iter().any(|arg| arg == "-DappendOutput=true"));
    }

    #[test]
    fn java_dependency_discovery_parses_modern_and_legacy_gradle_locks() {
        let project = project(&[
            (
                "gradle.lockfile",
                "# generated\norg.example:alpha:1.0=compileClasspath\nempty=testRuntimeClasspath\n",
            ),
            (
                "gradle/dependency-locks/runtime.lockfile",
                "org.example:beta:2.0=runtimeClasspath\nmalformed\n",
            ),
            ("src/App.java", "class App {}"),
        ]);
        let discovered = discover_metadata(&project);
        assert_eq!(
            vec![
                JavaMavenCoordinate::new("org.example", "alpha", "1.0"),
                JavaMavenCoordinate::new("org.example", "beta", "2.0"),
            ],
            discovered.coordinates
        );
    }

    #[test]
    fn java_dependency_discovery_identifies_refresh_inputs() {
        let root = tempfile::tempdir().unwrap();
        for (path, expected) in [
            ("pom.xml", true),
            ("module/build.gradle.kts", true),
            ("gradle/libs.versions.toml", true),
            ("buildSrc/src/main/java/Plugin.java", true),
            ("scripts/unrelated.kts", false),
            ("src/App.java", false),
            ("README.md", false),
        ] {
            let file = ProjectFile::new(root.path().to_path_buf(), PathBuf::from(path));
            assert_eq!(expected, is_java_dependency_input(&file), "{path}");
        }
    }

    #[test]
    fn java_dependency_discovery_parses_maven_tool_records_cross_platform() {
        let report = br#"
            org.example:direct:jar:1.0:compile:/tmp/direct.jar
            org.example:transitive:jar:tests:2.0:runtime:C:\cache\transitive-tests.jar
            org.example:not-a-jar:pom:1.0:compile:/tmp/not-a-jar.pom
            malformed
            org.example:direct:jar:1.0:compile:/tmp/direct.jar
        "#;
        let records = parse_maven_dependency_list(report);
        assert_eq!(3, records.len());
        assert_eq!(
            JavaMavenCoordinate::new("org.example", "direct", "1.0"),
            records[0].coordinate
        );
        assert_eq!(PathBuf::from("/tmp/direct.jar"), records[0].artifact_path);
        assert_eq!(
            JavaMavenCoordinate::new("org.example", "transitive", "2.0"),
            records[1].coordinate
        );
        assert_eq!(
            PathBuf::from(r"C:\cache\transitive-tests.jar"),
            records[1].artifact_path
        );
    }

    #[test]
    fn java_dependency_discovery_parses_gradle_tool_records_cross_platform() {
        let report = br#"
{"group":"org.example","name":"direct","version":"1.0","file":"/tmp/direct.jar"}
{"group":"org.example","name":"classified","version":"2.0","file":"C:\\cache\\classified-tests.jar"}
malformed
{"group":"org.example","name":"direct","version":"1.0","file":"/tmp/direct.jar"}
        "#;
        let records = parse_gradle_dependency_jsonl(report);
        assert_eq!(3, records.len());
        assert_eq!(
            JavaMavenCoordinate::new("org.example", "classified", "2.0"),
            records[1].coordinate
        );
        assert_eq!(
            PathBuf::from(r"C:\cache\classified-tests.jar"),
            records[1].artifact_path
        );
    }

    #[test]
    fn java_dependency_discovery_fake_executor_merges_partial_build_results() {
        let project = project(&[
            (
                "pom.xml",
                "<project><modules><module>child</module></modules></project>",
            ),
            ("child/pom.xml", "<project/>"),
            ("other/pom.xml", "<project/>"),
            ("settings.gradle.kts", "rootProject.name = \"root\""),
            ("module/build.gradle.kts", "plugins { java }"),
            ("standalone/build.gradle", "plugins { id 'java' }"),
            ("src/App.java", "class App {}"),
        ]);
        let maven_jar = project.root().join("maven.jar");
        let gradle_jar = project.root().join("gradle-tests.jar");
        fs::write(&maven_jar, []).unwrap();
        fs::write(&gradle_jar, []).unwrap();
        let root = stable_path(project.root());
        let other_root = stable_path(project.root().join("other"));
        let standalone_root = stable_path(project.root().join("standalone"));
        let executor = FakeExecutor::new(
            PathBuf::from("trusted-mvn"),
            PathBuf::from("trusted-gradle"),
            [(
                root.clone(),
                Ok(format!(
                    "org.example:maven:jar:1.0:compile:{}\norg.example:maven:jar:1.0:runtime:{}\norg.example:absent:jar:9.0:test:{}\n",
                    maven_jar.display(),
                    maven_jar.display(),
                    project.root().join("absent.jar").display()
                )
                .into_bytes()),
            ), (other_root, Err("missing tool".to_string()))],
            [
                (
                    root,
                    Ok(format!(
                        "{{\"group\":\"org.example\",\"name\":\"gradle\",\"version\":\"2.0\",\"file\":{}}}\n",
                        serde_json::to_string(&gradle_jar.display().to_string()).unwrap()
                    )
                    .into_bytes()),
                ),
                (standalone_root, Err("timed out".to_string())),
            ],
        );
        let config = JavaDependencyDiscoveryConfig {
            maven_executable: Some(PathBuf::from("trusted-mvn")),
            gradle_executable: Some(PathBuf::from("trusted-gradle")),
            ..JavaDependencyDiscoveryConfig::default()
        };

        let discovered = discover_build_tools_with_executor(&project, &config, &executor);
        assert_eq!(
            vec![
                JavaMavenCoordinate::new("org.example", "gradle", "2.0"),
                JavaMavenCoordinate::new("org.example", "maven", "1.0"),
            ],
            discovered.coordinates
        );
        assert_eq!(2, discovered.artifact_paths.len());
        assert_eq!(3, executor.calls.lock().unwrap().len());
    }

    #[test]
    fn java_dependency_discovery_fake_executor_failures_are_empty() {
        let project = project(&[
            ("pom.xml", "<project/>"),
            ("timeout/pom.xml", "<project/>"),
            ("settings.gradle", "rootProject.name = 'root'"),
            ("src/App.java", "class App {}"),
        ]);
        let root = stable_path(project.root());
        let timeout_root = stable_path(project.root().join("timeout"));
        let executor = FakeExecutor::new(
            PathBuf::from("mvn"),
            PathBuf::from("gradle"),
            [
                (root.clone(), Err("executable missing".to_string())),
                (timeout_root, Err("timed out".to_string())),
            ],
            [(root, Err("nonzero exit".to_string()))],
        );
        let discovered = discover_build_tools_with_executor(
            &project,
            &JavaDependencyDiscoveryConfig::default(),
            &executor,
        );
        assert!(discovered.coordinates.is_empty());
        assert!(discovered.artifact_paths.is_empty());
        assert_eq!(3, executor.calls.lock().unwrap().len());
    }

    struct FakeExecutor {
        expected_maven: PathBuf,
        expected_gradle: PathBuf,
        maven: HashMap<PathBuf, Result<Vec<u8>, String>>,
        gradle: HashMap<PathBuf, Result<Vec<u8>, String>>,
        calls: Mutex<Vec<(String, PathBuf)>>,
    }

    impl FakeExecutor {
        fn new(
            expected_maven: PathBuf,
            expected_gradle: PathBuf,
            maven: impl IntoIterator<Item = (PathBuf, Result<Vec<u8>, String>)>,
            gradle: impl IntoIterator<Item = (PathBuf, Result<Vec<u8>, String>)>,
        ) -> Self {
            Self {
                expected_maven,
                expected_gradle,
                maven: maven.into_iter().collect(),
                gradle: gradle.into_iter().collect(),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl DependencyCommandExecutor for FakeExecutor {
        fn maven_report(
            &self,
            root: &Path,
            executable: &Path,
            _config: &JavaDependencyDiscoveryConfig,
        ) -> Result<Vec<u8>, String> {
            assert_eq!(self.expected_maven, executable);
            self.calls
                .lock()
                .unwrap()
                .push(("maven".to_string(), root.to_path_buf()));
            self.maven
                .get(root)
                .cloned()
                .unwrap_or_else(|| Err("unexpected Maven root".to_string()))
        }

        fn gradle_report(
            &self,
            root: &Path,
            executable: &Path,
            _config: &JavaDependencyDiscoveryConfig,
        ) -> Result<Vec<u8>, String> {
            assert_eq!(self.expected_gradle, executable);
            self.calls
                .lock()
                .unwrap()
                .push(("gradle".to_string(), root.to_path_buf()));
            self.gradle
                .get(root)
                .cloned()
                .unwrap_or_else(|| Err("unexpected Gradle root".to_string()))
        }
    }

    fn project(files: &[(&str, &str)]) -> TestProject {
        let root = tempfile::tempdir().unwrap().keep();
        for (path, source) in files {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
        TestProject::new(root, Language::Java)
    }
}
