use crate::analyzer::{
    JavaExternalArtifact, JavaExternalDependencies, JavaMavenCoordinate, Project, ProjectFile,
};
use crate::hash::{HashMap, HashSet};
use quick_xml::Reader;
use quick_xml::events::Event;
use std::path::{Component, PathBuf};

const MAX_BUILD_METADATA_BYTES: usize = 2 * 1024 * 1024;

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

#[cfg(test)]
pub(super) fn is_java_dependency_input(file: &ProjectFile) -> bool {
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
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "gradle" | "kts" | "lockfile"))
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

        if scope == "system" {
            let Some(system_path) = dependency.child_text("systemPath") else {
                continue;
            };
            let Some(system_path) = expand_maven_value(system_path, &properties) else {
                continue;
            };
            let path = PathBuf::from(system_path);
            let path = if path.is_absolute() {
                path
            } else {
                file.parent().join(path)
            };
            if path.is_file() {
                discovered.artifact_paths.push(JavaExternalArtifact {
                    artifact_path: path,
                    source_artifact_path: None,
                });
            }
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

fn expand_maven_value(value: &str, properties: &HashMap<String, String>) -> Option<String> {
    fn expand(
        value: &str,
        properties: &HashMap<String, String>,
        active: &mut HashSet<String>,
    ) -> Option<String> {
        let mut result = String::new();
        let mut remainder = value.trim();
        while let Some(start) = remainder.find("${") {
            result.push_str(&remainder[..start]);
            let after_start = &remainder[start + 2..];
            let end = after_start.find('}')?;
            let key = after_start[..end].trim();
            if key.is_empty() || !active.insert(key.to_string()) {
                return None;
            }
            let replacement = properties.get(key)?;
            result.push_str(&expand(replacement, properties, active)?);
            active.remove(key);
            remainder = &after_start[end + 1..];
        }
        if remainder.contains("${") || remainder.contains('}') {
            return None;
        }
        result.push_str(remainder);
        Some(result.trim().to_string())
    }

    expand(value, properties, &mut HashSet::default())
}

fn read_bounded_source(project: &dyn Project, file: &ProjectFile) -> Option<String> {
    let source = project.read_source(file).ok()?;
    (source.len() <= MAX_BUILD_METADATA_BYTES).then_some(source)
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
    loop {
        match reader.read_event_into(&mut buffer).ok()? {
            Event::Start(start) => stack.push(XmlNode {
                name: local_xml_name(start.name().as_ref())?,
                ..XmlNode::default()
            }),
            Event::Empty(empty) => {
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
            ("src/App.java", false),
            ("README.md", false),
        ] {
            let file = ProjectFile::new(root.path().to_path_buf(), PathBuf::from(path));
            assert_eq!(expected, is_java_dependency_input(&file), "{path}");
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
