use crate::analyzer::store::maven_xml::MAX_BUILD_METADATA_BYTES;
use crate::analyzer::store::maven_xml::expand_maven_value;
use crate::analyzer::store::maven_xml::maven_project_properties;
use crate::analyzer::store::maven_xml::parse_xml;
use std::path::Path;
use std::path::PathBuf;

use crate::analyzer::topology::DependencyScope;
use crate::hash::HashMap;

/// A source visibility domain derived from selected package metadata and paths.
/// It is query-owned evidence, not a discovered build project.
#[derive(Debug, PartialEq, Eq)]
pub struct JvmSourceDomain {
    pub root: PathBuf,
}

impl JvmSourceDomain {
    pub fn discover(path: &Path, package: &str, requires_directory: bool) -> Option<Self> {
        let directory = path.parent()?;
        // Layout conventions also support Kotlin/Scala packages whose directory
        // does not mirror the declared package. Prefer the innermost source root.
        for root in directory.ancestors() {
            if source_set(root).is_some() {
                return Some(Self {
                    root: root.to_owned(),
                });
            }
        }
        let mut root = directory;
        for segment in package
            .split('.')
            .rev()
            .filter(|segment| !segment.is_empty())
        {
            if root.file_name() != Some(std::ffi::OsStr::new(segment)) {
                return (!requires_directory).then(|| Self {
                    root: directory.to_owned(),
                });
            }
            root = root.parent()?;
        }
        Some(Self {
            root: root.to_owned(),
        })
    }

    pub fn can_access(&self, target: &Self) -> bool {
        if self.root == target.root {
            return true;
        }
        let (Some((module, caller_set)), Some((target_module, target_set))) =
            (source_set(&self.root), source_set(&target.root))
        else {
            return false;
        };
        module == target_module && source_set_sees(caller_set, target_set)
    }
}

/// JVM layout rule. These are path components, not source syntax.
pub fn source_set(root: &Path) -> Option<(&Path, &str)> {
    let name = root.file_name()?.to_str()?;
    let set = if matches!(name, "java" | "kotlin" | "scala") {
        root.parent()?
    } else if matches!(name, "main" | "test") {
        root
    } else {
        return None;
    };
    let name = set.file_name()?.to_str()?;
    let src = set.parent()?;
    (src.file_name()? == "src").then_some((src.parent().unwrap_or(Path::new("")), name))
}

/// Conventional JVM source-set dependencies, directed from caller to target.
pub fn source_set_sees(caller: &str, target: &str) -> bool {
    const DEPENDENCIES: &[(&str, &str)] = &[
        ("test", "main"),
        ("jvmTest", "jvmMain"),
        ("jvmTest", "commonMain"),
    ];
    caller == target
        || DEPENDENCIES.contains(&(caller, target))
        || (target == "commonMain" && caller.ends_with("Main"))
}

/// The `src/main` and `src/test` roles Maven's default lifecycle fixes.
pub const MAVEN_SOURCE_SETS: [(&str, &str); 2] = [("main", "src/main"), ("test", "src/test")];

/// A declared value retains failed interpolation separately from absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MavenValue {
    Missing,
    Unresolved,
    Resolved(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MavenModelLimitation {
    ParentModel,
    Profiles,
    DependencyManagement,
    CustomSourceRoots,
    BuildPlugins,
}

/// Direct declarations in one selected pom, not an effective Maven model.
/// The caller retains the selected configuration file-version/content identity.
#[derive(Debug)]
pub struct MavenConfigurationFacts {
    pub directory: PathBuf,
    pub group_id: String,
    pub artifact_id: String,
    pub version: MavenValue,
    pub modules: Vec<MavenValue>,
    pub dependencies: Vec<MavenDependencyFacts>,
    pub limitations: Vec<MavenModelLimitation>,
}

impl MavenConfigurationFacts {
    pub fn default_source_roots(&self) -> [(&'static str, PathBuf); 2] {
        MAVEN_SOURCE_SETS.map(|(role, relative)| (role, self.directory.join(relative)))
    }
}

#[derive(Debug)]
pub struct MavenDependencyFacts {
    pub ordinal: u32,
    pub group_id: MavenValue,
    pub artifact_id: MavenValue,
    pub version: MavenValue,
    pub artifact_type: MavenValue,
    pub classifier: MavenValue,
    pub scope: MavenValue,
    pub optional: MavenValue,
    // Keep the established display topology's literal optional interpretation.
    pub topology_kind: DependencyScope,
}

/// Parse one exact configuration without consulting other files or the host.
/// Absence, malformed XML, invalid UTF-8, an oversized input or an unresolved
/// required project coordinate cannot supply a named Maven project.
pub fn maven_configuration_from_bytes(
    pom_path: &Path,
    source: &[u8],
) -> Option<MavenConfigurationFacts> {
    if source.len() > MAX_BUILD_METADATA_BYTES {
        return None;
    }
    read_maven_configuration(pom_path, std::str::from_utf8(source).ok()?)
}

pub fn maven_value(value: Option<&str>, properties: &HashMap<String, String>) -> MavenValue {
    match value {
        None => MavenValue::Missing,
        Some(value) => expand_maven_value(value, properties)
            .map(MavenValue::Resolved)
            .unwrap_or(MavenValue::Unresolved),
    }
}

pub fn read_maven_configuration(path: &Path, source: &str) -> Option<MavenConfigurationFacts> {
    let node = parse_xml(source)?;
    if node.name != "project" {
        return None;
    }
    let properties = maven_project_properties(&node);
    let parent = node.child("parent");
    let MavenValue::Resolved(group_id) = maven_value(
        node.child_text("groupId")
            .or_else(|| parent.and_then(|parent| parent.child_text("groupId"))),
        &properties,
    ) else {
        return None;
    };
    let MavenValue::Resolved(artifact_id) = maven_value(node.child_text("artifactId"), &properties)
    else {
        return None;
    };
    if group_id.is_empty() || artifact_id.is_empty() {
        return None;
    }
    let version = maven_value(
        node.child_text("version")
            .or_else(|| parent.and_then(|parent| parent.child_text("version"))),
        &properties,
    );
    let directory = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let modules = node
        .child("modules")
        .map(|modules| {
            modules
                .children_named("module")
                .map(|module| maven_value(Some(module.text.trim()), &properties))
                .collect()
        })
        .unwrap_or_default();
    let dependencies = node
        .child("dependencies")
        .map(|dependencies| {
            dependencies
                .children_named("dependency")
                .enumerate()
                .map(|(ordinal, dependency)| {
                    let scope = maven_value(dependency.child_text("scope"), &properties);
                    let optional_literal = dependency
                        .child_text("optional")
                        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
                    // An absent scope is Maven's compile default; a scope whose
                    // property does not resolve is not known to be compile.
                    let topology_kind = if optional_literal {
                        DependencyScope::Optional
                    } else {
                        match &scope {
                            MavenValue::Resolved(value) => maven_scope_edge_kind(Some(value)),
                            MavenValue::Missing => maven_scope_edge_kind(None),
                            MavenValue::Unresolved => DependencyScope::Unknown,
                        }
                    };
                    MavenDependencyFacts {
                        ordinal: u32::try_from(ordinal)
                            .expect("bounded XML node inventory fits u32"),
                        group_id: maven_value(dependency.child_text("groupId"), &properties),
                        artifact_id: maven_value(dependency.child_text("artifactId"), &properties),
                        version: maven_value(dependency.child_text("version"), &properties),
                        artifact_type: maven_value(dependency.child_text("type"), &properties),
                        classifier: maven_value(dependency.child_text("classifier"), &properties),
                        scope,
                        optional: maven_value(dependency.child_text("optional"), &properties),
                        topology_kind,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let mut limitations = Vec::new();
    if parent.is_some() {
        limitations.push(MavenModelLimitation::ParentModel);
    }
    if node.child("profiles").is_some() {
        limitations.push(MavenModelLimitation::Profiles);
    }
    if node.child("dependencyManagement").is_some() {
        limitations.push(MavenModelLimitation::DependencyManagement);
    }
    if let Some(build) = node.child("build") {
        if build.child("sourceDirectory").is_some() || build.child("testSourceDirectory").is_some()
        {
            limitations.push(MavenModelLimitation::CustomSourceRoots);
        }
        if build.child("plugins").is_some()
            || build.child("pluginManagement").is_some()
            || build.child("extensions").is_some()
        {
            limitations.push(MavenModelLimitation::BuildPlugins);
        }
    }
    Some(MavenConfigurationFacts {
        directory,
        group_id,
        artifact_id,
        version,
        modules,
        dependencies,
        limitations,
    })
}

/// The Maven scope vocabulary as topology edge kinds. An absent scope is
/// `compile` by Maven's own default; a scope this reader does not model stays
/// [`DependencyScope::Unknown`] rather than being folded into the nearest
/// match.
pub fn maven_scope_edge_kind(scope: Option<&str>) -> DependencyScope {
    match scope.map(str::trim) {
        None | Some("") | Some("compile") => DependencyScope::Compile,
        Some("runtime") => DependencyScope::Runtime,
        Some("test") => DependencyScope::Test,
        Some("provided") => DependencyScope::Provided,
        Some(_) => DependencyScope::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    fn pom(path: &str, source: &str) -> Option<MavenConfigurationFacts> {
        maven_configuration_from_bytes(Path::new(path), source.as_bytes())
    }

    fn resolved(value: &str) -> MavenValue {
        MavenValue::Resolved(value.to_owned())
    }

    /// A child module pom in the shape Maven's CI-friendly versions produce:
    /// groupId and version come from `<parent>`, the version is `${revision}`,
    /// and properties refer to other properties and to `project.*` values.
    #[test]
    fn child_pom_inherits_parent_coordinates_and_expands_nested_properties() {
        let source = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.acme</groupId>
    <artifactId>acme-parent</artifactId>
    <version>${revision}</version>
  </parent>
  <artifactId>billing</artifactId>
  <properties>
    <revision>2.4.0</revision>
    <slf4j.version>2.0.13</slf4j.version>
    <logging.version>${slf4j.version}</logging.version>
    <sibling.version>${project.version}</sibling.version>
  </properties>
  <modules>
    <module>${project.artifactId}-api</module>
    <module> core </module>
    <module>${undefined.module}</module>
  </modules>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${logging.version}</version>
    </dependency>
    <!-- a sibling module of the same reactor -->
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>billing-model</artifactId>
      <version>${sibling.version}</version>
      <classifier>${undefined.classifier}</classifier>
    </dependency>
  </dependencies>
</project>
"#;
        let facts = pom("services/billing/pom.xml", source).expect("a named Maven project");
        assert_eq!(facts.directory, PathBuf::from("services/billing"));
        assert_eq!(facts.group_id, "com.acme");
        assert_eq!(facts.artifact_id, "billing");
        assert_eq!(facts.version, resolved("2.4.0"));
        assert_eq!(
            facts.modules,
            vec![
                resolved("billing-api"),
                resolved("core"),
                MavenValue::Unresolved
            ]
        );
        assert_eq!(facts.limitations, vec![MavenModelLimitation::ParentModel]);
        assert_eq!(
            facts.default_source_roots(),
            [
                ("main", PathBuf::from("services/billing/src/main")),
                ("test", PathBuf::from("services/billing/src/test")),
            ]
        );

        let [logging, sibling] = facts.dependencies.as_slice() else {
            panic!("two dependencies: {:?}", facts.dependencies);
        };
        assert_eq!(logging.ordinal, 0);
        assert_eq!(logging.group_id, resolved("org.slf4j"));
        assert_eq!(logging.version, resolved("2.0.13"));
        assert_eq!(logging.scope, MavenValue::Missing);
        assert_eq!(logging.artifact_type, MavenValue::Missing);
        assert_eq!(logging.optional, MavenValue::Missing);
        assert_eq!(logging.topology_kind, DependencyScope::Compile);
        assert_eq!(sibling.ordinal, 1);
        assert_eq!(sibling.group_id, resolved("com.acme"));
        assert_eq!(sibling.artifact_id, resolved("billing-model"));
        assert_eq!(sibling.version, resolved("2.4.0"));
        assert_eq!(sibling.classifier, MavenValue::Unresolved);

        // A pom's own groupId and version override the parent's; artifactId
        // is never inherited.
        let own = pom(
            "pom.xml",
            "<project><parent><groupId>parent.group</groupId><artifactId>base</artifactId>\
             <version>1.0</version></parent><groupId>own.group</groupId>\
             <artifactId>app</artifactId><version>9.1</version></project>",
        )
        .expect("a named Maven project");
        assert_eq!(own.group_id, "own.group");
        assert_eq!(own.artifact_id, "app");
        assert_eq!(own.version, resolved("9.1"));
        assert_eq!(own.directory, PathBuf::new());
    }

    #[test]
    fn pom_without_a_resolvable_named_project_yields_no_facts() {
        let accepted = "<project><groupId>g</groupId><artifactId>a</artifactId></project>";
        let control = pom("pom.xml", accepted).expect("the control pom names a project");
        assert_eq!(control.version, MavenValue::Missing);
        assert!(control.limitations.is_empty());

        for (label, source) in [
            (
                "root is not <project>",
                "<settings><groupId>g</groupId><artifactId>a</artifactId></settings>",
            ),
            (
                "artifactId is not inherited from the parent",
                "<project><parent><groupId>g</groupId><artifactId>p</artifactId>\
                 <version>1</version></parent></project>",
            ),
            (
                "no groupId and no parent",
                "<project><artifactId>a</artifactId></project>",
            ),
            (
                "whitespace-only groupId and no parent",
                "<project><groupId>  </groupId><artifactId>a</artifactId></project>",
            ),
            (
                "groupId names an undefined property",
                "<project><groupId>${undefined}</groupId><artifactId>a</artifactId></project>",
            ),
            (
                "artifactId refers to itself",
                "<project><groupId>g</groupId><artifactId>${project.artifactId}</artifactId>\
                 </project>",
            ),
            (
                "mismatched end tag",
                "<project><groupId>g</artifactId><artifactId>a</artifactId></project>",
            ),
            (
                "unclosed root",
                "<project><groupId>g</groupId><artifactId>a</artifactId>",
            ),
        ] {
            let facts = pom("pom.xml", source);
            assert!(facts.is_none(), "{label}: {facts:?}");
        }

        // Invalid UTF-8 inside a comment would still parse after lossy
        // decoding; the exact bytes are not a readable configuration.
        let mut invalid_utf8 =
            b"<project><groupId>g</groupId><artifactId>a</artifactId><!-- ".to_vec();
        invalid_utf8.extend_from_slice(&[0xff, 0xfe]);
        invalid_utf8.extend_from_slice(b" --></project>");
        assert!(pom("pom.xml", &String::from_utf8_lossy(&invalid_utf8)).is_some());
        assert!(maven_configuration_from_bytes(Path::new("pom.xml"), &invalid_utf8).is_none());

        // The byte cap is inclusive: a pom of exactly the cap is read.
        let at_cap = format!(
            "{accepted}{}",
            " ".repeat(MAX_BUILD_METADATA_BYTES - accepted.len())
        );
        assert_eq!(at_cap.len(), MAX_BUILD_METADATA_BYTES);
        assert!(pom("pom.xml", &at_cap).is_some());
        let over_cap = format!("{at_cap} ");
        assert!(pom("pom.xml", &over_cap).is_none());
    }

    /// Maven's scope vocabulary: an absent scope is `compile`; `system` and
    /// `import` are real Maven scopes this reader does not model.
    #[test]
    fn dependency_scopes_become_topology_edge_kinds() {
        let dependency = |scope: &str, optional: &str| {
            format!(
                "<dependency><groupId>g</groupId><artifactId>d</artifactId>{scope}{optional}</dependency>"
            )
        };
        let cases = [
            ("", "", DependencyScope::Compile),
            ("<scope>compile</scope>", "", DependencyScope::Compile),
            ("<scope> runtime </scope>", "", DependencyScope::Runtime),
            ("<scope>test</scope>", "", DependencyScope::Test),
            ("<scope>provided</scope>", "", DependencyScope::Provided),
            ("<scope>system</scope>", "", DependencyScope::Unknown),
            ("<scope>import</scope>", "", DependencyScope::Unknown),
            ("<scope>${test.scope}</scope>", "", DependencyScope::Test),
            (
                "<scope>test</scope>",
                "<optional>TRUE</optional>",
                DependencyScope::Optional,
            ),
            (
                "<scope>provided</scope>",
                "<optional>false</optional>",
                DependencyScope::Provided,
            ),
        ];
        let dependencies: String = cases
            .iter()
            .map(|(scope, optional, _)| dependency(scope, optional))
            .collect();
        let source = format!(
            "<project><groupId>g</groupId><artifactId>a</artifactId>\
             <properties><test.scope>test</test.scope></properties>\
             <dependencies>{dependencies}</dependencies></project>"
        );
        let facts = pom("pom.xml", &source).expect("a named Maven project");
        let actual: Vec<_> = facts
            .dependencies
            .iter()
            .map(|dependency| (dependency.ordinal, dependency.topology_kind))
            .collect();
        let expected: Vec<_> = (0u32..)
            .zip(cases.iter().map(|(_, _, kind)| *kind))
            .collect();
        assert_eq!(actual, expected);
    }

    /// `DependencyScope::Unknown` documents that a resolver which cannot
    /// attribute a dependency to a scope must write Unknown, not guess.
    #[test]
    #[hardwon("4961f92aee92: an unresolved ${...} dependency scope was read as compile")]
    fn unresolved_dependency_scope_is_unknown_not_compile() {
        let facts = pom(
            "pom.xml",
            "<project><groupId>g</groupId><artifactId>a</artifactId><dependencies>\
             <dependency><groupId>g</groupId><artifactId>d</artifactId>\
             <scope>${undefined.scope}</scope></dependency></dependencies></project>",
        )
        .expect("a named Maven project");
        assert_eq!(facts.dependencies[0].scope, MavenValue::Unresolved);
        assert_eq!(
            facts.dependencies[0].topology_kind,
            DependencyScope::Unknown
        );
    }

    fn domain(path: &str, package: &str, requires_directory: bool) -> Option<PathBuf> {
        JvmSourceDomain::discover(Path::new(path), package, requires_directory)
            .map(|domain| domain.root)
    }

    /// Source domains follow the Maven and Gradle `src/<set>/<language>`
    /// layout first and the package-mirrors-directory rule otherwise.
    #[test]
    fn source_domains_follow_jvm_layout_and_package_directories() {
        for (path, package, requires_directory, expected) in [
            (
                "w/app/src/main/java/com/acme/Order.java",
                "com.acme",
                true,
                Some("w/app/src/main/java"),
            ),
            // Kotlin does not require the directory to mirror the package.
            (
                "w/app/src/test/kotlin/OrderTest.kt",
                "com.acme",
                false,
                Some("w/app/src/test/kotlin"),
            ),
            // A package segment named like a source set is not a source root.
            (
                "w/app/src/main/java/org/test/Fixture.java",
                "org.test",
                true,
                Some("w/app/src/main/java"),
            ),
            (
                "w/app/src/main/java/org/java/Util.java",
                "org.java",
                true,
                Some("w/app/src/main/java"),
            ),
            (
                "w/kmp/src/commonMain/kotlin/a/Shared.kt",
                "a",
                false,
                Some("w/kmp/src/commonMain/kotlin"),
            ),
            // Without a layout, the package directories locate the root.
            ("w/lib/com/acme/Order.java", "com.acme", true, Some("w/lib")),
            ("w/lib/Order.java", "", true, Some("w/lib")),
            ("w/lib/com/other/Order.java", "com.acme", true, None),
            (
                "w/lib/com/other/Order.kt",
                "com.acme",
                false,
                Some("w/lib/com/other"),
            ),
        ] {
            assert_eq!(
                domain(path, package, requires_directory),
                expected.map(PathBuf::from),
                "{path} in package {package:?}"
            );
        }
    }

    #[test]
    fn source_sets_see_their_conventional_dependencies() {
        let root = |path: &str| JvmSourceDomain {
            root: PathBuf::from(path),
        };
        let main = root("w/app/src/main/java");
        let main_kotlin = root("w/app/src/main/kotlin");
        let test = root("w/app/src/test/java");
        let other_main = root("w/lib/src/main/java");
        let common_main = root("w/kmp/src/commonMain/kotlin");
        let jvm_main = root("w/kmp/src/jvmMain/kotlin");
        let jvm_test = root("w/kmp/src/jvmTest/kotlin");
        let ios_main = root("w/kmp/src/iosMain/kotlin");
        let plain = root("w/plain");
        for (caller, target, expected) in [
            (&test, &main, true),
            (&main, &test, false),
            // Java and Kotlin directories of one source set are one set.
            (&main, &main_kotlin, true),
            (&test, &other_main, false),
            (&jvm_test, &jvm_main, true),
            (&jvm_test, &common_main, true),
            (&ios_main, &common_main, true),
            (&common_main, &jvm_main, false),
            (&jvm_main, &ios_main, false),
            (&plain, &plain, true),
            (&plain, &main, false),
            (&main, &plain, false),
        ] {
            assert_eq!(
                caller.can_access(target),
                expected,
                "{:?} -> {:?}",
                caller.root,
                target.root
            );
        }
    }
}
