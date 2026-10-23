use crate::analyzer::jvm::external::*;
#[cfg(test)]
use brokk_bifrost_core::analyzer::config::JvmMavenCoordinate;
use std::fs;
use std::process::Command;
#[doc(hidden)]
pub struct ExternalJarFixture {
    _temp: tempfile::TempDir,
    pub(in crate::analyzer::jvm::external) root: PathBuf,
    pub(in crate::analyzer::jvm::external) workspace_root: PathBuf,
}
impl ExternalJarFixture {
    #[doc(hidden)]
    pub fn new(include_sources: bool) -> Option<Self> {
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
        let other_package_dir = source_dir.join("com/example/other");
        let classes_dir = root.join("dep-classes");
        fs::create_dir_all(&workspace_root).unwrap();
        fs::create_dir_all(&repo_dir).unwrap();
        fs::create_dir_all(&package_dir).unwrap();
        fs::create_dir_all(&other_package_dir).unwrap();
        fs::create_dir_all(&classes_dir).unwrap();

        fs::write(
                package_dir.join("ExternalService.java"),
                "package com.example.dep;\n\
                 public class ExternalService {\n\
                   public String echo(String name) { return name; }\n\
                   public static class Nested {}\n\
                   protected static class ProtectedNested {}\n\
                   @Deprecated(since = \"public\") protected static class AnnotatedProtectedNested {}\n\
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
        fs::write(
            package_dir.join("PackageOuter.java"),
            "package com.example.dep; class PackageOuter { public static class Nested {} }\n",
        )
        .unwrap();
        fs::write(
            package_dir.join("PublicApi.java"),
            "package com.example.dep; public interface PublicApi { interface Callback {} }\n",
        )
        .unwrap();
        fs::write(
            package_dir.join("Foo.java"),
            "package com.example.dep; public class Foo {}\n",
        )
        .unwrap();
        fs::write(
            other_package_dir.join("Foo.java"),
            "package com.example.other; public class Foo {}\n",
        )
        .unwrap();

        brokk_bifrost_analysis::test_support::run_command_success(
            Command::new("javac")
                .arg("-d")
                .arg(&classes_dir)
                .arg(package_dir.join("ExternalService.java"))
                .arg(package_dir.join("ExternalInterface.java"))
                .arg(package_dir.join("ExternalHelper.java"))
                .arg(package_dir.join("PackageHelper.java"))
                .arg(package_dir.join("PackageOuter.java"))
                .arg(package_dir.join("PublicApi.java"))
                .arg(package_dir.join("Foo.java"))
                .arg(other_package_dir.join("Foo.java")),
        );
        brokk_bifrost_analysis::test_support::run_command_success(
            Command::new("jar")
                .current_dir(&classes_dir)
                .arg("cf")
                .arg(repo_dir.join(BINARY_JAR))
                .arg("."),
        );
        if include_sources {
            brokk_bifrost_analysis::test_support::run_command_success(
                Command::new("jar")
                    .current_dir(&source_dir)
                    .arg("cf")
                    .arg(repo_dir.join(SOURCE_JAR))
                    .arg("."),
            );
        }

        Some(Self {
            _temp: temp,
            root,
            workspace_root,
        })
    }

    #[doc(hidden)]
    pub fn project_root(&self) -> &Path {
        &self.workspace_root
    }

    #[cfg(test)]
    pub(in crate::analyzer::jvm::external) fn jar_path(&self, name: &str) -> PathBuf {
        self.root.join("m2").join(GROUP_PATH).join(name)
    }

    #[cfg(test)]
    pub(in crate::analyzer::jvm::external) fn source_jar_path(&self) -> PathBuf {
        self.jar_path(SOURCE_JAR)
    }

    #[cfg(test)]
    pub(in crate::analyzer::jvm::external) fn binary_jar_path(&self) -> PathBuf {
        self.jar_path(BINARY_JAR)
    }

    #[doc(hidden)]
    pub fn maven_repository_root(&self) -> PathBuf {
        self.root.join("m2")
    }

    #[cfg(test)]
    pub(in crate::analyzer::jvm::external) fn coordinate_config(&self) -> JvmExternalDependencies {
        JvmExternalDependencies {
            coordinates: vec![JvmMavenCoordinate::new(
                "com.example",
                "external-lib",
                "1.2.3",
            )],
            repository_roots: vec![self.root.join("m2")],
            ..JvmExternalDependencies::default()
        }
    }
}

pub(in crate::analyzer::jvm::external) const GROUP_PATH: &str = "com/example/external-lib/1.2.3";

pub(in crate::analyzer::jvm::external) fn jdk_tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

pub(in crate::analyzer::jvm::external) const BINARY_JAR: &str = "external-lib-1.2.3.jar";

pub(in crate::analyzer::jvm::external) const SOURCE_JAR: &str = "external-lib-1.2.3-sources.jar";
