use super::aliases::php_namespace_to_fq;
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct PhpComposerAutoload {
    psr4_roots: Vec<Psr4Root>,
}

impl PhpComposerAutoload {
    pub fn from_project(project: &dyn Project) -> Self {
        let Some(manifest) = composer_manifest_file(project) else {
            return Self::default();
        };
        let Ok(source) = project.read_source(&manifest) else {
            return Self::default();
        };
        let Ok(json) = serde_json::from_str::<Value>(&source) else {
            return Self::default();
        };

        let mut roots = Vec::new();
        collect_psr4_roots(json.get("autoload"), &mut roots);
        collect_psr4_roots(json.get("autoload-dev"), &mut roots);
        Self { psr4_roots: roots }
    }

    pub fn manifest_changed(file: &ProjectFile) -> bool {
        file.rel_path() == Path::new("composer.json")
    }

    pub fn is_empty(&self) -> bool {
        self.psr4_roots.is_empty()
    }

    pub fn target_is_autoloaded(&self, index: &dyn CodeUnitIndex, target: &CodeUnit) -> bool {
        if self.is_empty() {
            return false;
        }
        if target.is_class() {
            return self.class_is_autoloaded(target);
        }
        index
            .parent_of(target)
            .as_ref()
            .is_some_and(|owner| self.class_is_autoloaded(owner))
    }

    pub fn class_is_autoloaded(&self, class_unit: &CodeUnit) -> bool {
        class_unit.is_class()
            && self
                .psr4_roots
                .iter()
                .any(|root| root.matches_class(class_unit.fq_name().as_str(), class_unit.source()))
    }
}

fn composer_manifest_file(project: &dyn Project) -> Option<ProjectFile> {
    let rel_path = Path::new("composer.json");
    project.file_by_rel_path(rel_path).or_else(|| {
        let file = ProjectFile::new(project.root().to_path_buf(), rel_path);
        project.has_overlay(&file).then_some(file)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Psr4Root {
    namespace: String,
    paths: Vec<PathBuf>,
}

impl Psr4Root {
    fn matches_class(&self, fq_name: &str, file: &ProjectFile) -> bool {
        let Some(remainder) = namespace_remainder(fq_name, &self.namespace) else {
            return false;
        };
        let class_path = dotted_fqn_to_path(remainder);
        self.paths
            .iter()
            .map(|path| normalize_rel_path(path.join(&class_path)))
            .any(|expected| expected == normalize_rel_path(file.rel_path()))
    }
}

fn collect_psr4_roots(section: Option<&Value>, roots: &mut Vec<Psr4Root>) {
    let Some(psr4) = section.and_then(|section| section.get("psr-4")) else {
        return;
    };
    let Some(entries) = psr4.as_object() else {
        return;
    };
    for (namespace, paths) in entries {
        let paths = composer_paths(paths);
        if paths.is_empty() {
            continue;
        }
        roots.push(Psr4Root {
            namespace: php_namespace_to_fq(namespace),
            paths,
        });
    }
}

fn composer_paths(value: &Value) -> Vec<PathBuf> {
    match value {
        Value::String(path) => normalized_composer_path(path).into_iter().collect(),
        Value::Array(paths) => {
            let mut seen = HashSet::default();
            paths
                .iter()
                .filter_map(Value::as_str)
                .filter_map(normalized_composer_path)
                .filter(|path| seen.insert(path.clone()))
                .collect()
        }
        _ => Vec::new(),
    }
}

fn normalized_composer_path(path: &str) -> Option<PathBuf> {
    let normalized = path.trim().replace('\\', "/");
    if normalized.is_empty() {
        return Some(PathBuf::new());
    }
    normalize_project_relative_path(Path::new(&normalized))
}

fn namespace_remainder<'a>(fq_name: &'a str, namespace: &str) -> Option<&'a str> {
    if namespace.is_empty() {
        return Some(fq_name);
    }
    if fq_name == namespace {
        return Some("");
    }
    fq_name
        .strip_prefix(namespace)
        .and_then(|rest| rest.strip_prefix('.'))
}

fn dotted_fqn_to_path(fq_name: &str) -> PathBuf {
    let mut path = PathBuf::new();
    for part in fq_name.split('.').filter(|part| !part.is_empty()) {
        path.push(part);
    }
    path.set_extension("php");
    path
}

fn normalize_project_relative_path(path: &Path) -> Option<PathBuf> {
    brokk_bifrost_core::path_utils::normalize_relative_path_from(Path::new(""), path)
}

fn normalize_rel_path(path: impl AsRef<Path>) -> PathBuf {
    normalize_project_relative_path(path.as_ref()).unwrap_or_else(|| path.as_ref().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::model::{CodeUnitType, Language, Range};
    use brokk_bifrost_core::analyzer::project::{FileSetProject, OverlayProject};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    struct Index {
        project: OverlayProject,
        owner: CodeUnit,
        listed: bool,
    }

    // A project may expose unsaved source before its tracked-file index updates.
    impl Project for Index {
        fn root(&self) -> &Path {
            self.project.root()
        }
        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.project.analyzer_languages()
        }
        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.project.all_files()
        }
        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.project.analyzable_files(language)
        }
        fn file_by_rel_path(&self, path: &Path) -> Option<ProjectFile> {
            self.listed
                .then(|| self.project.file_by_rel_path(path))
                .flatten()
        }
        fn has_overlay(&self, file: &ProjectFile) -> bool {
            self.project.has_overlay(file)
        }
        fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
            self.project.read_source(file)
        }
        fn read_source_snapshot(
            &self,
            file: &ProjectFile,
        ) -> std::io::Result<brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot> {
            self.project.read_source_snapshot(file)
        }
    }

    impl CodeUnitIndex for Index {
        fn project(&self) -> &dyn Project {
            &self.project
        }
        fn languages(&self) -> BTreeSet<Language> {
            BTreeSet::from([Language::Php])
        }
        fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            Box::new(std::iter::once(self.owner.clone()))
        }
        fn parent_of(&self, _: &CodeUnit) -> Option<CodeUnit> {
            Some(self.owner.clone())
        }
        fn search_definitions(&self, _: &str, _: bool) -> BTreeSet<CodeUnit> {
            unimplemented!()
        }
        fn enclosing_code_unit(&self, _: &ProjectFile, _: &Range) -> Option<CodeUnit> {
            unimplemented!()
        }
        fn enclosing_code_unit_for_lines(
            &self,
            _: &ProjectFile,
            _: usize,
            _: usize,
        ) -> Option<CodeUnit> {
            unimplemented!()
        }
        fn get_skeleton(&self, _: &CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_skeleton_header(&self, _: &CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_sources(&self, _: &CodeUnit, _: bool) -> BTreeSet<String> {
            unimplemented!()
        }
    }

    #[test]
    fn composer_manifest_format_boundary() {
        // Composer's PSR-4 schema maps namespaces to a string or an array;
        // PSR-4 maps remaining namespace components and the basename to .php.
        let manifest = serde_json::json!({
            "autoload": {"psr-4": {
                "App\\": "src/", "Multi\\": ["modern/", "legacy/"], "": "fallback/"
            }},
            "autoload-dev": {"psr-4": {"Tests\\": "tests/"}}
        })
        .to_string();
        let root = std::env::current_dir().unwrap();
        // Exercise a listed manifest and an overlay-only manifest, with a
        // conflicting lock file present in both project views.
        for listed in [true, false] {
            let files = if listed {
                vec![
                    PathBuf::from("composer.json"),
                    PathBuf::from("composer.lock"),
                ]
            } else {
                vec![PathBuf::from("composer.lock")]
            };
            let project = OverlayProject::new(Arc::new(FileSetProject::new(root.clone(), files)));
            assert!(project.set(root.join("composer.json"), manifest.clone()));
            assert!(project.set(root.join("composer.lock"), "{}".into()));
            let mut index = Index {
                project,
                listed,
                owner: CodeUnit::new(
                    ProjectFile::new(&root, "src/Service.php"),
                    CodeUnitType::Class,
                    "App",
                    "Service",
                ),
            };
            let autoload = PhpComposerAutoload::from_project(&index);
            let rows = [
                ("App", "Service", "src/Service.php", true),
                ("App.Package", "Service", "src/Package/Service.php", true),
                ("Tests", "Helper", "tests/Helper.php", true),
                ("Multi", "Modern", "modern/Modern.php", true),
                ("Multi", "Legacy", "legacy/Legacy.php", true),
                (
                    "Vendor.Package",
                    "Service",
                    "fallback/Vendor/Package/Service.php",
                    true,
                ),
                ("App", "Service", "Service.php", false),
                ("App", "Service", "src/Other.php", false),
                ("App", "Service", "src/Service.phtml", false),
                ("Vendor", "OffPath", "misc/OffPath.php", false),
                ("Application", "Service", "src/Service.php", false),
            ];
            for (namespace, class, path, expected) in rows {
                let file = ProjectFile::new(&root, path);
                let owner = CodeUnit::new(file.clone(), CodeUnitType::Class, namespace, class);
                let member = CodeUnit::new(
                    file,
                    CodeUnitType::Function,
                    owner.fq_name().as_str(),
                    "run",
                );
                index.owner = owner.clone();
                assert_eq!(
                    autoload.class_is_autoloaded(&owner),
                    expected,
                    "listed={listed}: {owner:?}"
                );
                assert_eq!(
                    autoload.target_is_autoloaded(&index, &owner),
                    expected,
                    "class {owner:?}"
                );
                assert_eq!(
                    autoload.target_is_autoloaded(&index, &member),
                    expected,
                    "member {member:?}"
                );
                assert!(!autoload.class_is_autoloaded(&member));
            }
        }
    }
}
