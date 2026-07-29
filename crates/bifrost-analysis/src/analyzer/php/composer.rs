use crate::analyzer::{CodeUnit, Project, ProjectFile};
use crate::hash::HashSet;
use serde_json::Value;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub(crate) struct PhpComposerAutoload {
    psr4_roots: Vec<Psr4Root>,
}

impl PhpComposerAutoload {
    pub(crate) fn from_project(project: &dyn Project) -> Self {
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

    pub(crate) fn manifest_changed(file: &ProjectFile) -> bool {
        file.rel_path() == Path::new("composer.json")
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.psr4_roots.is_empty()
    }

    pub(crate) fn target_is_autoloaded(
        &self,
        analyzer: &dyn crate::analyzer::IAnalyzer,
        target: &CodeUnit,
    ) -> bool {
        if self.is_empty() {
            return false;
        }
        if target.is_class() {
            return self.class_is_autoloaded(target);
        }
        analyzer
            .parent_of(target)
            .as_ref()
            .is_some_and(|owner| self.class_is_autoloaded(owner))
    }

    pub(crate) fn class_is_autoloaded(&self, class_unit: &CodeUnit) -> bool {
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
            namespace: crate::analyzer::php_namespace_to_fq(namespace),
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
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => out.push(part),
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

fn normalize_rel_path(path: impl AsRef<Path>) -> PathBuf {
    normalize_project_relative_path(path.as_ref()).unwrap_or_else(|| path.as_ref().to_path_buf())
}
