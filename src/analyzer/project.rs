use crate::analyzer::{Language, ProjectFile};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub trait Project: Send + Sync {
    fn root(&self) -> &Path;
    fn analyzer_languages(&self) -> BTreeSet<Language>;
    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>>;
    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>>;
    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile>;

    fn is_gitignored(&self, _rel_path: &Path) -> bool {
        false
    }
}

#[derive(Debug, Clone)]
pub struct TestProject {
    root: PathBuf,
    languages: BTreeSet<Language>,
}

impl TestProject {
    pub fn new(root: impl Into<PathBuf>, language: Language) -> Self {
        let root = root.into();
        assert!(root.is_absolute(), "test project root must be absolute");
        assert!(root.is_dir(), "test project root must exist");

        let mut languages = BTreeSet::new();
        languages.insert(language);

        Self { root, languages }
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }
}

impl Project for TestProject {
    fn root(&self) -> &Path {
        &self.root
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.languages.clone()
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        let mut files = BTreeSet::new();

        for entry in WalkDir::new(&self.root) {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }

            let rel = entry
                .path()
                .strip_prefix(&self.root)
                .expect("walkdir returned a path outside the project root");
            files.insert(ProjectFile::new(self.root.clone(), rel.to_path_buf()));
        }

        Ok(files)
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let extension = match language {
            Language::Java => Some("java"),
            Language::Go => Some("go"),
            Language::Cpp => Some("cpp"),
            Language::JavaScript => Some("js"),
            Language::TypeScript => Some("ts"),
            Language::Python => Some("py"),
            Language::Rust => Some("rs"),
            Language::Php => Some("php"),
            Language::Scala => Some("scala"),
            Language::CSharp => Some("cs"),
            Language::None => None,
        };

        let files = self.all_files()?;
        Ok(files
            .into_iter()
            .filter(|file| {
                extension
                    .map(|extension| {
                        file.rel_path().extension().and_then(|ext| ext.to_str()) == Some(extension)
                    })
                    .unwrap_or(false)
            })
            .collect())
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        file.exists().then_some(file)
    }
}
