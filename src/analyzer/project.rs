use crate::analyzer::{Language, ProjectFile};
use ignore::WalkBuilder;
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
        let extensions = language.extensions();
        if extensions.is_empty() {
            return Ok(BTreeSet::new());
        }

        let files = self.all_files()?;
        Ok(files
            .into_iter()
            .filter(|file| {
                file.rel_path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| extensions.contains(&ext))
                    .unwrap_or(false)
            })
            .collect())
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        file.exists().then_some(file)
    }
}

#[derive(Debug, Clone)]
pub struct FilesystemProject {
    root: PathBuf,
    languages: BTreeSet<Language>,
}

impl FilesystemProject {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into().canonicalize()?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("project root is not a directory: {}", root.display()),
            ));
        }

        let languages = detect_languages(&root)?;
        Ok(Self { root, languages })
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }
}

impl Project for FilesystemProject {
    fn root(&self) -> &Path {
        &self.root
    }

    fn analyzer_languages(&self) -> BTreeSet<Language> {
        self.languages.clone()
    }

    fn all_files(&self) -> io::Result<BTreeSet<ProjectFile>> {
        collect_project_files(&self.root)
    }

    fn analyzable_files(&self, language: Language) -> io::Result<BTreeSet<ProjectFile>> {
        let extensions = language.extensions();
        if extensions.is_empty() {
            return Ok(BTreeSet::new());
        }

        let files = self.all_files()?;
        Ok(files
            .into_iter()
            .filter(|file| {
                file.rel_path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| {
                        let normalized = ext.to_ascii_lowercase();
                        extensions.contains(&normalized.as_str())
                    })
                    .unwrap_or(false)
            })
            .collect())
    }

    fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        file.exists().then_some(file)
    }

    fn is_gitignored(&self, rel_path: &Path) -> bool {
        let file = ProjectFile::new(self.root.clone(), rel_path.to_path_buf());
        file.exists()
            && self
                .all_files()
                .map(|files| !files.contains(&file))
                .unwrap_or(false)
    }
}

fn collect_project_files(root: &Path) -> io::Result<BTreeSet<ProjectFile>> {
    let mut files = BTreeSet::new();
    let walker = WalkBuilder::new(root)
        .hidden(false)
        .ignore(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .parents(true)
        .require_git(false)
        .build();

    for entry in walker {
        let entry = entry.map_err(|err| io::Error::other(err.to_string()))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }

        let rel = entry
            .path()
            .strip_prefix(root)
            .expect("walkdir returned a path outside the project root");
        files.insert(ProjectFile::new(root.to_path_buf(), rel.to_path_buf()));
    }

    Ok(files)
}

fn detect_languages(root: &Path) -> io::Result<BTreeSet<Language>> {
    let mut languages = BTreeSet::new();
    for file in collect_project_files(root)? {
        if let Some(extension) = file.rel_path().extension().and_then(|ext| ext.to_str()) {
            let language = Language::from_extension(extension);
            if language != Language::None {
                languages.insert(language);
            }
        }
    }
    Ok(languages)
}
