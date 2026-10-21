use super::*;

use crate::analyzer::Language;
use crate::test_support::AnalyzerFixture;

#[doc(hidden)]
pub struct Fixture {
    pub(super) analyzer: AnalyzerFixture,
    pub(super) file: ProjectFile,
    pub(super) source: String,
}

impl Fixture {
    #[doc(hidden)]
    pub fn new(language: Language, relative_path: &str, source: &str) -> Self {
        let analyzer = AnalyzerFixture::new_for_language(language, &[(relative_path, source)]);
        let file = ProjectFile::new(analyzer.project_root(), relative_path);
        Self {
            analyzer,
            file,
            source: source.to_owned(),
        }
    }

    #[doc(hidden)]
    pub fn rows(&self) -> MaterializationFileResult {
        materialization_for_file(self.analyzer.analyzer().analyzer(), &self.file)
    }

    #[doc(hidden)]
    pub fn at(&self, needle: &str) -> usize {
        crate::test_support::fixture_marker(&self.source, needle)
    }
}
