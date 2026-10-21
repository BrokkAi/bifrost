#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CallRelationWork {
    pub scanned_files: usize,
    pub scanned_source_bytes: usize,
    pub examined_candidates: usize,
}

impl CallRelationWork {
    #[doc(hidden)]
    pub fn add(&mut self, other: Self) {
        self.scanned_files = self.scanned_files.saturating_add(other.scanned_files);
        self.scanned_source_bytes = self
            .scanned_source_bytes
            .saturating_add(other.scanned_source_bytes);
        self.examined_candidates = self
            .examined_candidates
            .saturating_add(other.examined_candidates);
    }
}
