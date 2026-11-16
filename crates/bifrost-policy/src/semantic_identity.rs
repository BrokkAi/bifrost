use crate::finding::PolicySourceLocation;
use brokk_bifrost_analysis::analyzer::semantic::{
    CallSiteHandle, ProcedureHandle, ProgramPointHandle, SemanticLocator,
};
use brokk_bifrost_analysis::analyzer::{ProjectFile, WorkspaceAnalyzer};
use brokk_bifrost_analysis::text_utils::{
    compute_line_starts, compute_line_starts_bounded, line_column_for_offset,
};

pub(super) fn policy_location(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> Result<PolicySourceLocation, String> {
    let span = locator.anchor().span();
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        locator.path().as_path(),
    );
    let (start_line, start_column, end_line, end_column) = workspace
        .analyzer()
        .indexed_source(&file)
        .map(|source| {
            let starts = compute_line_starts(&source);
            let (start_line, start_column) =
                line_column_for_offset(&source, &starts, span.start_byte() as usize);
            let (end_line, end_column) =
                line_column_for_offset(&source, &starts, span.end_byte() as usize);
            (start_line, start_column, end_line, end_column)
        })
        .unwrap_or_else(|| {
            (
                span.start().line() as usize + 1,
                span.start().byte_column() as usize + 1,
                span.end().line() as usize + 1,
                span.end().byte_column() as usize + 1,
            )
        });
    PolicySourceLocation::span_from_coordinates(
        locator.path().clone(),
        u64::from(span.start_byte()),
        u64::from(span.end_byte()),
        start_line as u64,
        start_column as u64,
        end_line as u64,
        end_column as u64,
    )
}

type FileCoordinates = (ProjectFile, (String, Vec<usize>));

/// Report locations of structural sites known only by their file and byte
/// range (an undecided selector candidate has no semantic locator). Each
/// file's source and line starts are read once per index, which lives for one
/// verdict assembly.
#[derive(Default)]
pub(super) struct FileSpanLocations {
    files: Vec<FileCoordinates>,
    #[cfg(test)]
    table_allocations: usize,
}

impl FileSpanLocations {
    fn file_index(&self, root: &std::path::Path, path: &std::path::Path) -> Result<usize, usize> {
        self.files.binary_search_by(|(file, _)| {
            file.root()
                .cmp(root)
                .then_with(|| file.rel_path().cmp(path))
        })
    }

    pub(super) fn cached_file(
        &self,
        root: &std::path::Path,
        path: &std::path::Path,
    ) -> Option<&ProjectFile> {
        self.file_index(root, path)
            .ok()
            .map(|index| &self.files[index].0)
    }

    pub(super) fn len(&self) -> usize {
        self.files.len()
    }

    fn allocate_table(&mut self, capacity: usize) -> Vec<FileCoordinates> {
        #[cfg(test)]
        {
            self.table_allocations += 1;
        }
        Vec::with_capacity(capacity)
    }

    pub(super) fn locator_location(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
        locator: &SemanticLocator,
        available: &mut usize,
        admit_scan: &mut dyn FnMut(usize) -> bool,
    ) -> Result<PolicySourceLocation, String> {
        assert_eq!(file.root(), workspace.analyzer().project().root());
        assert_eq!(file.rel_path(), locator.path().as_path());
        let span = locator.anchor().span();
        self.bounded_location(
            workspace,
            file,
            &(span.start_byte() as usize..span.end_byte() as usize),
            available,
            admit_scan,
        )
    }

    pub(super) fn bounded_location(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
        span: &std::ops::Range<usize>,
        available: &mut usize,
        admit_scan: &mut dyn FnMut(usize) -> bool,
    ) -> Result<PolicySourceLocation, String> {
        assert_eq!(file.root(), workspace.analyzer().project().root());
        let index = match self.file_index(file.root(), file.rel_path()) {
            Ok(index) => index,
            Err(index) => {
                let refusal =
                    || "finding-primary source coordinates exceed report allowance".to_owned();
                let capacity = if self.files.len() == self.files.capacity() {
                    self.files
                        .capacity()
                        .checked_mul(2)
                        .ok_or_else(refusal)?
                        .max(1)
                } else {
                    self.files.capacity()
                };
                let growing = capacity != self.files.capacity();
                let new_slots = if growing {
                    capacity
                        .checked_mul(std::mem::size_of::<FileCoordinates>())
                        .ok_or_else(refusal)?
                } else {
                    0
                };
                // The indexed-source API necessarily returns one transient owned
                // String. Everything retained, including the FULL replacement
                // table while old slots remain live, must fit before allocation.
                let source = workspace
                    .analyzer()
                    .indexed_source(file)
                    .ok_or_else(|| "finding-primary site has no indexed source".to_owned())?;
                if !admit_scan(source.len()) {
                    return Err("source coordinate scan exceeds report work allowance".to_owned());
                }
                let fixed = file
                    .retained_heap_bytes()
                    .checked_add(source.capacity())
                    .and_then(|bytes| bytes.checked_add(new_slots))
                    .ok_or_else(refusal)?;
                let line_allowance = available.checked_sub(fixed).ok_or_else(refusal)?;
                let starts =
                    compute_line_starts_bounded(&source, line_allowance).ok_or_else(refusal)?;
                let bytes = starts
                    .capacity()
                    .checked_mul(std::mem::size_of::<usize>())
                    .and_then(|bytes| bytes.checked_add(fixed))
                    .ok_or_else(refusal)?;
                let remaining = available.checked_sub(bytes).ok_or_else(refusal)?;
                let old_slots = if growing {
                    self.files
                        .capacity()
                        .checked_mul(std::mem::size_of::<FileCoordinates>())
                        .ok_or_else(refusal)?
                } else {
                    0
                };
                // Check refund arithmetic before changing either cache or ledger.
                let final_available = remaining.checked_add(old_slots).ok_or_else(refusal)?;
                *available = remaining;
                let entry = (file.clone(), (source, starts));
                if growing {
                    let replacement = self.allocate_table(capacity);
                    let old = std::mem::replace(&mut self.files, replacement);
                    let mut entries = old.into_iter();
                    self.files.extend(entries.by_ref().take(index));
                    self.files.push(entry);
                    self.files.extend(entries.by_ref());
                    // Release the entire old allocation before refunding its
                    // slots. Each old entry moves once, within admitted work.
                    drop(entries);
                } else {
                    self.files.insert(index, entry);
                }
                *available = final_available;
                index
            }
        };
        let (file, (source, starts)) = &self.files[index];
        Self::render_location(file, source, starts, span)
    }

    /// Includes ordinary subject files loaded before Sites admission. Their
    /// entire baseline is charged by the caller before budgeted insertions.
    pub(super) fn retained_heap_bytes(&self) -> usize {
        self.files.iter().fold(
            brokk_bifrost_analysis::hash::vec_slot_bytes(&self.files),
            |bytes, (file, (source, starts))| {
                bytes
                    .saturating_add(file.retained_heap_bytes())
                    .saturating_add(source.capacity())
                    .saturating_add(brokk_bifrost_analysis::hash::vec_slot_bytes(starts))
            },
        )
    }

    pub(super) fn location(
        &mut self,
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
        span: &std::ops::Range<usize>,
    ) -> Result<PolicySourceLocation, String> {
        let index = match self.file_index(file.root(), file.rel_path()) {
            Ok(index) => index,
            Err(index) => {
                let source = workspace.analyzer().indexed_source(file).ok_or_else(|| {
                    format!(
                        "{} has no indexed source for its subject location",
                        file.rel_path().display()
                    )
                })?;
                let starts = compute_line_starts(&source);
                self.files.insert(index, (file.clone(), (source, starts)));
                index
            }
        };
        let (file, (source, starts)) = &self.files[index];
        Self::render_location(file, source, starts, span)
    }

    fn render_location(
        file: &ProjectFile,
        source: &str,
        starts: &[usize],
        span: &std::ops::Range<usize>,
    ) -> Result<PolicySourceLocation, String> {
        let rel_path = brokk_bifrost_analysis::path_utils::rel_path_string(file);
        let (start_line, start_column) = line_column_for_offset(source, starts, span.start);
        let (end_line, end_column) = line_column_for_offset(source, starts, span.end);
        PolicySourceLocation::span_from_coordinates(
            brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath::new(&rel_path)
                .map_err(|error| error.to_string())?,
            span.start as u64,
            span.end as u64,
            start_line as u64,
            start_column as u64,
            end_line as u64,
            end_column as u64,
        )
    }
}

pub(super) fn program_point_locator(point: &ProgramPointHandle) -> &SemanticLocator {
    let _row = point
        .procedure()
        .semantics()
        .point(point.id())
        .expect("validated policy witness point resolves");
    point
        .locator()
        .expect("validated policy witness point has a source mapping")
}

pub(super) fn call_site_locator(call: &CallSiteHandle) -> &SemanticLocator {
    let _row = call
        .procedure()
        .semantics()
        .call_site(call.id())
        .expect("validated policy witness call resolves");
    call.locator()
        .expect("validated policy witness call has a source mapping")
}

pub(super) fn source_excerpt(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> Option<String> {
    let span = locator.anchor().span();
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        locator.path().as_path(),
    );
    let source = workspace.analyzer().indexed_source(&file)?;
    source
        .get(span.start_byte() as usize..span.end_byte() as usize)
        .map(str::to_owned)
}

pub(super) fn semantic_root_key(root: &ProcedureHandle) -> String {
    let mut bytes = Vec::new();
    let locator = root.semantics().locator();
    bytes.extend_from_slice(locator.path().as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(locator.language().config_label().as_bytes());
    bytes.push(0);
    append_declaration_identity(locator, &mut bytes);
    stable_hex(&bytes)
}

pub(super) fn semantic_site_key(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(semantic_root_key_from_locator(locator).as_bytes());
    bytes.extend_from_slice(locator.role().stable_label().as_bytes());
    let span = locator.anchor().span();
    let file = ProjectFile::new(
        workspace.analyzer().project().root().to_path_buf(),
        locator.path().as_path(),
    );
    if let Some(source) = workspace.analyzer().indexed_source(&file)
        && let Some(slice) = source.get(span.start_byte() as usize..span.end_byte() as usize)
    {
        bytes.extend_from_slice(slice.as_bytes());
    }
    bytes.extend_from_slice(&locator.anchor().occurrence().to_le_bytes());
    stable_hex(&bytes)
}

fn semantic_root_key_from_locator(locator: &SemanticLocator) -> String {
    let mut bytes = Vec::new();
    append_declaration_identity(locator, &mut bytes);
    stable_hex(&bytes)
}

fn append_declaration_identity(locator: &SemanticLocator, bytes: &mut Vec<u8>) {
    for segment in locator.declaration().segments() {
        bytes.extend_from_slice(segment.kind().stable_label().as_bytes());
        bytes.push(0);
        if let Some(name) = segment.name() {
            bytes.extend_from_slice(name.as_bytes());
        }
        bytes.extend_from_slice(&segment.sibling_ordinal().to_le_bytes());
    }
}

pub(super) fn stable_hex(bytes: &[u8]) -> String {
    brokk_bifrost_analysis::analyzer::semantic_model::csmi::sha256_hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::Language;
    use brokk_bifrost_analysis::analyzer::semantic::{
        DeclarationLocator, DeclarationSegment, DeclarationSegmentKind, SemanticLanguage,
        SemanticRole, SourceAnchor, SourcePosition, SourceSpan, WorkspaceMountId,
    };
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon("#11250: finite-site coordinate caches escaped the shared report allowance")]
    fn source_coordinate_retention_obeys_the_grant_and_preserves_unicode_crlf_columns() {
        let mut builder = crate::inline_project::InlineTestProject::with_language(Language::Python);
        let names = ["f.py", "b.py", "e.py", "a.py", "d.py", "c.py"];
        for name in names {
            builder = builder.file(name, "# \u{e9}\r\npass\r\n");
        }
        let project = builder.build();
        let workspace = project.workspace_analyzer(Default::default());
        // Fixture keys exist before any admission attempt; production borrows
        // generation-owned lease handles instead of constructing new keys.
        let files = names.map(|name| ProjectFile::new(project.root().to_path_buf(), name));
        let locators = names.map(|name| {
            let path = brokk_bifrost_analysis::analyzer::semantic::WorkspaceRelativePath::new(name)
                .unwrap();
            let anchor = SourceAnchor::new(
                SourceSpan::new(SourcePosition::new(4, 0, 4), SourcePosition::new(6, 0, 6))
                    .unwrap(),
                0,
            );
            let declaration = DeclarationLocator::new(vec![
                DeclarationSegment::named(DeclarationSegmentKind::File, name, anchor, 0).unwrap(),
            ])
            .unwrap();
            SemanticLocator::new(
                WorkspaceMountId::hash_bytes(b"coordinate retention test"),
                path,
                SemanticLanguage::Standard(Language::Python),
                declaration,
                SemanticRole::MemoryLocation,
                anchor,
            )
        });
        let entry_bytes = std::mem::size_of::<FileCoordinates>();
        let source = workspace.analyzer().indexed_source(&files[0]).unwrap();
        let payload_bytes = source.capacity()
            + files[0].retained_heap_bytes()
            + compute_line_starts_bounded(&source, usize::MAX)
                .unwrap()
                .capacity()
                * std::mem::size_of::<usize>();
        let mut cache = FileSpanLocations::default();
        for grant in [
            0,
            source.capacity() + files[0].retained_heap_bytes() + entry_bytes,
        ] {
            let mut available = grant;
            let pointer = cache.files.as_ptr();
            assert!(
                cache
                    .locator_location(
                        &workspace,
                        &files[0],
                        &locators[0],
                        &mut available,
                        &mut |_| true
                    )
                    .is_err()
            );
            assert_eq!(cache.table_allocations, 0);
            assert_eq!(cache.files.as_ptr(), pointer);
            assert_eq!(cache.files.capacity(), 0);
            assert!(cache.files.is_empty());
            assert_eq!(cache.retained_heap_bytes(), 0);
            assert_eq!(available, grant);
        }
        for (index, (file, locator)) in files.iter().zip(&locators).enumerate() {
            let growing = cache.files.len() == cache.files.capacity();
            let old_slots = cache.files.capacity() * entry_bytes;
            let new_slots = if growing {
                (cache.files.capacity() * 2).max(1) * entry_bytes
            } else {
                0
            };
            let peak = payload_bytes + new_slots;
            if growing && index > 0 {
                let before = cache.files.clone();
                let pointer = cache.files.as_ptr();
                let capacity = cache.files.capacity();
                let allocations = cache.table_allocations;
                let heap = cache.retained_heap_bytes();
                let mut available = peak - 1;
                assert!(available >= peak - old_slots, "net retained growth fits");
                assert!(
                    cache
                        .locator_location(&workspace, file, locator, &mut available, &mut |_| true)
                        .is_err()
                );
                assert_eq!(cache.files, before);
                assert_eq!(cache.files.as_ptr(), pointer);
                assert_eq!(cache.files.capacity(), capacity);
                assert_eq!(
                    cache.table_allocations, allocations,
                    "refusal never allocates then discards a table"
                );
                assert_eq!(cache.retained_heap_bytes(), heap);
                assert_eq!(available, peak - 1);
                let mut no_grant = 0;
                cache
                    .locator_location(
                        &workspace,
                        &files[0],
                        &locators[0],
                        &mut no_grant,
                        &mut |_| true,
                    )
                    .unwrap();
                assert_eq!(no_grant, 0);
            }
            let before_heap = cache.retained_heap_bytes();
            let allocations = cache.table_allocations;
            let mut available = peak;
            let location = cache
                .locator_location(&workspace, file, locator, &mut available, &mut |_| true)
                .unwrap();
            assert_eq!(cache.table_allocations, allocations + usize::from(growing));
            assert_eq!(peak - available, cache.retained_heap_bytes() - before_heap);
            assert_eq!(available, if growing { old_slots } else { 0 });
            assert!(cache.files.windows(2).all(|pair| pair[0].0 < pair[1].0));
            let region = location.region().unwrap();
            assert_eq!(
                (
                    region.start_line(),
                    region.start_column(),
                    region.end_line(),
                    region.end_column()
                ),
                (1, 4, 2, 1)
            );
            let paid = available;
            assert_eq!(
                cache
                    .locator_location(&workspace, file, locator, &mut available, &mut |_| true)
                    .unwrap(),
                location
            );
            assert_eq!(available, paid, "warm coordinates are free");
            assert_eq!(
                cache.cached_file(project.root(), locator.path().as_path()),
                Some(file)
            );
            let mut ordinary = FileSpanLocations::default();
            assert_eq!(
                ordinary.location(&workspace, file, &(4..6)).unwrap(),
                location
            );
        }

        // Ordinary subject coordinates precede Sites. Charge that baseline
        // exactly once, then test warm reuse, cold growth and refusal against it.
        let mut ordinary = FileSpanLocations::default();
        ordinary.location(&workspace, &files[0], &(4..6)).unwrap();
        let baseline = ordinary.retained_heap_bytes();
        let grant = baseline + 1024 * 1024;
        let mut available = grant - baseline;
        let initial = available;
        ordinary
            .locator_location(
                &workspace,
                &files[0],
                &locators[0],
                &mut available,
                &mut |_| true,
            )
            .unwrap();
        assert_eq!(available, initial);
        ordinary
            .locator_location(
                &workspace,
                &files[1],
                &locators[1],
                &mut available,
                &mut |_| true,
            )
            .unwrap();
        assert_eq!(grant - available, ordinary.retained_heap_bytes());
        let before = ordinary.files.clone();
        let allocations = ordinary.table_allocations;
        let mut no_grant = 0;
        assert!(
            ordinary
                .locator_location(
                    &workspace,
                    &files[2],
                    &locators[2],
                    &mut no_grant,
                    &mut |_| true
                )
                .is_err()
        );
        assert_eq!(ordinary.files, before);
        assert_eq!(ordinary.table_allocations, allocations);
        assert_eq!(no_grant, 0);
    }
}
