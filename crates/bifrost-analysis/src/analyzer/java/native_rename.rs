//! Test-support Java rename from complete selected inverse evidence.
//!
//! Only selected proven edges authorize edits, and the same selected inverse
//! query checks the counterfactual world and actual peer-language inventory.

use super::JavaAnalyzer;
use super::selected_reverse::{JavaSelectedReverseOutcome, java_selected_inverse_for};
use crate::CancellationToken;
use crate::analyzer::CodeUnitIndex;
use crate::analyzer::OverlayProject;
use crate::analyzer::structural::reference_edges::{EdgeCompleteness, EdgeDerivationResult};
use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, UsageProof};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, Project, ProjectFile, resolve_analyzer};
use crate::symbol_rename::{
    MAX_RENAME_IDENTIFIER_BYTES, RenameEdit, RenameFailure, RenameFileEdits, RenameResult,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tree_sitter::{Node, Tree};

/// Native Java rename provider, kept outside production dispatch.
pub struct JavaNativeRenameProvider;

impl crate::symbol_rename::RenameProvider for JavaNativeRenameProvider {
    fn rename(
        &self,
        analyzer: &dyn IAnalyzer,
        project: &dyn Project,
        target: &CodeUnit,
        new_name: &str,
    ) -> Result<RenameResult, RenameFailure> {
        let java = resolve_analyzer::<JavaAnalyzer>(analyzer).ok_or_else(|| {
            failure(
                "incomplete_analysis",
                "selected Java analyzer is unavailable",
            )
        })?;
        java_native_rename(
            java,
            project,
            target,
            new_name,
            &CancellationToken::default(),
        )
    }
}

struct CounterfactualFile {
    hypothetical: String,
    edits: Box<[RenameEdit]>,
}

impl CounterfactualFile {
    fn hypothetical_range_to_original(
        &self,
        start_byte: usize,
        end_byte: usize,
    ) -> Option<(usize, usize)> {
        Some((
            self.hypothetical_offset_to_original(start_byte)?,
            self.hypothetical_offset_to_original(end_byte)?,
        ))
    }

    fn hypothetical_offset_to_original(&self, offset: usize) -> Option<usize> {
        let mut delta = 0_i128;
        for edit in &self.edits {
            let hypothetical_start = usize::try_from(edit.start_byte as i128 + delta).ok()?;
            let hypothetical_end = hypothetical_start.checked_add(edit.new_text.len())?;
            if offset < hypothetical_start {
                break;
            }
            if offset == hypothetical_start {
                return Some(edit.start_byte);
            }
            if offset < hypothetical_end {
                return None;
            }
            if offset == hypothetical_end {
                return Some(edit.end_byte);
            }
            delta +=
                edit.new_text.len() as i128 - edit.end_byte.checked_sub(edit.start_byte)? as i128;
        }
        usize::try_from(offset as i128 - delta).ok()
    }
}

/// Test-support entry point for comparing native Java rename with the
/// incumbent `symbol_rename` implementation.
pub fn java_native_rename(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    target: &CodeUnit,
    new_name: &str,
    cancellation: &CancellationToken,
) -> Result<RenameResult, RenameFailure> {
    use crate::analyzer::common::is_valid_rename_identifier;

    let java = resolve_analyzer::<JavaAnalyzer>(analyzer).ok_or_else(|| {
        failure(
            "incomplete_analysis",
            "selected Java analyzer is unavailable",
        )
    })?;
    if target.source().declaration_language() != Language::Java {
        return Err(failure(
            "unsupported",
            "native Java rename requires a Java declaration",
        ));
    }
    if new_name.len() > MAX_RENAME_IDENTIFIER_BYTES
        || !is_valid_rename_identifier(Language::Java, new_name)
    {
        return Err(failure(
            "invalid_name",
            "invalid Java replacement identifier",
        ));
    }
    if cancellation.is_cancelled() {
        return Err(failure("cancelled", "native Java rename was cancelled"));
    }

    let generation = project.analysis_generation();
    refuse_unproven_override_group(java, target)?;
    let original = match java_selected_inverse_for(java, target, cancellation) {
        JavaSelectedReverseOutcome::Ready(answer) => answer,
        outcome => {
            return Err(failure(
                "incomplete_analysis",
                format!("native Java inverse selection failed: {outcome:?}"),
            ));
        }
    };
    require_complete_proven(&original, "original")?;
    if original.edges.len() > DEFAULT_MAX_USAGES {
        return Err(failure(
            "too_many_callsites",
            format!(
                "native Java rename exceeds the usage limit: {}",
                original.edges.len()
            ),
        ));
    }
    let target_source = project
        .read_source(target.source())
        .map_err(|error| failure("incomplete_analysis", error.to_string()))?;
    if !java
        .inner
        .source_matches_selected_native_content(target.source(), &target_source)
    {
        return Err(failure(
            "incomplete_analysis",
            "native Java rename target source differs from selected content",
        ));
    }
    let declaration = crate::analyzer::declaration_range::code_unit_declaration_name_range(
        java,
        target.source(),
        &target_source,
        target,
    )
    .ok_or_else(|| {
        failure(
            "incomplete_analysis",
            "native Java rename target has no structured declaration name",
        )
    })?;

    let mut edits_by_file = BTreeMap::<ProjectFile, (String, Tree, Vec<RenameEdit>)>::new();
    for edge in &original.edges {
        let file = edge.site.file.clone();
        if !edits_by_file.contains_key(&file) {
            if edits_by_file.len() >= DEFAULT_MAX_FILES {
                return Err(failure(
                    "too_many_files",
                    "native Java rename exceeds the file limit",
                ));
            }
            let source = project
                .read_source(&file)
                .map_err(|error| failure("incomplete_analysis", error.to_string()))?;
            if !java
                .inner
                .source_matches_selected_native_content(&file, &source)
            {
                return Err(failure(
                    "incomplete_analysis",
                    format!("native Java rename source differs from selected content: {file}"),
                ));
            }
            let tree =
                brokk_bifrost_jvm::java::declarations::parse_tree(&source).ok_or_else(|| {
                    failure(
                        "incomplete_analysis",
                        format!("cannot parse selected Java source: {file}"),
                    )
                })?;
            edits_by_file.insert(file.clone(), (source, tree, Vec::new()));
        }
        let (source, tree, edits) = edits_by_file
            .get_mut(&file)
            .expect("selected Java rename source was admitted");
        let Some((start_byte, end_byte)) = reference_name_range(
            tree.root_node(),
            source,
            edge.site.range.start_byte,
            edge.site.range.end_byte,
            target,
        ) else {
            return Err(failure(
                "incomplete_analysis",
                format!(
                    "selected Java reference does not expose one structured target identifier: {:?}",
                    edge.site
                ),
            ));
        };
        edits.push(RenameEdit {
            start_byte,
            end_byte,
            new_text: new_name.to_owned(),
        });
    }

    if !edits_by_file.contains_key(target.source()) {
        if edits_by_file.len() >= DEFAULT_MAX_FILES {
            return Err(failure(
                "too_many_files",
                "native Java rename exceeds the file limit",
            ));
        }
        let tree =
            brokk_bifrost_jvm::java::declarations::parse_tree(&target_source).ok_or_else(|| {
                failure(
                    "incomplete_analysis",
                    "cannot parse selected Java declaration source",
                )
            })?;
        edits_by_file.insert(
            target.source().clone(),
            (target_source.clone(), tree, Vec::new()),
        );
    }
    let (declaration_source, _, declaration_edits) = edits_by_file
        .get_mut(target.source())
        .expect("target source was admitted");
    if declaration_source.get(declaration.start_byte..declaration.end_byte)
        != Some(target.identifier())
    {
        return Err(failure(
            "incomplete_analysis",
            "native Java declaration range does not contain its structured identifier",
        ));
    }
    declaration_edits.push(RenameEdit {
        start_byte: declaration.start_byte,
        end_byte: declaration.end_byte,
        new_text: new_name.to_owned(),
    });

    let counterfactual_files =
        build_counterfactual_files(edits_by_file, target.identifier(), new_name)?;
    let result = RenameResult {
        target: target.clone(),
        old_name: target.identifier().to_owned(),
        files: counterfactual_files
            .iter()
            .filter_map(|(file, contents)| {
                (!contents.edits.is_empty()).then_some(RenameFileEdits {
                    file: file.clone(),
                    edits: contents.edits.to_vec(),
                })
            })
            .collect(),
    };

    let hypothetical_java = counterfactual_analyzer(java, &counterfactual_files)?;
    let original_parent = java.parent_of(target);
    let hypothetical_target = find_counterfactual_target(
        &hypothetical_java,
        target,
        original_parent.as_ref(),
        new_name,
    )?;
    let hypothetical =
        match java_selected_inverse_for(&hypothetical_java, &hypothetical_target, cancellation) {
            JavaSelectedReverseOutcome::Ready(answer) => answer,
            outcome => {
                return Err(failure(
                    "incomplete_analysis",
                    format!("counterfactual Java inverse selection failed: {outcome:?}"),
                ));
            }
        };
    require_complete_proven(&hypothetical, "counterfactual")?;
    let original_sites = inverse_site_positions(&original, None)?;
    let hypothetical_sites = inverse_site_positions(&hypothetical, Some(&counterfactual_files))?;
    if original_sites != hypothetical_sites {
        return Err(failure(
            "capture_or_rebinding",
            format!(
                "Java rename changes selected binding sites: original={original_sites:?}, counterfactual={hypothetical_sites:?}"
            ),
        ));
    }
    if cancellation.is_cancelled() || project.analysis_generation() != generation {
        return Err(failure(
            "incomplete_analysis",
            "native Java rename was cancelled or selected generation changed",
        ));
    }
    Ok(result)
}

fn reference_name_range(
    root: Node<'_>,
    source: &str,
    start_byte: usize,
    end_byte: usize,
    target: &CodeUnit,
) -> Option<(usize, usize)> {
    if start_byte > end_byte || source.get(start_byte..end_byte).is_none() {
        return None;
    }
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "import_declaration"
            && node.start_byte() <= start_byte
            && end_byte <= node.end_byte()
        {
            let is_static = (0..node.child_count()).any(|index| {
                node.child(index)
                    .is_some_and(|child| child.kind() == "static")
            });
            let is_wildcard = (0..node.child_count()).any(|index| {
                node.child(index)
                    .is_some_and(|child| child.kind() == "asterisk")
            });
            let path = (0..node.named_child_count())
                .filter_map(|index| node.named_child(index))
                .find(|child| matches!(child.kind(), "identifier" | "scoped_identifier"))?;
            let mut segments = Vec::new();
            let mut path_stack = vec![path];
            while let Some(segment) = path_stack.pop() {
                if segment.kind() == "identifier" {
                    segments.push(segment);
                    continue;
                }
                let mut children = (0..segment.named_child_count())
                    .filter_map(|index| segment.named_child(index))
                    .collect::<Vec<_>>();
                children.reverse();
                path_stack.extend(children);
            }
            let index = if is_static
                && !is_wildcard
                && target.is_class()
                && !target.owner_is_type_scope()
            {
                // A top-level type in `import static Owner.member` is the
                // owner segment. A nested type is itself the imported member.
                segments.len().checked_sub(2)?
            } else if (is_static && !is_wildcard) || target.is_class() {
                segments.len().checked_sub(1)?
            } else {
                return None;
            };
            let segment = *segments.get(index)?;
            if start_byte <= segment.start_byte()
                && segment.end_byte() <= end_byte
                && source.get(segment.start_byte()..segment.end_byte()) == Some(target.identifier())
            {
                return Some((segment.start_byte(), segment.end_byte()));
            }
            return None;
        }
        let mut children = (0..node.named_child_count())
            .filter_map(|index| node.named_child(index))
            .filter(|child| child.start_byte() <= end_byte && start_byte <= child.end_byte())
            .collect::<Vec<_>>();
        children.reverse();
        stack.extend(children);
    }

    let mut candidates = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "identifier" | "type_identifier")
            && start_byte <= node.start_byte()
            && node.end_byte() <= end_byte
            && source.get(node.start_byte()..node.end_byte()) == Some(target.identifier())
        {
            candidates.push((node.start_byte(), node.end_byte()));
        }
        let mut children = (0..node.named_child_count())
            .filter_map(|index| node.named_child(index))
            .filter(|child| child.start_byte() <= end_byte && start_byte <= child.end_byte())
            .collect::<Vec<_>>();
        children.reverse();
        stack.extend(children);
    }
    candidates.sort_unstable();
    candidates.pop()
}

fn build_counterfactual_files(
    mut edits_by_file: BTreeMap<ProjectFile, (String, Tree, Vec<RenameEdit>)>,
    old_name: &str,
    new_name: &str,
) -> Result<BTreeMap<ProjectFile, CounterfactualFile>, RenameFailure> {
    let mut files = BTreeMap::new();
    for (file, (original, _tree, edits)) in &mut edits_by_file {
        edits.sort_by_key(|edit| (edit.start_byte, edit.end_byte));
        edits.dedup_by_key(|edit| (edit.start_byte, edit.end_byte));
        if edits
            .windows(2)
            .any(|pair| pair[1].start_byte < pair[0].end_byte)
        {
            return Err(failure(
                "incomplete_analysis",
                "native Java rename edits overlap",
            ));
        }
        for edit in edits.iter() {
            if edit.new_text != new_name
                || original.get(edit.start_byte..edit.end_byte) != Some(old_name)
            {
                return Err(failure(
                    "incomplete_analysis",
                    format!(
                        "native Java rename edit is not an exact identifier replacement: {edit:?}"
                    ),
                ));
            }
        }
        let mut hypothetical = original.clone();
        for edit in edits.iter().rev() {
            hypothetical.replace_range(edit.start_byte..edit.end_byte, &edit.new_text);
        }
        files.insert(
            file.clone(),
            CounterfactualFile {
                hypothetical,
                edits: edits.clone().into_boxed_slice(),
            },
        );
    }
    Ok(files)
}

fn counterfactual_analyzer(
    java: &JavaAnalyzer,
    files: &BTreeMap<ProjectFile, CounterfactualFile>,
) -> Result<JavaAnalyzer, RenameFailure> {
    let overlay = Arc::new(OverlayProject::new(java.inner.shared_project()));
    for (file, contents) in files {
        if !overlay.set(file.abs_path().to_path_buf(), contents.hypothetical.clone()) {
            return Err(failure(
                "incomplete_analysis",
                format!("cannot mount Java rename overlay for {file}"),
            ));
        }
    }
    let project: Arc<dyn Project> = Arc::new(overlay.snapshot());
    let hypothetical = java.clone_with_project(project);
    for file in files.keys() {
        hypothetical
            .inner
            .write_live_file_to_store_for_test(file)
            .ok_or_else(|| {
                failure(
                    "incomplete_analysis",
                    format!("cannot publish counterfactual Java source for {file}"),
                )
            })?;
    }
    Ok(hypothetical)
}

fn find_counterfactual_target(
    java: &JavaAnalyzer,
    target: &CodeUnit,
    original_parent: Option<&CodeUnit>,
    new_name: &str,
) -> Result<CodeUnit, RenameFailure> {
    let mut matches = java
        .declarations(target.source())
        .into_iter()
        .filter(|candidate| {
            candidate.identifier() == new_name
                && candidate.kind() == target.kind()
                && candidate.signature() == target.signature()
                && java.parent_of(candidate).as_ref() == original_parent
        })
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [candidate] => Ok(candidate.clone()),
        _ => Err(failure(
            "capture_or_rebinding",
            format!("counterfactual Java target is absent or ambiguous: {matches:?}"),
        )),
    }
}

fn inverse_site_positions(
    result: &EdgeDerivationResult,
    counterfactual: Option<&BTreeMap<ProjectFile, CounterfactualFile>>,
) -> Result<BTreeSet<(ProjectFile, usize, usize)>, RenameFailure> {
    let mut sites = BTreeSet::new();
    for edge in &result.edges {
        let (start, end) =
            if let Some(file) = counterfactual.and_then(|files| files.get(&edge.site.file)) {
                file.hypothetical_range_to_original(
                    edge.site.range.start_byte,
                    edge.site.range.end_byte,
                )
                .ok_or_else(|| {
                    failure(
                        "incomplete_analysis",
                        format!(
                            "counterfactual Java reference range cannot map to original: {:?}",
                            edge.site
                        ),
                    )
                })?
            } else {
                (edge.site.range.start_byte, edge.site.range.end_byte)
            };
        sites.insert((edge.site.file.clone(), start, end));
    }
    Ok(sites)
}

fn refuse_unproven_override_group(
    java: &JavaAnalyzer,
    target: &CodeUnit,
) -> Result<(), RenameFailure> {
    if !target.is_function() {
        return Ok(());
    }
    let parent = java.parent_of(target);
    let candidates = java
        .inner
        .lookup_declarations_by_identifier(target.identifier())
        .into_iter()
        .filter(|candidate| {
            candidate != target && candidate.is_function() && java.parent_of(candidate) != parent
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(());
    }
    Err(failure(
        "incomplete_analysis",
        format!(
            "Java rename cannot establish the override relation for same-name declarations: {candidates:?}"
        ),
    ))
}

fn require_complete_proven(
    result: &EdgeDerivationResult,
    world: &str,
) -> Result<(), RenameFailure> {
    if result.completeness != EdgeCompleteness::Complete
        || result
            .edges
            .iter()
            .any(|edge| edge.proof != UsageProof::Proven)
    {
        return Err(failure(
            "incomplete_analysis",
            format!("{world} Java inverse evidence is incomplete or unproven: {result:?}"),
        ));
    }
    Ok(())
}

fn failure(kind: &'static str, message: impl Into<String>) -> RenameFailure {
    RenameFailure {
        kind,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::fq_name::{FqName, SegmentKind, segment_interner};
    use crate::analyzer::{CodeUnitType, ProjectFile};

    #[test]
    fn selected_import_identifier_ranges_preserve_java_qualifiers() {
        let source = "package client; import model.Base; import static model.Base.staticMethod; import static model.Base.Nested; class Use {}";
        let tree = brokk_bifrost_jvm::java::declarations::parse_tree(source).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(temp.path().to_path_buf(), "src/client/Use.java");
        let class = CodeUnit::new(file.clone(), CodeUnitType::Class, "model", "Base");
        let method = CodeUnit::new(file, CodeUnitType::Function, "model.Base", "staticMethod");

        let regular_site = source.find("model.Base").unwrap();
        let regular = reference_name_range(
            tree.root_node(),
            source,
            regular_site,
            regular_site + "model.Base".len(),
            &class,
        )
        .unwrap();
        assert_eq!(&source[regular.0..regular.1], "Base");

        let static_site = source.find("model.Base.staticMethod").unwrap();
        let static_owner = reference_name_range(
            tree.root_node(),
            source,
            static_site,
            static_site + "model.Base.staticMethod".len(),
            &class,
        )
        .unwrap();
        assert_eq!(&source[static_owner.0..static_owner.1], "Base");
        let static_member = reference_name_range(
            tree.root_node(),
            source,
            static_site,
            static_site + "model.Base.staticMethod".len(),
            &method,
        )
        .unwrap();
        assert_eq!(&source[static_member.0..static_member.1], "staticMethod");

        let mut nested_fq = FqName::new();
        nested_fq.push(segment_interner().intern("model", SegmentKind::Package));
        nested_fq.push(segment_interner().intern("Base", SegmentKind::Type));
        nested_fq.push(segment_interner().intern("Nested", SegmentKind::Nested));
        let nested_type = CodeUnit::new_fq(
            ProjectFile::new(temp.path().to_path_buf(), "src/client/Use.java"),
            CodeUnitType::Class,
            "model",
            "Base$Nested",
            nested_fq,
        );
        assert!(nested_type.owner_is_type_scope());
        let nested_site = source.find("model.Base.Nested").unwrap();
        let nested_member = reference_name_range(
            tree.root_node(),
            source,
            nested_site,
            nested_site + "model.Base.Nested".len(),
            &nested_type,
        )
        .unwrap();
        assert_eq!(&source[nested_member.0..nested_member.1], "Nested");
    }

    #[test]
    fn selected_type_reference_uses_the_type_identifier_node() {
        let source = "package client; import model.Base; class Use { Base value; }";
        let tree = brokk_bifrost_jvm::java::declarations::parse_tree(source).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let file = ProjectFile::new(temp.path().to_path_buf(), "src/client/Use.java");
        let class = CodeUnit::new(file, CodeUnitType::Class, "model", "Base");
        let start = source.find("Base value").unwrap();
        let name = reference_name_range(
            tree.root_node(),
            source,
            start,
            start + "Base".len(),
            &class,
        )
        .unwrap();
        assert_eq!(&source[name.0..name.1], "Base");
    }

    #[test]
    fn counterfactual_ranges_map_qualified_imports_around_name_edits() {
        let original = "import client.Base;";
        let hypothetical = "import client.Renamed;";
        let old_start = original.find("Base").unwrap();
        let new_start = hypothetical.find("Renamed").unwrap();
        let contents = CounterfactualFile {
            hypothetical: hypothetical.to_owned(),
            edits: vec![RenameEdit {
                start_byte: old_start,
                end_byte: old_start + "Base".len(),
                new_text: "Renamed".to_owned(),
            }]
            .into_boxed_slice(),
        };
        assert_eq!(
            contents.hypothetical_range_to_original(0, hypothetical.len()),
            Some((0, original.len()))
        );
        assert_eq!(
            contents.hypothetical_range_to_original(new_start, new_start + "Renamed".len()),
            Some((old_start, old_start + "Base".len()))
        );
    }
}
