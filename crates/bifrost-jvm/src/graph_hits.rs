use brokk_bifrost_core::analyzer::usages::accumulator::UsageAccumulator;
use brokk_bifrost_core::analyzer::usages::common::{
    SNIPPET_CONTEXT_LINES, classify_recursive_hit, usage_hit,
};
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::text_utils::{find_line_index_for_offset, snippet_around_line};

/// Shared Java/Kotlin hit recording after their language-specific context lookup.
pub(crate) struct HitRecorder<'a> {
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    target: &'a CodeUnit,
}

impl<'a> HitRecorder<'a> {
    pub(crate) fn new(
        file: &'a ProjectFile,
        source: &'a str,
        line_starts: &'a [usize],
        target: &'a CodeUnit,
    ) -> Self {
        Self {
            file,
            source,
            line_starts,
            target,
        }
    }

    /// Keep class self-references as ordinary hits and reclassify callable recursion.
    pub(crate) fn record_proven(
        &self,
        usages: &mut UsageAccumulator,
        node: tree_sitter::Node<'_>,
        enclosing: CodeUnit,
        knowledge: &dyn brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge,
    ) {
        let start = node.start_byte();
        let end = node.end_byte();
        let line_idx = find_line_index_for_offset(self.line_starts, start);
        let hit = usage_hit(
            self.file,
            line_idx,
            start,
            end,
            enclosing,
            snippet_around_line(
                self.source,
                self.line_starts,
                line_idx,
                SNIPPET_CONTEXT_LINES,
            ),
        );
        let hit = if self.target.is_class() {
            Some(hit)
        } else {
            classify_recursive_hit(hit, self.target, Some(node), knowledge)
        };
        if let Some(hit) = hit {
            usages.insert_hit(hit);
        }
    }

    pub(crate) fn record_unproven(
        &self,
        usages: &mut UsageAccumulator,
        start: usize,
        end: usize,
        enclosing: Option<CodeUnit>,
    ) {
        let Some(enclosing) = enclosing else {
            return;
        };
        if enclosing == *self.target {
            return;
        }
        let line_idx = find_line_index_for_offset(self.line_starts, start);
        let hit = usage_hit(
            self.file,
            line_idx,
            start,
            end,
            enclosing,
            snippet_around_line(
                self.source,
                self.line_starts,
                line_idx,
                SNIPPET_CONTEXT_LINES,
            ),
        );
        usages.insert_unproven_hit(hit);
    }
}
