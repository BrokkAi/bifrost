use crate::graph::PhpGraphSource;
use crate::graph::resolver::TargetSpec;
use crate::graph_support::PhpSource;
use brokk_bifrost_core::analyzer::model::Range;
use brokk_bifrost_core::analyzer::usages::common::{
    SNIPPET_CONTEXT_LINES, reclassify_import_hit_at, reclassify_override_declaration_hit_at,
    reclassify_self_receiver_hit_at, usage_hit,
};
use brokk_bifrost_core::analyzer::usages::model::UsageHit;
use brokk_bifrost_core::analyzer::{CodeUnit, ProjectFile};
use brokk_bifrost_core::text_utils::{find_line_index_for_offset, snippet_around_line};
use std::collections::BTreeSet;
use tree_sitter::Node;

pub fn push_hit(
    node: Node<'_>,
    analyzer: PhpGraphSource<'_>,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    push_hit_range(
        node.start_byte(),
        node.end_byte(),
        analyzer,
        file,
        source,
        line_starts,
        spec,
        hits,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn push_import_hit(
    node: Node<'_>,
    analyzer: PhpGraphSource<'_>,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    push_hit(node, analyzer, file, source, line_starts, spec, hits);
    reclassify_import_hit_at(hits, file, node.start_byte(), node.end_byte());
}

#[allow(clippy::too_many_arguments)]
pub fn push_hit_range(
    start: usize,
    end: usize,
    analyzer: PhpGraphSource<'_>,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(line_starts, start),
        end_line: find_line_index_for_offset(line_starts, end),
    };
    let enclosing = analyzer
        .index
        .enclosing_code_unit(file, &range)
        .unwrap_or_else(|| CodeUnit::file_scope(file.clone()));
    // A reference whose enclosing declaration is a *callable* target is a
    // recursive call (#1638): recorded, then classified `SelfReceiver`, so
    // editor find-references lists it while the external usage surface omits
    // it. For any other target the site is the declaration itself, not a use
    // of it, and stays dropped.
    if enclosing == spec.target && !spec.target.is_function() {
        return;
    }
    let recursive = enclosing == spec.target;
    hits.insert(usage_hit(
        file,
        range.start_line,
        start,
        end,
        enclosing,
        snippet_around_line(source, line_starts, range.start_line, SNIPPET_CONTEXT_LINES),
    ));
    if recursive {
        reclassify_self_receiver_hit_at(hits, file, start, end);
    }
}

/// Push a hit for `[start, end)` then reclassify it as a same-owner self/this
/// receiver hit (`$this->m()`, `self::m()`, `static::m()`) — excluded from the
/// external usage surface, counted as a same-owner site (#1014 facet B).
#[allow(clippy::too_many_arguments)]
pub fn push_self_receiver_hit_range(
    start: usize,
    end: usize,
    analyzer: PhpGraphSource<'_>,
    file: &ProjectFile,
    source: &str,
    line_starts: &[usize],
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    push_hit_range(start, end, analyzer, file, source, line_starts, spec, hits);
    reclassify_self_receiver_hit_at(hits, file, start, end);
}

pub fn push_override_declaration_hit(
    php: &dyn PhpSource,
    analyzer: PhpGraphSource<'_>,
    declaration: &CodeUnit,
    hits: &mut BTreeSet<UsageHit>,
) {
    let file = declaration.source();
    let Ok(source) = php.project().read_source(file) else {
        return;
    };
    let Some((start, end)) = declaration_name_range(php, declaration) else {
        return;
    };
    let line_starts = brokk_bifrost_core::text_utils::compute_line_starts(&source);
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: find_line_index_for_offset(&line_starts, start),
        end_line: find_line_index_for_offset(&line_starts, end),
    };
    let enclosing = analyzer
        .index
        .enclosing_code_unit(file, &range)
        .unwrap_or_else(|| declaration.clone());
    hits.insert(usage_hit(
        file,
        range.start_line,
        start,
        end,
        enclosing,
        snippet_around_line(
            &source,
            &line_starts,
            range.start_line,
            SNIPPET_CONTEXT_LINES,
        ),
    ));
    reclassify_override_declaration_hit_at(hits, file, start, end);
}

fn declaration_name_range(php: &dyn PhpSource, declaration: &CodeUnit) -> Option<(usize, usize)> {
    let source = php.php_source_facts(declaration.source())?;
    let first = source.declarations_for(declaration).next()?;
    let name = source.source.declaration(first.declaration).name?;
    let range = source.source.occurrence(name).range;
    Some((range.start_byte, range.end_byte))
}

#[cfg(test)]
mod source_range_boundary_tests {
    use super::*;
    use crate::graph::syntax::graph_boundary_tests::Fixture;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "847cee536608: quicksilver round 9 on brokk-bifrost-php: uppercase interface implementations lost override hits"
    )]
    fn published_override_name_range_selects_the_forward_identifier() {
        let fixture = Fixture::new(
            "<?php\ninterface Notifier {\n function notify();\n}\nclass Concrete implements Notifier {\n public function NOTIFY() {}\n}\n",
        );
        for name in ["Notifier.notify", "Concrete.NOTIFY"] {
            let unit = fixture.unit(name);
            let (start, end) = declaration_name_range(&fixture, &unit).unwrap();
            assert!(start < end);
            assert_eq!(&fixture.source[start..end], unit.identifier());
        }
        let spec = crate::graph::resolver::TargetSpec::from_target(
            &fixture,
            &fixture.unit("Notifier.notify"),
        )
        .unwrap();
        let hierarchy =
            crate::graph::resolver::PhpHierarchyIndex::for_target_owner(&fixture, &spec);
        let implementations = hierarchy.overriding_methods(
            &fixture,
            &spec,
            &brokk_bifrost_core::hash::HashSet::from_iter([fixture.file.clone()]),
            None,
        );
        assert_eq!(implementations, vec![fixture.unit("Concrete.NOTIFY")]);
    }
}
