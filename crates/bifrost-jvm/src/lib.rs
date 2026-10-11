//! JVM language knowledge for Bifrost.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! This crate sits between [`brokk_bifrost_core`] and `brokk-bifrost-analysis`.
//! It holds Java, Scala and Kotlin *language knowledge* as plain functions and
//! data, and it uses the released Brokk Scala and Kotlin tree-sitter grammars. It depends on no
//! other Bifrost crate than core, so nothing here
//! may name `IAnalyzer`, `TreeSitterAnalyzer`, `JavaAnalyzer`, `ScalaAnalyzer`
//! or `KotlinAnalyzer`.
//!
//! # Why one crate for three languages
//!
//! Java, Scala and Kotlin sources in one workspace compile to one classpath, so
//! a declaration written in any of them can be named from the other two.
//! [`realm::JvmSourceRealm`] is the view that closes that gap, and it makes
//! Kotlin's import, type and hierarchy routes depend on Java's and Scala's
//! declarations; Java's forward scan depends on Scala syntax in the other
//! direction. The three languages also share one
//! [`brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig`]. Splitting them
//! would need a cycle between crates.
//!
//! # The grammar packages
//!
//! Scala uses the released `brokk-tree-sitter-scala` crate with a contextual
//! selector correction. Kotlin uses the released `brokk-tree-sitter-kotlin`
//! crate. Both grammars use distinct native symbols. `brokk-bifrost-analysis` re-imports both languages for parsing and
//! store epochs.
//!
//! Where analysis code would reach for an analyzer handle, the functions here
//! take a source trait -- a core
//! [`brokk_bifrost_core::analyzer::CodeUnitIndex`] plus the memoized products
//! the language logic resolves through. `analyzer/{java,scala,kotlin,jvm}/` in
//! `brokk-bifrost-analysis` keeps the shims: the three analyzer structs with
//! their moka caches and `OnceLock` cells, the `CodeUnitIndex` and `IAnalyzer`
//! impls, the three adapter forwarding shells, the three SPI blocks, and the
//! downcasts that produce the arguments -- including the three that build a
//! [`realm::JvmSourceRealm`].

mod call_arguments;
pub(crate) mod graph_hits;
pub mod java;
pub mod kotlin;
mod package_lookup;
pub mod proof;
pub mod queries;
pub mod realm;
pub mod scala;
mod test_detection;

pub(crate) fn source_header(source: &str, start_byte: usize, end_byte: usize) -> String {
    brokk_bifrost_core::analyzer::common::collapse_whitespace(
        source.get(start_byte..end_byte).unwrap_or_default(),
    )
}

pub(crate) fn is_literal_initializer_kind(kind: &str) -> bool {
    kind.ends_with("_literal") || matches!(kind, "true" | "false" | "null")
}

pub(crate) fn same_expression_text(
    left: tree_sitter::Node<'_>,
    right: tree_sitter::Node<'_>,
    source: &str,
) -> bool {
    let left = source
        .get(left.start_byte()..left.end_byte())
        .unwrap_or_default()
        .trim();
    let right = source
        .get(right.start_byte()..right.end_byte())
        .unwrap_or_default()
        .trim();
    left == right
}

pub(crate) fn is_overspecified_string_literal(
    node: tree_sitter::Node<'_>,
    source: &str,
    threshold: usize,
) -> bool {
    node.kind() == "string_literal"
        && source
            .get(node.start_byte()..node.end_byte())
            .is_some_and(|text| text.len() >= threshold)
}

pub(crate) fn format_modifier_prefix(parts: impl IntoIterator<Item = String>) -> String {
    let mut prefix = String::new();
    for part in parts.into_iter().filter(|part| !part.is_empty()) {
        prefix.push_str(&part);
        prefix.push(' ');
    }
    prefix
}

pub(crate) fn same_package_reference_index(
    files: &[brokk_bifrost_core::analyzer::ProjectFile],
    target_names: impl Fn(&brokk_bifrost_core::analyzer::ProjectFile) -> Option<(String, Vec<String>)>,
    reference_names: impl Fn(
        &brokk_bifrost_core::analyzer::ProjectFile,
    ) -> Option<(String, Vec<String>)>
    + Sync,
    parallel: bool,
) -> brokk_bifrost_core::hash::HashMap<
    brokk_bifrost_core::analyzer::ProjectFile,
    std::sync::Arc<brokk_bifrost_core::hash::HashSet<brokk_bifrost_core::analyzer::ProjectFile>>,
> {
    let mut targets_by_package_and_name: brokk_bifrost_core::hash::HashMap<
        (String, String),
        Vec<brokk_bifrost_core::analyzer::ProjectFile>,
    > = brokk_bifrost_core::hash::HashMap::default();
    for file in files {
        let Some((package, names)) = target_names(file) else {
            continue;
        };
        for name in names {
            targets_by_package_and_name
                .entry((package.clone(), name))
                .or_default()
                .push(file.clone());
        }
    }

    brokk_bifrost_core::analyzer::capabilities::build_reverse_file_index(
        files,
        |candidate| {
            let Some((package, identifiers)) = reference_names(candidate) else {
                return Vec::new();
            };
            let mut targets = Vec::new();
            for identifier in identifiers {
                if let Some(matching_targets) =
                    targets_by_package_and_name.get(&(package.clone(), identifier))
                {
                    targets.extend(matching_targets.iter().cloned());
                }
            }
            targets
        },
        parallel,
    )
}

pub(crate) fn same_source_hierarchy_declaration<T>(
    winner: usize,
    declarations: &[usize],
    descendant: &brokk_bifrost_core::analyzer::CodeUnit,
    candidates: &[T],
    declaration: impl for<'a> Fn(&'a T) -> &'a brokk_bifrost_core::analyzer::CodeUnit,
) -> usize {
    let mut same_source = declarations
        .iter()
        .copied()
        .filter(|index| declaration(&candidates[*index]).source() == descendant.source());
    let Some(exact) = same_source.next() else {
        return winner;
    };
    if same_source.next().is_none() {
        exact
    } else {
        winner
    }
}

pub(crate) fn hierarchy_descendants_from_edges<T>(
    candidates: &[T],
    workspace_edges: &[Vec<usize>],
    external_descendants: Vec<usize>,
    cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
    declaration: impl for<'a> Fn(&'a T) -> &'a brokk_bifrost_core::analyzer::CodeUnit,
) -> Option<Vec<brokk_bifrost_core::analyzer::CodeUnit>> {
    assert_eq!(workspace_edges.len(), candidates.len());
    let mut seen = vec![false; candidates.len()];
    let mut stack = external_descendants;
    while let Some(index) = stack.pop() {
        if cancellation
            .is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled)
        {
            return None;
        }
        if std::mem::replace(&mut seen[index], true) {
            continue;
        }
        stack.extend(workspace_edges[index].iter().copied());
    }
    let mut descendants = seen
        .into_iter()
        .enumerate()
        .filter(|(_, seen)| *seen)
        .map(|(index, _)| declaration(&candidates[index]).clone())
        .collect::<Vec<_>>();
    descendants.sort();
    Some(descendants)
}

#[cfg(test)]
pub(crate) mod test_support {
    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;

    pub(crate) fn assert_recorded_type_parameter_counts(
        parsed: &ParsedFile,
        expected: &[(&str, usize)],
    ) {
        let mut actual = parsed
            .signature_metadata
            .iter()
            .flat_map(|(unit, metadata)| {
                metadata
                    .iter()
                    .filter(|entry| entry.type_parameters_recorded())
                    .map(|entry| (unit.short_name().to_string(), entry.type_parameters().len()))
            })
            .collect::<Vec<_>>();
        actual.sort();
        let mut expected = expected
            .iter()
            .map(|(name, count)| ((*name).to_string(), *count))
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(
            actual, expected,
            "generic callable parameters remain separate from class metadata"
        );
    }
}
