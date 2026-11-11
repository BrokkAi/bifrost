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

mod anonymous_type;
mod call_arguments;
mod constructor_site;
pub(crate) mod graph_hits;
mod implicit_supertype;
pub mod intrinsics;
pub mod java;
pub mod kotlin;
pub mod member_type_coverage;
mod package_lookup;
pub mod proof;
pub mod queries;
pub mod realm;
mod resolution_scan_index;
pub mod scala;
mod synthetic_members;
mod test_detection;
mod type_parameters;

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

/// A query-local external hierarchy walk stopped before enumerating its paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalSupertypeClosureStop {
    Cancelled,
    BudgetExhausted,
}

/// Positive reachability and the independent completeness of an external walk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExternalSupertypeClosureAnswer {
    pub reaches_root: bool,
    pub unresolved_supertype: Option<String>,
}

/// Known parent edges and whether they exhaust one external type's inventory.
#[derive(Debug, Clone)]
pub struct ExternalSupertypeFacts {
    pub supertypes: Vec<String>,
    pub complete: bool,
}

/// One hierarchy query's external supertype closures.
///
/// Each external identity is read and charged once. Completed answers include
/// incompleteness, so a warm hit cannot close a family that a missing branch
/// opened. Cyclic nodes are not memoized until every parent has settled; their
/// facts still stay available to later starts without further reads or charges.
/// Nothing survives the query.
#[derive(Default)]
pub struct ExternalSupertypeClosure {
    parents: brokk_bifrost_core::hash::HashMap<String, Option<ExternalSupertypeFacts>>,
    answers: brokk_bifrost_core::hash::HashMap<String, ExternalSupertypeClosureAnswer>,
}

impl ExternalSupertypeClosure {
    /// Follow every reachable external parent, preserving positive reachability
    /// even when another branch or an inventory is incomplete. `supertypes`
    /// returns `None` when no unambiguous parent facts are available.
    #[allow(clippy::too_many_arguments)]
    pub fn reaches_root(
        &mut self,
        raw: &str,
        root: &str,
        visited: &mut usize,
        max_visits: usize,
        cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
        resolve_raw_supertype: impl FnOnce(&str) -> Option<String>,
        mut supertypes: impl FnMut(&str) -> Option<ExternalSupertypeFacts>,
    ) -> Result<ExternalSupertypeClosureAnswer, ExternalSupertypeClosureStop> {
        use brokk_bifrost_core::hash::HashSet;
        enum Frame {
            Enter(String),
            Exit(String),
        }
        let Some(start) = resolve_raw_supertype(raw) else {
            return Ok(ExternalSupertypeClosureAnswer {
                reaches_root: false,
                unresolved_supertype: Some(raw.to_owned()),
            });
        };
        let mut stack = vec![Frame::Enter(start)];
        let mut seen = HashSet::default();
        let mut answer = ExternalSupertypeClosureAnswer::default();
        while let Some(frame) = stack.pop() {
            if cancellation.is_some_and(|token| token.is_cancelled()) {
                return Err(ExternalSupertypeClosureStop::Cancelled);
            }
            match frame {
                Frame::Enter(identity) => {
                    if let Some(cached) = self.answers.get(&identity) {
                        answer.reaches_root |= cached.reaches_root;
                        if answer.unresolved_supertype.is_none() {
                            answer
                                .unresolved_supertype
                                .clone_from(&cached.unresolved_supertype);
                        }
                        continue;
                    }
                    if !seen.insert(identity.clone()) {
                        continue;
                    }
                    if !self.parents.contains_key(&identity) {
                        if *visited >= max_visits {
                            return Err(ExternalSupertypeClosureStop::BudgetExhausted);
                        }
                        *visited += 1;
                        let parents = if identity == root {
                            Some(ExternalSupertypeFacts {
                                supertypes: Vec::new(),
                                complete: true,
                            })
                        } else {
                            supertypes(&identity)
                        };
                        self.parents.insert(identity.clone(), parents);
                    }
                    if identity == root {
                        self.answers.insert(
                            identity,
                            ExternalSupertypeClosureAnswer {
                                reaches_root: true,
                                unresolved_supertype: None,
                            },
                        );
                        answer.reaches_root = true;
                        continue;
                    }
                    let Some(parents) = &self.parents[&identity] else {
                        self.answers.insert(
                            identity.clone(),
                            ExternalSupertypeClosureAnswer {
                                reaches_root: false,
                                unresolved_supertype: Some(identity.clone()),
                            },
                        );
                        answer.unresolved_supertype.get_or_insert(identity);
                        continue;
                    };
                    if !parents.complete {
                        answer
                            .unresolved_supertype
                            .get_or_insert_with(|| identity.clone());
                    }
                    stack.push(Frame::Exit(identity.clone()));
                    stack.extend(parents.supertypes.iter().cloned().map(Frame::Enter));
                }
                Frame::Exit(identity) => {
                    let parents = self.parents[&identity]
                        .as_ref()
                        .expect("entered resolved node");
                    let mut completed = ExternalSupertypeClosureAnswer {
                        reaches_root: false,
                        unresolved_supertype: (!parents.complete).then(|| identity.clone()),
                    };
                    let mut settled = true;
                    for parent in &parents.supertypes {
                        let Some(parent_answer) = self.answers.get(parent) else {
                            settled = false;
                            break;
                        };
                        completed.reaches_root |= parent_answer.reaches_root;
                        if completed.unresolved_supertype.is_none() {
                            completed
                                .unresolved_supertype
                                .clone_from(&parent_answer.unresolved_supertype);
                        }
                    }
                    if settled {
                        self.answers.insert(identity, completed);
                    }
                }
            }
        }
        Ok(answer)
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
mod external_closure_tests {
    use super::{ExternalSupertypeClosure, ExternalSupertypeFacts};
    use brokk_bifrost_test_macros::hardwon;
    use std::collections::HashMap;

    fn graph(edges: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        edges
            .iter()
            .map(|(node, parents)| {
                (
                    (*node).to_owned(),
                    parents.iter().map(|parent| (*parent).to_owned()).collect(),
                )
            })
            .collect()
    }

    fn probe(
        closure: &mut ExternalSupertypeClosure,
        graph: &HashMap<String, Vec<String>>,
        start: &str,
        reads: &mut usize,
    ) -> bool {
        let mut visited = 0;
        let answer = closure
            .reaches_root(
                start,
                "Root",
                &mut visited,
                usize::MAX,
                None,
                |raw| Some(raw.to_owned()),
                |identity| {
                    *reads += 1;
                    graph
                        .get(identity)
                        .cloned()
                        .map(|supertypes| ExternalSupertypeFacts {
                            supertypes,
                            complete: true,
                        })
                },
            )
            .unwrap();
        assert_eq!(answer.unresolved_supertype, None);
        answer.reaches_root
    }

    #[test]
    #[hardwon(
        "af18b0d929dd: starts along one external chain re-read the rest of it, quadratic in its length"
    )]
    fn each_external_identity_is_read_once_and_cycles_answer_exactly() {
        let chain = (0..20)
            .map(|i| {
                (
                    format!("A{i}"),
                    vec![if i == 19 {
                        "Root".to_owned()
                    } else {
                        format!("A{}", i + 1)
                    }],
                )
            })
            .collect::<HashMap<_, _>>();
        let mut closure = ExternalSupertypeClosure::default();
        let mut reads = 0;
        for i in 0..20 {
            assert!(probe(&mut closure, &chain, &format!("A{i}"), &mut reads));
        }
        assert_eq!(reads, 20, "each chain node is read once");

        // A cycle that reaches the root through one member, probed from each
        // member in turn: neither may be remembered as not reaching it.
        let cyclic = graph(&[("X", &["Y"]), ("Y", &["X", "Root"])]);
        let mut closure = ExternalSupertypeClosure::default();
        let mut reads = 0;
        assert!(probe(&mut closure, &cyclic, "X", &mut reads));
        assert!(probe(&mut closure, &cyclic, "Y", &mut reads));
        let back = graph(&[("P", &["Q", "Root"]), ("Q", &["P"])]);
        let mut closure = ExternalSupertypeClosure::default();
        assert!(probe(&mut closure, &back, "P", &mut reads));
        assert!(probe(&mut closure, &back, "Q", &mut reads));
        // A cycle that never reaches the root.
        let closed = graph(&[("M", &["N"]), ("N", &["M"])]);
        let mut closure = ExternalSupertypeClosure::default();
        assert!(!probe(&mut closure, &closed, "M", &mut reads));
        assert!(!probe(&mut closure, &closed, "N", &mut reads));
    }

    #[test]
    #[hardwon(
        "#10497: an unresolved external branch erased proven ancestry or closed it on a warm hit"
    )]
    fn unresolved_external_branch_keeps_proven_ancestry_and_incompleteness() {
        for parents in [vec!["Root", "Missing"], vec!["Missing", "Root"]] {
            for cyclic in [false, true] {
                let mut edges = graph(&[("Base", &parents)]);
                if cyclic {
                    edges.insert("Child".into(), vec!["Base".into(), "Root".into()]);
                    edges.get_mut("Base").unwrap().push("Child".into());
                }
                let mut closure = ExternalSupertypeClosure::default();
                let mut visited = 0;
                let mut reads = Vec::new();
                for start in if cyclic {
                    vec!["Base", "Child", "Base"]
                } else {
                    vec!["Base", "Base"]
                } {
                    let answer = closure
                        .reaches_root(
                            start,
                            "Root",
                            &mut visited,
                            edges.len() + 2,
                            None,
                            |raw| Some(raw.into()),
                            |identity| {
                                reads.push(identity.to_owned());
                                edges.get(identity).cloned().map(|supertypes| {
                                    ExternalSupertypeFacts {
                                        supertypes,
                                        complete: true,
                                    }
                                })
                            },
                        )
                        .unwrap();
                    assert!(
                        answer.reaches_root,
                        "{start}, {parents:?}, cyclic={cyclic}: {answer:?}"
                    );
                    assert_eq!(answer.unresolved_supertype.as_deref(), Some("Missing"));
                }
                reads.sort();
                assert_eq!(
                    reads,
                    if cyclic {
                        vec!["Base", "Child", "Missing"]
                    } else {
                        vec!["Base", "Missing"]
                    }
                );
                assert_eq!(visited, edges.len() + 2);
            }
        }
    }
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

mod knowledge;
pub use knowledge::{JavaKnowledge, KotlinKnowledge, ScalaKnowledge};

/// Validate a syntax name before comparing or publishing its spelling.
/// Quoted identifiers with no contents are empty names as well.
pub(crate) fn recovered_name(node: tree_sitter::Node<'_>, source: &str) -> bool {
    node.is_missing()
        || node.has_error()
        || source[node.byte_range()]
            .trim()
            .trim_matches('`')
            .is_empty()
}
