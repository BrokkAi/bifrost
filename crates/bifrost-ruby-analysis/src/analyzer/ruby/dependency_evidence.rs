//! Files-only RubyGems and Ruby runtime evidence projected into the shared
//! #2442 contract (#9318).
//!
//! A bundle is a directory holding a `Gemfile` (or `gems.rb`) or a
//! `Gemfile.lock` (or `gems.locked`). Every row of a bundle, and of a gemspec
//! beside it, names the bundle's BuildProject in `declared_by`:
//! - `Gemfile` `gem` calls, with their groups, platforms and sources, are
//!   `declared` `rubygems` rows; gemspec `add_*dependency` calls likewise;
//! - each `Gemfile.lock` spec, direct or transitive, is a `locked` row whose
//!   exact version excludes a platform suffix (`1.16.0-arm64-darwin`), with
//!   its `GEM`, `GIT` or `PATH` source kind as a condition; `CHECKSUMS`
//!   entries are `checksum` rows;
//! - the Ruby runtime is the `ruby-toolchain` ecosystem with package `ruby`:
//!   the lock's `RUBY VERSION` and an exact `.ruby-version` or
//!   `.tool-versions` pin are `locked`, a `Gemfile` `ruby` directive or a
//!   gemspec `required_ruby_version` is a `constraint`, and a bundle with
//!   none of them has a `ruby.runtime_evidence=none` constraint so the
//!   runtime is a typed unknown rather than an absent row. None of these is
//!   the runtime that executes: `ruby.runtime_override=unobserved` says so on
//!   every pin.
//!
//! A `Gemfile` without a lock and a lock that does not parse are gaps, so a
//! missing lock is never a complete empty answer (#8357).

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::Path;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    DependencyCondition, DependencyEvidence, DependencyEvidenceGap, DependencyEvidenceGapKind,
    DependencyEvidenceKind, DependencyFileEvidence, DependencyFileEvidenceLimits,
};
use brokk_bifrost_analysis::analyzer::topology::{
    DependencyScope, TopologyCompleteness, TopologyEntity, TopologyEntityKind, TopologyProvenance,
    TopologyProvenanceKind,
};
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;
use brokk_bifrost_ruby::declarations::{parse_ruby_tree, ruby_node_text};
use brokk_bifrost_ruby::structural::RUBY_STRUCTURAL_SPEC;
use brokk_bifrost_ruby::syntax::ruby_call_arguments;
use tree_sitter::Node;

/// Gem rows from Gemfiles, gemspecs and lockfiles.
pub const RUBYGEMS_ECOSYSTEM: &str = "rubygems";
/// Ruby runtime rows; the package is always `ruby`.
pub const RUBY_TOOLCHAIN_ECOSYSTEM: &str = "ruby-toolchain";

const GEMFILE_NAMES: [&str; 2] = ["Gemfile", "gems.rb"];
const LOCKFILE_NAMES: [&str; 2] = ["Gemfile.lock", "gems.locked"];
const RUNTIME_FILE_NAMES: [&str; 2] = [".ruby-version", ".tool-versions"];

/// Whether `path` is a file this producer reads.
pub(crate) fn is_ruby_dependency_input(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            GEMFILE_NAMES.contains(&name)
                || LOCKFILE_NAMES.contains(&name)
                || RUNTIME_FILE_NAMES.contains(&name)
        })
        || path
            .extension()
            .is_some_and(|extension| extension == "gemspec")
}

/// Whether `path` declares or locks a bundle, so its directory's runtime pins
/// apply to it.
pub(crate) fn is_ruby_bundle_input(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| GEMFILE_NAMES.contains(&name) || LOCKFILE_NAMES.contains(&name))
}

/// Shared topology identity convention for the bundle rooted at `directory`.
/// Its identity is the directory alone, so the Gemfile, the lock and a
/// gemspec beside them name one owner.
pub fn ruby_bundle_project(directory: &Path, provenance: &Path) -> TopologyEntity {
    TopologyEntity {
        kind: TopologyEntityKind::BuildProject,
        name: format!("rubygems:{}", portable_directory(directory)),
        owner: None,
        root: Some(directory.to_path_buf()),
        provenance: vec![TopologyProvenance::new(
            provenance,
            TopologyProvenanceKind::ProjectDeclaration,
        )],
        completeness: TopologyCompleteness::Complete,
    }
}

fn portable_directory(directory: &Path) -> String {
    let text = directory.to_string_lossy().replace('\\', "/");
    if text.is_empty() {
        ".".to_owned()
    } else {
        text
    }
}

struct Input<'a> {
    path: &'a Path,
    source: &'a str,
    digest: String,
}

/// One file's rows before ownership, limits and ordering are applied.
struct Collector<'a> {
    result: &'a mut DependencyFileEvidence,
    rows: Vec<DependencyEvidence>,
}

impl Collector<'_> {
    fn gap(
        &mut self,
        path: &Path,
        range: Range<usize>,
        kind: DependencyEvidenceGapKind,
        message: impl Into<String>,
    ) {
        self.result.gaps.push(DependencyEvidenceGap {
            kind,
            build_file: path.to_path_buf(),
            byte_range: range,
            message: message.into(),
        });
    }
}

struct RowSpec {
    ecosystem: &'static str,
    package: String,
    kind: DependencyEvidenceKind,
    requirement: Option<String>,
    exact: Option<String>,
    source: Option<String>,
    scope: DependencyScope,
    conditions: Vec<DependencyCondition>,
    range: Range<usize>,
    complete: bool,
}

fn row(input: &Input<'_>, owner: &str, spec: RowSpec) -> DependencyEvidence {
    DependencyEvidence {
        ecosystem: spec.ecosystem.to_owned(),
        package: spec.package,
        kind: spec.kind,
        version_requirement: spec.requirement,
        exact_version: spec.exact,
        source: spec.source,
        locator: None,
        declared_by: Some(owner.to_owned()),
        scope: spec.scope,
        conditions: spec.conditions,
        build_file: input.path.to_path_buf(),
        source_digest: input.digest.clone(),
        byte_range: spec.range,
        complete: spec.complete,
    }
}

fn condition(kind: &str, value: &str) -> DependencyCondition {
    DependencyCondition {
        kind: kind.to_owned(),
        value: value.to_owned(),
    }
}

/// The first of `names` present among `files`.
fn named<'a, 'b>(files: &[&'a Input<'b>], names: &[&str]) -> Option<&'a Input<'b>> {
    names.iter().find_map(|name| {
        files
            .iter()
            .find(|input| input.path.file_name().is_some_and(|file| file == *name))
            .copied()
    })
}

/// Acquire every Ruby bundle's gem and runtime rows from the selected
/// configuration snapshots. Nothing survives the return but the rows.
pub(crate) fn collect_ruby_dependency_evidence(
    selected: &[(ProjectFile, ProjectSourceSnapshot)],
    limits: &DependencyFileEvidenceLimits,
) -> DependencyFileEvidence {
    let mut result = DependencyFileEvidence::default();
    let inputs = selected
        .iter()
        .filter(|(file, _)| is_ruby_dependency_input(file.rel_path()))
        .map(|(file, source)| Input {
            path: file.rel_path(),
            source: source.source(),
            digest: source.oid().to_string(),
        })
        .collect::<Vec<_>>();
    result.files_read = inputs.len();
    result.bytes_read = inputs.iter().map(|input| input.source.len()).sum();
    let mut by_directory = BTreeMap::<&Path, Vec<&Input<'_>>>::new();
    for input in &inputs {
        by_directory
            .entry(input.path.parent().unwrap_or(Path::new("")))
            .or_default()
            .push(input);
    }
    let bundles = by_directory
        .iter()
        .filter(|(_, files)| files.iter().any(|input| is_ruby_bundle_input(input.path)))
        .map(|(directory, _)| *directory)
        .collect::<BTreeSet<_>>();
    let mut collector = Collector {
        result: &mut result,
        rows: Vec::new(),
    };
    for (directory, files) in &by_directory {
        let gemfile = named(files, &GEMFILE_NAMES);
        let lockfile = named(files, &LOCKFILE_NAMES);
        let gemspecs = files
            .iter()
            .filter(|input| {
                input
                    .path
                    .extension()
                    .is_some_and(|extension| extension == "gemspec")
            })
            .copied()
            .collect::<Vec<_>>();
        let Some(primary) = lockfile.or(gemfile).or(gemspecs.first().copied()) else {
            continue;
        };
        let owner = ruby_bundle_project(directory, primary.path).id();
        let mut runtime = false;
        if let Some(gemfile) = gemfile {
            runtime |= gemfile_rows(&mut collector, gemfile, &owner, !gemspecs.is_empty());
            if lockfile.is_none() {
                collector.gap(
                    gemfile.path,
                    0..0,
                    DependencyEvidenceGapKind::Missing,
                    "the Gemfile has no Gemfile.lock, so its locked gem versions are unknown",
                );
            }
        }
        if let Some(lockfile) = lockfile {
            runtime |= lockfile_rows(&mut collector, lockfile, &owner);
        }
        for gemspec in &gemspecs {
            runtime |= gemspec_rows(&mut collector, gemspec, &owner);
        }
        if bundles.contains(directory) {
            for name in RUNTIME_FILE_NAMES {
                // rbenv, chruby and asdf read the nearest file upward.
                let pin = directory.ancestors().find_map(|level| {
                    by_directory
                        .get(level)
                        .and_then(|files| named(files, &[name]))
                });
                if let Some(pin) = pin {
                    runtime |= runtime_file_row(&mut collector, pin, &owner);
                }
            }
            if !runtime {
                collector.rows.push(row(
                    primary,
                    &owner,
                    RowSpec {
                        ecosystem: RUBY_TOOLCHAIN_ECOSYSTEM,
                        package: "ruby".to_owned(),
                        kind: DependencyEvidenceKind::Constraint,
                        requirement: None,
                        exact: None,
                        source: None,
                        scope: DependencyScope::Unknown,
                        conditions: vec![condition("ruby.runtime_evidence", "none")],
                        range: 0..0,
                        complete: true,
                    },
                ));
            }
        }
    }
    if bundles.is_empty() {
        collector.gap(
            Path::new("Gemfile"),
            0..0,
            DependencyEvidenceGapKind::Missing,
            "no Gemfile or Gemfile.lock was supplied, so the gems a Ruby program loads are unknown",
        );
    }
    let rows = std::mem::take(&mut collector.rows);
    for row in rows {
        if result.rows.len() >= limits.max_rows {
            result.gaps.push(DependencyEvidenceGap {
                kind: DependencyEvidenceGapKind::Limit,
                build_file: row.build_file,
                byte_range: row.byte_range,
                message: "Ruby dependency evidence row limit".to_owned(),
            });
            break;
        }
        result.rows.push(row);
    }
    result.rows.sort_by_cached_key(DependencyEvidence::id);
    result
}

/// Where a Gemfile `gem` call's context came from: enclosing `group`,
/// `platforms` and `source`/`git`/`path` blocks, and whether a conditional
/// encloses it.
#[derive(Clone, Default)]
struct GemfileContext {
    groups: Vec<String>,
    platforms: Vec<String>,
    source: Option<String>,
    conditional: bool,
}

/// Returns whether the Gemfile declares the Ruby runtime.
fn gemfile_rows(
    collector: &mut Collector<'_>,
    input: &Input<'_>,
    owner: &str,
    has_gemspec: bool,
) -> bool {
    let Some(tree) = parse_ruby_tree(input.source) else {
        collector.gap(
            input.path,
            0..input.source.len(),
            DependencyEvidenceGapKind::Malformed,
            "the Gemfile could not be parsed",
        );
        return false;
    };
    let parsed = !tree.root_node().has_error();
    if !parsed {
        collector.gap(
            input.path,
            0..input.source.len(),
            DependencyEvidenceGapKind::Malformed,
            "the Gemfile has syntax errors",
        );
    }
    let mut runtime = false;
    let mut stack = vec![(tree.root_node(), GemfileContext::default())];
    while let Some((node, context)) = stack.pop() {
        if node.kind() == "call" && node.child_by_field_name("receiver").is_none() {
            let method = node
                .child_by_field_name("method")
                .map(|method| ruby_node_text(method, input.source))
                .unwrap_or_default();
            let arguments = ruby_call_arguments(node);
            match method {
                "gem" => {
                    let gem = GemCall::read(&arguments, input.source);
                    let mut conditions = Vec::new();
                    let groups = gem
                        .groups
                        .iter()
                        .chain(&context.groups)
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>();
                    if groups.is_empty() {
                        conditions.push(condition("bundler.group", "default"));
                    }
                    conditions.extend(groups.iter().map(|group| condition("bundler.group", group)));
                    conditions.extend(
                        gem.platforms
                            .iter()
                            .chain(&context.platforms)
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .map(|platform| condition("bundler.platform", platform)),
                    );
                    if context.conditional {
                        conditions.push(condition("bundler.conditional", "true"));
                    }
                    let scope = if groups.is_empty() || groups.contains("default") {
                        DependencyScope::Runtime
                    } else if groups.iter().all(|group| *group == "test") {
                        DependencyScope::Test
                    } else {
                        DependencyScope::Unknown
                    };
                    let source = gem.source.clone().or_else(|| context.source.clone());
                    let Some(name) = gem.name.clone() else {
                        collector.gap(
                            input.path,
                            node.byte_range(),
                            DependencyEvidenceGapKind::Unresolved,
                            "a Gemfile gem call names no literal gem",
                        );
                        continue;
                    };
                    collector.rows.push(row(
                        input,
                        owner,
                        RowSpec {
                            ecosystem: RUBYGEMS_ECOSYSTEM,
                            package: name,
                            kind: DependencyEvidenceKind::Declared,
                            requirement: gem.requirement(),
                            exact: None,
                            source,
                            scope,
                            conditions,
                            range: node.byte_range(),
                            complete: parsed && gem.complete,
                        },
                    ));
                    continue;
                }
                "ruby" => {
                    runtime = true;
                    collector
                        .rows
                        .push(ruby_directive_row(input, owner, node, &arguments, parsed));
                    continue;
                }
                "gemspec" if !has_gemspec => {
                    collector.gap(
                        input.path,
                        node.byte_range(),
                        DependencyEvidenceGapKind::Missing,
                        "the Gemfile loads a gemspec that is not beside it",
                    );
                }
                "eval_gemfile" => {
                    collector.gap(
                        input.path,
                        node.byte_range(),
                        DependencyEvidenceGapKind::Unsupported,
                        "eval_gemfile declarations are not read",
                    );
                }
                "group" | "platforms" | "platform" | "source" | "git" | "path" | "github" => {
                    if let Some(block) = node.child_by_field_name("block") {
                        let mut inner = context.clone();
                        let values = arguments
                            .iter()
                            .filter_map(|argument| literal_name(*argument, input.source))
                            .collect::<Vec<_>>();
                        match method {
                            "group" => inner.groups.extend(values),
                            "platforms" | "platform" => inner.platforms.extend(values),
                            _ => {
                                inner.source =
                                    values.first().map(|value| source_identity(method, value))
                            }
                        }
                        stack.push((block, inner));
                        continue;
                    }
                }
                _ => {}
            }
        }
        let conditional = context.conditional
            || matches!(
                node.kind(),
                "if" | "unless" | "case" | "if_modifier" | "unless_modifier" | "conditional"
            );
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            let mut inner = context.clone();
            inner.conditional = conditional;
            stack.push((child, inner));
        }
    }
    runtime
}

/// The `gem` call's literal name, requirements and options.
#[derive(Default)]
struct GemCall {
    name: Option<String>,
    requirements: Vec<String>,
    groups: Vec<String>,
    platforms: Vec<String>,
    source: Option<String>,
    complete: bool,
}

impl GemCall {
    fn read(arguments: &[Node<'_>], source: &str) -> Self {
        let mut gem = GemCall {
            complete: true,
            ..Default::default()
        };
        let mut positional = arguments
            .iter()
            .filter(|argument| argument.kind() != "pair");
        gem.name = positional
            .next()
            .and_then(|argument| string_value(*argument, source));
        for argument in positional {
            match literal_strings(*argument, source) {
                Some(values) => gem.requirements.extend(values),
                None => gem.complete = false,
            }
        }
        for pair in arguments
            .iter()
            .filter(|argument| argument.kind() == "pair")
        {
            let (Some(key), Some(value)) = (
                pair.child_by_field_name("key"),
                pair.child_by_field_name("value"),
            ) else {
                gem.complete = false;
                continue;
            };
            let Some(key) = literal_name(key, source) else {
                gem.complete = false;
                continue;
            };
            let names = || literal_names(value, source);
            match key.as_str() {
                "group" | "groups" => match names() {
                    Some(values) => gem.groups.extend(values),
                    None => gem.complete = false,
                },
                "platform" | "platforms" => match names() {
                    Some(values) => gem.platforms.extend(values),
                    None => gem.complete = false,
                },
                "git" | "path" | "github" | "source" => match string_value(value, source) {
                    Some(value) => gem.source = Some(source_identity(&key, &value)),
                    None => gem.complete = false,
                },
                _ => {}
            }
        }
        gem
    }

    fn requirement(&self) -> Option<String> {
        (!self.requirements.is_empty()).then(|| self.requirements.join(", "))
    }
}

/// The source identity a lock records for the same declaration kind.
fn source_identity(kind: &str, value: &str) -> String {
    match kind {
        "git" => format!("git+{value}"),
        "github" => format!("git+https://github.com/{value}.git"),
        "path" => format!("path:{value}"),
        _ => value.to_owned(),
    }
}

fn ruby_directive_row(
    input: &Input<'_>,
    owner: &str,
    node: Node<'_>,
    arguments: &[Node<'_>],
    parsed: bool,
) -> DependencyEvidence {
    let mut complete = parsed;
    let mut requirements = Vec::new();
    let mut conditions = vec![condition("ruby.runtime_evidence", "gemfile_ruby_directive")];
    for argument in arguments {
        if argument.kind() == "pair" {
            let key = argument
                .child_by_field_name("key")
                .and_then(|key| literal_name(key, input.source));
            let value = argument.child_by_field_name("value").and_then(|value| {
                string_value(value, input.source).or_else(|| literal_name(value, input.source))
            });
            match (key.as_deref(), value) {
                (Some("engine"), Some(value)) => conditions.push(condition("ruby.engine", &value)),
                (Some("engine_version"), Some(value)) => {
                    conditions.push(condition("ruby.engine_version", &value))
                }
                (Some("patchlevel"), Some(value)) => {
                    conditions.push(condition("ruby.patchlevel", &value))
                }
                (Some("file"), Some(value)) => {
                    conditions.push(condition("ruby.version_file", &value))
                }
                _ => complete = false,
            }
        } else {
            match literal_strings(*argument, input.source) {
                Some(values) => requirements.extend(values),
                None => complete = false,
            }
        }
    }
    row(
        input,
        owner,
        RowSpec {
            ecosystem: RUBY_TOOLCHAIN_ECOSYSTEM,
            package: "ruby".to_owned(),
            kind: DependencyEvidenceKind::Constraint,
            requirement: (!requirements.is_empty()).then(|| requirements.join(", ")),
            exact: None,
            source: None,
            scope: DependencyScope::Unknown,
            conditions,
            range: node.byte_range(),
            complete,
        },
    )
}

/// Returns whether the gemspec declares a required Ruby version.
fn gemspec_rows(collector: &mut Collector<'_>, input: &Input<'_>, owner: &str) -> bool {
    let Some(tree) = parse_ruby_tree(input.source) else {
        collector.gap(
            input.path,
            0..input.source.len(),
            DependencyEvidenceGapKind::Malformed,
            "the gemspec could not be parsed",
        );
        return false;
    };
    let parsed = !tree.root_node().has_error();
    if !parsed {
        collector.gap(
            input.path,
            0..input.source.len(),
            DependencyEvidenceGapKind::Malformed,
            "the gemspec has syntax errors",
        );
    }
    let mut runtime = false;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let method = |node: Node<'_>| {
            node.child_by_field_name("method")
                .map(|method| ruby_node_text(method, input.source))
        };
        if node.kind() == "call" && node.child_by_field_name("receiver").is_some() {
            let dependency_type = match method(node) {
                Some("add_dependency" | "add_runtime_dependency") => Some("runtime"),
                Some("add_development_dependency") => Some("development"),
                _ => None,
            };
            if let Some(dependency_type) = dependency_type {
                let gem = GemCall::read(&ruby_call_arguments(node), input.source);
                let Some(name) = gem.name.clone() else {
                    collector.gap(
                        input.path,
                        node.byte_range(),
                        DependencyEvidenceGapKind::Unresolved,
                        "a gemspec dependency names no literal gem",
                    );
                    continue;
                };
                collector.rows.push(row(
                    input,
                    owner,
                    RowSpec {
                        ecosystem: RUBYGEMS_ECOSYSTEM,
                        package: name,
                        kind: DependencyEvidenceKind::Declared,
                        requirement: gem.requirement(),
                        exact: None,
                        source: None,
                        scope: if dependency_type == "runtime" {
                            DependencyScope::Runtime
                        } else {
                            DependencyScope::Unknown
                        },
                        conditions: vec![condition("rubygems.dependency_type", dependency_type)],
                        range: node.byte_range(),
                        complete: parsed && gem.complete,
                    },
                ));
                continue;
            }
        }
        if node.kind() == "assignment"
            && let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
            && left.kind() == "call"
            && method(left) == Some("required_ruby_version")
        {
            runtime = true;
            let requirements = literal_strings(right, input.source);
            collector.rows.push(row(
                input,
                owner,
                RowSpec {
                    ecosystem: RUBY_TOOLCHAIN_ECOSYSTEM,
                    package: "ruby".to_owned(),
                    kind: DependencyEvidenceKind::Constraint,
                    requirement: requirements.as_ref().map(|values| values.join(", ")),
                    exact: None,
                    source: None,
                    scope: DependencyScope::Unknown,
                    conditions: vec![condition(
                        "ruby.runtime_evidence",
                        "gemspec_required_ruby_version",
                    )],
                    range: node.byte_range(),
                    complete: parsed && requirements.is_some(),
                },
            ));
            continue;
        }
        brokk_bifrost_core::analyzer::tree_walk::push_named_children_reversed_as(
            node,
            &mut stack,
            |child| child,
        );
    }
    runtime
}

/// The string value of a literal string node.
fn string_value(node: Node<'_>, source: &str) -> Option<String> {
    RUBY_STRUCTURAL_SPEC.string_literal_value(node, source)
}

/// A literal string, or an array of literal strings.
fn literal_strings(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    if node.kind() == "array" {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .map(|element| string_value(element, source))
            .collect();
    }
    string_value(node, source).map(|value| vec![value])
}

/// A symbol, hash-key symbol or string naming a group, platform or option.
fn literal_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "simple_symbol" => ruby_node_text(node, source)
            .strip_prefix(':')
            .map(str::to_owned),
        "hash_key_symbol" => Some(ruby_node_text(node, source).to_owned()),
        _ => string_value(node, source),
    }
}

/// A name, or an array of names.
fn literal_names(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    if node.kind() == "array" {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .map(|element| literal_name(element, source))
            .collect();
    }
    literal_name(node, source).map(|value| vec![value])
}

/// Lockfile top-level sections Bundler writes. `PLUGIN SOURCE` lists Bundler
/// plugins rather than gems the program loads.
const LOCKFILE_SECTIONS: [&str; 9] = [
    "GEM",
    "GIT",
    "PATH",
    "PLUGIN SOURCE",
    "PLATFORMS",
    "DEPENDENCIES",
    "CHECKSUMS",
    "RUBY VERSION",
    "BUNDLED WITH",
];

/// Byte offset of `slice` inside `source`; `slice` must borrow from it.
fn offset_in(source: &str, slice: &str) -> usize {
    let offset = (slice.as_ptr() as usize).wrapping_sub(source.as_ptr() as usize);
    assert!(
        offset + slice.len() <= source.len(),
        "lockfile slice is not borrowed from its source"
    );
    offset
}

/// The range from `start` to the end of its line, without the line ending.
fn rest_of_line(source: &str, start: usize) -> Range<usize> {
    let end = source[start..]
        .find('\n')
        .map_or(source.len(), |length| start + length);
    start..start + source[start..end].trim_end().len()
}

/// Returns whether the lock records the Ruby runtime.
fn lockfile_rows(collector: &mut Collector<'_>, input: &Input<'_>, owner: &str) -> bool {
    let source = input.source;
    let mut sections = 0;
    let mut line_start = 0;
    for line in source.split_inclusive('\n') {
        let header = line.trim_end();
        if !header.is_empty() && !header.starts_with(char::is_whitespace) {
            if LOCKFILE_SECTIONS.contains(&header) {
                sections += 1;
            } else {
                collector.gap(
                    input.path,
                    line_start..line_start + header.len(),
                    DependencyEvidenceGapKind::Unsupported,
                    format!("the Gemfile.lock section {header:?} is not read"),
                );
            }
        }
        line_start += line.len();
    }
    if sections == 0 {
        collector.gap(
            input.path,
            0..source.len(),
            DependencyEvidenceGapKind::Malformed,
            "the Gemfile.lock has no Bundler sections",
        );
        return false;
    }
    let lock = rubund::parser::parse_lockfile(source);
    let direct = lock
        .dependencies
        .iter()
        .map(|(name, _)| *name)
        .collect::<BTreeSet<_>>();
    for spec in &lock.specs {
        let range = rest_of_line(source, offset_in(source, spec.name));
        let (version, platform) = spec
            .version
            .split_once('-')
            .map_or((spec.version, None), |(version, platform)| {
                (version, Some(platform))
            });
        let mut complete = GemVersion::parse(version).is_ok();
        if !complete {
            collector.gap(
                input.path,
                range.clone(),
                DependencyEvidenceGapKind::Malformed,
                format!("{:?} is not a RubyGems version", spec.version),
            );
        }
        let mut conditions = vec![condition(
            "bundler.lock_association",
            if direct.contains(spec.name) {
                "direct"
            } else {
                "transitive"
            },
        )];
        if let Some(platform) = platform {
            conditions.push(condition("bundler.platform", platform));
        }
        let source_identity = match lock.sources.get(spec.source_index) {
            Some(locked) => {
                let (kind, identity) = match locked.type_ {
                    rubund::parser::SourceType::Gem => ("gem", locked.remote.to_owned()),
                    rubund::parser::SourceType::Git => (
                        "git",
                        match locked.revision {
                            Some(revision) => format!("git+{}#{revision}", locked.remote),
                            None => format!("git+{}", locked.remote),
                        },
                    ),
                    rubund::parser::SourceType::Path => (
                        "path",
                        format!("path:{}", locked.path.unwrap_or(locked.remote)),
                    ),
                };
                conditions.push(condition("bundler.source_kind", kind));
                if let Some(branch) = locked.branch {
                    conditions.push(condition("bundler.git_branch", branch));
                }
                complete &= !locked.remote.is_empty() || locked.path.is_some();
                Some(identity)
            }
            None => {
                complete = false;
                None
            }
        };
        collector.rows.push(row(
            input,
            owner,
            RowSpec {
                ecosystem: RUBYGEMS_ECOSYSTEM,
                package: spec.name.to_owned(),
                kind: DependencyEvidenceKind::Locked,
                requirement: None,
                exact: Some(version.to_owned()),
                source: source_identity,
                scope: DependencyScope::Unknown,
                conditions,
                range,
                complete,
            },
        ));
    }
    for (name, version, checksum) in &lock.checksums {
        let (exact, platform) = version
            .split_once('-')
            .map_or((*version, None), |(version, platform)| {
                (version, Some(platform))
            });
        let mut conditions = vec![condition("bundler.checksum", checksum)];
        if let Some(platform) = platform {
            conditions.push(condition("bundler.platform", platform));
        }
        collector.rows.push(row(
            input,
            owner,
            RowSpec {
                ecosystem: RUBYGEMS_ECOSYSTEM,
                package: (*name).to_owned(),
                kind: DependencyEvidenceKind::Checksum,
                requirement: None,
                exact: Some(exact.to_owned()),
                source: None,
                scope: DependencyScope::Unknown,
                conditions,
                range: rest_of_line(source, offset_in(source, name)),
                complete: true,
            },
        ));
    }
    let Some(ruby) = lock.ruby_version else {
        return false;
    };
    let range = rest_of_line(source, offset_in(source, ruby));
    // `ruby 3.2.2p53`, or `ruby 3.1.4p0 (jruby 9.4.5.0)` for another engine.
    let mut conditions = vec![
        condition("ruby.runtime_evidence", "gemfile_lock_ruby_version"),
        condition("ruby.runtime_override", "unobserved"),
    ];
    let text = ruby.strip_prefix("ruby ").unwrap_or(ruby);
    let (version, engine) = match text.split_once(" (") {
        Some((version, engine)) => (version, Some(engine.trim_end_matches(')'))),
        None => (text, None),
    };
    if let Some(engine) = engine {
        conditions.push(condition("ruby.engine", engine));
    }
    let version = mri_version(version, &mut conditions);
    let complete = version.is_some();
    if !complete {
        collector.gap(
            input.path,
            range.clone(),
            DependencyEvidenceGapKind::Malformed,
            format!("{ruby:?} is not a Ruby version"),
        );
    }
    collector.rows.push(row(
        input,
        owner,
        RowSpec {
            ecosystem: RUBY_TOOLCHAIN_ECOSYSTEM,
            package: "ruby".to_owned(),
            kind: DependencyEvidenceKind::Locked,
            requirement: None,
            exact: version,
            source: None,
            scope: DependencyScope::Unknown,
            conditions,
            range,
            complete,
        },
    ));
    true
}

/// The release of a Ruby version that may carry a patchlevel (`3.2.0p0`),
/// recording the patchlevel as a condition.
fn mri_version(text: &str, conditions: &mut Vec<DependencyCondition>) -> Option<String> {
    // A patchlevel follows the release's last digit; `3.3.0-preview1` has none.
    let (version, patchlevel) = match text.rsplit_once('p') {
        Some((version, patchlevel))
            if version.ends_with(|c: char| c.is_ascii_digit())
                && !patchlevel.is_empty()
                && patchlevel.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            (version, Some(patchlevel))
        }
        _ => (text, None),
    };
    GemVersion::parse(version).ok()?;
    if let Some(patchlevel) = patchlevel {
        conditions.push(condition("ruby.patchlevel", patchlevel));
    }
    Some(version.to_owned())
}

/// A `.ruby-version` or `.tool-versions` pin. Returns whether it names Ruby.
fn runtime_file_row(collector: &mut Collector<'_>, input: &Input<'_>, owner: &str) -> bool {
    let tool_versions = input.path.ends_with(".tool-versions");
    let mut line_start = 0;
    let mut pin = None;
    for line in input.source.split_inclusive('\n') {
        let content = line.split('#').next().unwrap_or("").trim();
        let leading = line.len() - line.trim_start().len();
        if !content.is_empty() {
            if !tool_versions {
                pin = Some((content, line_start + leading));
                break;
            }
            // `ruby 3.2.0 3.1.0`: the first version wins, the rest are fallbacks.
            let mut fields = content.split_whitespace();
            if fields.next() == Some("ruby")
                && let Some(version) = fields.next()
            {
                pin = Some((version, line_start + leading));
                break;
            }
        }
        line_start += line.len();
    }
    let Some((text, start)) = pin else {
        if !tool_versions {
            collector.gap(
                input.path,
                0..input.source.len(),
                DependencyEvidenceGapKind::Malformed,
                "the .ruby-version file names no version",
            );
        }
        return false;
    };
    let mut conditions = vec![
        condition(
            "ruby.runtime_evidence",
            if tool_versions {
                "tool_versions_file"
            } else {
                "ruby_version_file"
            },
        ),
        condition("ruby.runtime_override", "unobserved"),
    ];
    // `ruby-3.2.0` names MRI; `jruby-9.4.5.0` or `truffleruby-23.0.0`
    // another engine whose version is not a Ruby version.
    let (engine, version) = match text.split_once('-') {
        Some((engine, version)) if !engine.starts_with(|c: char| c.is_ascii_digit()) => {
            (engine, version)
        }
        _ => ("ruby", text),
    };
    if engine != "ruby" {
        conditions.push(condition("ruby.engine", engine));
    }
    let exact = (engine == "ruby")
        .then(|| mri_version(version, &mut conditions))
        .flatten()
        .filter(|version| {
            let parts = version.split('.').collect::<Vec<_>>();
            parts.len() == 3
                && parts
                    .iter()
                    .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
        });
    let line = rest_of_line(input.source, start);
    collector.rows.push(row(
        input,
        owner,
        RowSpec {
            ecosystem: RUBY_TOOLCHAIN_ECOSYSTEM,
            package: "ruby".to_owned(),
            kind: if exact.is_some() {
                DependencyEvidenceKind::Locked
            } else {
                DependencyEvidenceKind::Constraint
            },
            requirement: exact.is_none().then(|| text.to_owned()),
            exact,
            source: None,
            scope: DependencyScope::Unknown,
            conditions,
            range: line,
            complete: true,
        },
    ));
    true
}

/// A RubyGems version in `Gem::Version` order. Segments are runs of digits
/// or of letters; a letter segment makes the version a prerelease and sorts
/// below any number, so `8.1.0.beta1 < 8.1.0`. Trailing zeros of the release
/// and of the prerelease part do not count, so `1.0 == 1.0.0`.
#[derive(Debug, Clone)]
pub struct GemVersion {
    segments: Vec<GemSegment>,
    canonical: Vec<GemSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GemSegment {
    Number(u64),
    Text(String),
}

impl GemSegment {
    fn order(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match (self, other) {
            (Self::Number(left), Self::Number(right)) => left.cmp(right),
            (Self::Text(left), Self::Text(right)) => left.cmp(right),
            (Self::Text(_), Self::Number(_)) => Ordering::Less,
            (Self::Number(_), Self::Text(_)) => Ordering::Greater,
        }
    }
}

impl GemVersion {
    /// Accepts what `Gem::Version.correct?` accepts; a `-` starts a
    /// prerelease, as RubyGems reads it as `.pre.`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let invalid = || format!("{text:?} is not a RubyGems version");
        let text = text.trim();
        let (release, prerelease) = text
            .split_once('-')
            .map_or((text, None), |(release, prerelease)| {
                (release, Some(prerelease))
            });
        let alphanumeric = |part: &str, extra: Option<char>| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || extra == Some(c))
        };
        let mut parts = release.split('.');
        let first = parts.next().expect("split yields one part");
        if first.is_empty() || !first.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        if !parts.all(|part| alphanumeric(part, None))
            || prerelease.is_some_and(|prerelease| {
                !prerelease
                    .split('.')
                    .all(|part| alphanumeric(part, Some('-')))
            })
        {
            return Err(invalid());
        }
        let normalized = text.replace('-', ".pre.");
        let mut segments = Vec::new();
        let mut rest = normalized.as_str();
        while let Some(start) = rest.find(|c: char| c.is_ascii_alphanumeric()) {
            rest = &rest[start..];
            let digits = rest.starts_with(|c: char| c.is_ascii_digit());
            let length = rest
                .find(|c: char| {
                    !(if digits {
                        c.is_ascii_digit()
                    } else {
                        c.is_ascii_alphabetic()
                    })
                })
                .unwrap_or(rest.len());
            let segment = &rest[..length];
            segments.push(if digits {
                GemSegment::Number(segment.parse().map_err(|_| invalid())?)
            } else {
                GemSegment::Text(segment.to_owned())
            });
            rest = &rest[length..];
        }
        let split = segments
            .iter()
            .position(|segment| matches!(segment, GemSegment::Text(_)))
            .unwrap_or(segments.len());
        let trim = |part: &[GemSegment]| {
            let length = part
                .iter()
                .rposition(|segment| *segment != GemSegment::Number(0))
                .map_or(0, |index| index + 1);
            part[..length].to_vec()
        };
        let mut canonical = trim(&segments[..split]);
        canonical.extend(trim(&segments[split..]));
        Ok(Self {
            segments,
            canonical,
        })
    }

    /// The semver activation coordinate for this version (#10011). The first
    /// three release segments are major, minor and patch, missing ones zero.
    /// Later release segments, such as the `1` of Rails `7.0.8.1`, are below
    /// semver's resolution and become build metadata, which requirements
    /// ignore: a pack requirement reads `7.0.8.1` as `7.0.8`, as the JDK
    /// coordinate reads a fourth JDK component. Prerelease segments become
    /// semver prerelease identifiers, so `8.1.0.beta1` is `8.1.0-beta.1`.
    /// Trailing zeros do not count, matching `Gem::Version` equality.
    pub fn coordinate_version(&self) -> semver::Version {
        let split = self
            .canonical
            .iter()
            .position(|segment| matches!(segment, GemSegment::Text(_)))
            .unwrap_or(self.canonical.len());
        let (release, prerelease) = self.canonical.split_at(split);
        let number = |segment: &GemSegment| match segment {
            GemSegment::Number(number) => *number,
            GemSegment::Text(_) => unreachable!("release segments are numbers"),
        };
        let component = |index: usize| release.get(index).map_or(0, number);
        let join = |segments: &[GemSegment]| {
            segments
                .iter()
                .map(|segment| match segment {
                    GemSegment::Number(number) => number.to_string(),
                    GemSegment::Text(text) => text.clone(),
                })
                .collect::<Vec<_>>()
                .join(".")
        };
        let mut version = semver::Version::new(component(0), component(1), component(2));
        if !prerelease.is_empty() {
            version.pre = semver::Prerelease::new(&join(prerelease))
                .expect("RubyGems prerelease segments are semver identifiers");
        }
        if release.len() > 3 {
            version.build = semver::BuildMetadata::new(&join(&release[3..]))
                .expect("numeric release segments are semver build identifiers");
        }
        version
    }

    /// `Gem::Version#release`: the version without its prerelease part.
    fn release(&self) -> Self {
        let split = self
            .segments
            .iter()
            .position(|segment| matches!(segment, GemSegment::Text(_)))
            .unwrap_or(self.segments.len());
        Self::from_segments(self.segments[..split].to_vec())
    }

    /// `Gem::Version#bump`: the upper bound of `~>`. `2.2` and `2.2.0.rc1`
    /// bump to `3` and `2.3`.
    fn bump(&self) -> Self {
        let mut segments = self.release().segments;
        if segments.len() > 1 {
            segments.pop();
        }
        match segments.last_mut() {
            Some(GemSegment::Number(last)) => *last += 1,
            _ => unreachable!("a release begins with a number"),
        }
        Self::from_segments(segments)
    }

    fn from_segments(segments: Vec<GemSegment>) -> Self {
        let text = segments
            .iter()
            .map(|segment| match segment {
                GemSegment::Number(number) => number.to_string(),
                GemSegment::Text(text) => text.clone(),
            })
            .collect::<Vec<_>>()
            .join(".");
        Self::parse(&text).expect("segments of a version form a version")
    }
}

impl PartialEq for GemVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for GemVersion {}

impl Ord for GemVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let zero = GemSegment::Number(0);
        let length = self.canonical.len().max(other.canonical.len());
        (0..length)
            .map(|index| {
                let left = self.canonical.get(index).unwrap_or(&zero);
                let right = other.canonical.get(index).unwrap_or(&zero);
                left.order(right)
            })
            .find(|ordering| ordering.is_ne())
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

impl PartialOrd for GemVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GemOperator {
    Equal,
    NotEqual,
    Greater,
    Less,
    GreaterOrEqual,
    LessOrEqual,
    /// `~>`: at least the version, below its bump.
    Pessimistic,
}

/// An authored affected-version range in `Gem::Requirement` syntax for
/// `rubygems` or `ruby-toolchain`: comma- or whitespace-joined requirements
/// (`>= 2.0, < 2.2.22`, `~> 2.2.0`, `< 2.2.22`) and `||`-joined alternatives,
/// as an advisory's list of vulnerable ranges reads. Each requirement keeps
/// RubyGems semantics: prereleases order below their release and match
/// ordinary bounds, and `~> 2.2` admits `2.9` but not `3.0.0.beta1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RubyVersionRange {
    ecosystem: &'static str,
    alternatives: Vec<Vec<(GemOperator, GemVersion)>>,
}

impl RubyVersionRange {
    pub fn parse(ecosystem: &str, text: &str) -> Result<Self, String> {
        let ecosystem = match ecosystem {
            RUBYGEMS_ECOSYSTEM => RUBYGEMS_ECOSYSTEM,
            RUBY_TOOLCHAIN_ECOSYSTEM => RUBY_TOOLCHAIN_ECOSYSTEM,
            _ => unreachable!("{ecosystem} is not a Ruby version ecosystem"),
        };
        let alternatives = text
            .split("||")
            .map(parse_requirements)
            .collect::<Result<_, String>>()?;
        Ok(Self {
            ecosystem,
            alternatives,
        })
    }

    fn admits(&self, version: &GemVersion) -> bool {
        self.alternatives.iter().any(|requirements| {
            requirements.iter().all(|(operator, bound)| match operator {
                GemOperator::Equal => version == bound,
                GemOperator::NotEqual => version != bound,
                GemOperator::Greater => version > bound,
                GemOperator::Less => version < bound,
                GemOperator::GreaterOrEqual => version >= bound,
                GemOperator::LessOrEqual => version <= bound,
                GemOperator::Pessimistic => version >= bound && version.release() < bound.bump(),
            })
        })
    }
}

fn parse_requirements(text: &str) -> Result<Vec<(GemOperator, GemVersion)>, String> {
    const OPERATORS: [(&str, GemOperator); 7] = [
        ("~>", GemOperator::Pessimistic),
        (">=", GemOperator::GreaterOrEqual),
        ("<=", GemOperator::LessOrEqual),
        ("!=", GemOperator::NotEqual),
        (">", GemOperator::Greater),
        ("<", GemOperator::Less),
        ("=", GemOperator::Equal),
    ];
    let separator = |c: char| c == ',' || c.is_whitespace();
    let mut requirements = Vec::new();
    let mut rest = text.trim_start_matches(separator);
    while !rest.is_empty() {
        let (operator, after) = OPERATORS
            .iter()
            .find_map(|(spelling, operator)| {
                rest.strip_prefix(spelling).map(|after| (*operator, after))
            })
            .unwrap_or((GemOperator::Equal, rest));
        let after = after.trim_start();
        let length = after.find(separator).unwrap_or(after.len());
        if length == 0 {
            return Err(format!("{text:?} has a requirement with no version"));
        }
        let version = GemVersion::parse(&after[..length])?;
        requirements.push((operator, version));
        rest = after[length..].trim_start_matches(separator);
    }
    if requirements.is_empty() {
        return Err("an empty RubyGems requirement alternative".to_owned());
    }
    Ok(requirements)
}

/// Whether one complete locked or installed row of the range's ecosystem has
/// an exact version in `range`. Declarations, runtime constraints, checksums
/// and gems locked from a `GIT` or `PATH` source (whose code need not be the
/// released gem of that version) have no comparable selected version and
/// stay unknown.
pub fn ruby_dependency_version_matches(
    row: &DependencyEvidence,
    range: &RubyVersionRange,
) -> Result<Option<bool>, String> {
    if row.ecosystem != range.ecosystem
        || !row.complete
        || !matches!(
            row.kind,
            DependencyEvidenceKind::Locked | DependencyEvidenceKind::Installed
        )
        || (row.ecosystem == RUBYGEMS_ECOSYSTEM
            && !row.conditions.iter().any(|condition| {
                condition.kind == "bundler.source_kind" && condition.value == "gem"
            }))
    {
        return Ok(None);
    }
    row.exact_version
        .as_deref()
        .map(|version| GemVersion::parse(version).map(|version| range.admits(&version)))
        .transpose()
}

#[cfg(test)]
mod tests {
    use crate::analyzer::ruby::dependency_evidence::*;

    fn version(text: &str) -> GemVersion {
        GemVersion::parse(text).unwrap()
    }

    fn admits(range: &str, candidate: &str) -> bool {
        RubyVersionRange::parse(RUBYGEMS_ECOSYSTEM, range)
            .unwrap()
            .admits(&version(candidate))
    }

    /// RubyGems ordering and requirement operators, checked against the
    /// answers `Gem::Version#<=>` and `Gem::Requirement#satisfied_by?` give.
    #[test]
    fn rubygems_versions_and_requirements_follow_gem_semantics() {
        for (lower, higher) in [
            ("8.1.0.beta1", "8.1.0"),
            ("8.1.0.beta1", "8.1.0.beta2"),
            ("8.1.0.beta2", "8.1.0.rc1"),
            ("1.0.a", "1.0.b"),
            ("1.0.0-rc1", "1.0.0"),
            ("1.9", "1.10"),
            ("2.2.21", "2.2.22"),
        ] {
            assert!(version(lower) < version(higher), "{lower} < {higher}");
        }
        assert_eq!(version("1.0"), version("1.0.0"));
        assert_eq!(version("1.0.a"), version("1.0.0.a"));
        assert_eq!(version("1.0.0-rc1"), version("1.0.0.pre.rc1"));
        for invalid in ["", "v1.0", "1..0", "1.0 2", "junk"] {
            assert!(GemVersion::parse(invalid).is_err(), "{invalid:?}");
        }
        for (gem, coordinate) in [
            ("7.0.8.1", "7.0.8+1"),
            ("7.0.8.0", "7.0.8"),
            ("1.2", "1.2.0"),
            ("8.1.0.beta1", "8.1.0-beta.1"),
            ("1.0.0-rc1", "1.0.0-pre.rc.1"),
            ("2.0.0.1.rc2", "2.0.0-rc.2+1"),
        ] {
            assert_eq!(version(gem).coordinate_version().to_string(), coordinate);
        }
        assert!(admits("< 2.2.22", "2.2.21"));
        assert!(!admits("< 2.2.22", "2.2.22"));
        assert!(admits("<2.2.22", "2.2.22.rc1"));
        assert!(admits(">= 2.0, < 2.2.22", "2.1"));
        assert!(admits(">=2.0 <2.2.22", "2.1"));
        assert!(!admits(">= 2.0, < 2.2.22", "1.9"));
        assert!(admits("~> 2.2", "2.9.1"));
        assert!(!admits("~> 2.2", "3.0.0.beta1"));
        assert!(!admits("~> 2.2", "2.2.0.rc1"));
        assert!(admits("~> 2.2.0", "2.2.21"));
        assert!(!admits("~> 2.2.0", "2.3.0"));
        assert!(admits("~> 2.2.0.rc1", "2.2.0"));
        assert!(admits("< 1.0 || ~> 2.2.0", "0.9"));
        assert!(admits("!= 1.2.3", "1.2.4"));
        assert!(admits("2.2.21", "2.2.21.0"));
        for invalid in ["", "<", "< 1.0 ||", ">= x"] {
            assert!(
                RubyVersionRange::parse(RUBYGEMS_ECOSYSTEM, invalid).is_err(),
                "{invalid:?}"
            );
        }
    }
}
