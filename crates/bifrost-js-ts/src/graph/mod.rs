//! The JS/TS usage graph's language knowledge.
//!
//! The forward scan ([`extractor`] plus [`hits`]), the cacheable resolution
//! index ([`resolver`]), the whole-workspace inverted per-file walk
//! ([`inverted`]) and the receiver-facts index ([`receiver_analysis`]) are one
//! body of code and crossed together: they import each other's items freely.
//!
//! No analyzer handle appears here. `brokk-bifrost-analysis` downcasts once per
//! language and hands over a [`JsTsAnalyzerHost`](crate::providers::JsTsAnalyzerHost);
//! where a scan spans both dialects at once it is handed a [`JsTsHosts`] view,
//! the `JvmSourceRealm` shape.

pub mod common;
pub mod extractor;
pub mod hits;
pub mod inverted;
pub mod receiver_analysis;
pub mod resolver;

use crate::graph::extractor::scan_files_for_seeds;
use crate::graph::resolver::{JsTsUsageIndex, is_static_member, member_name};
use crate::parse::js_ts_tree_sitter_language_for_file;
use crate::providers::JsTsAnalyzerHost;
use crate::syntax::{direct_property_definitions, slice};
use crate::tsconfig::AliasResolver;
use brokk_bifrost_core::analyzer::usages::model::{
    ExportEntry, FuzzyResult, UsageHit, UsageHitSurface, UsageProof,
};
use brokk_bifrost_core::analyzer::usages::outcome::GraphUsageOutcome;
use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use std::collections::BTreeSet;
use tree_sitter::Parser;

/// The JS/TS analyzers a workspace has, viewed as one scan surface.
///
/// A single query resolves against one dialect and needs only that dialect's
/// host, but the whole-workspace edge builders walk TypeScript and JavaScript in
/// one pass and need both. Finding the members means downcasting an
/// `&dyn IAnalyzer` to `JavascriptAnalyzer` and `TypescriptAnalyzer` -- two
/// analysis-side types this crate must not name -- so
/// `brokk-bifrost-analysis` does the downcast and hands the list here, exactly
/// as it does for [`JvmSourceRealm`](https://docs.rs/brokk-bifrost-jvm).
pub struct JsTsHosts<'a> {
    hosts: Vec<(Language, &'a dyn JsTsAnalyzerHost)>,
}

impl<'a> JsTsHosts<'a> {
    /// A view over `hosts`, in the order the builder found them.
    pub fn new(hosts: Vec<(Language, &'a dyn JsTsAnalyzerHost)>) -> Self {
        Self { hosts }
    }

    /// Any member's shared alias resolver, or `None` when the workspace
    /// analyzes neither dialect. Every member is built over the same project
    /// root, so a scan that spans both dialects resolves specifiers through one
    /// warm config memo instead of building its own cold one.
    pub fn alias_resolver(&self) -> Option<&'a AliasResolver> {
        self.hosts
            .first()
            .map(|(_, host)| host.alias_resolver().as_ref())
    }

    /// The host for `language`, when the workspace analyzes it.
    pub fn get(&self, language: Language) -> Option<&'a dyn JsTsAnalyzerHost> {
        self.hosts
            .iter()
            .find(|(member, _)| *member == language)
            .map(|(_, host)| *host)
    }
}

/// Resolve every usage of `target` through the export/import graph.
///
/// The body of the `UsageQueryResolver` impl in `brokk-bifrost-analysis`, which
/// keeps the SPI block, the downcast that produces `host`, and the
/// missing-analyzer and cancellation outcomes. `analyzer` is the dispatching
/// analyzer -- in a mixed workspace a `MultiAnalyzer` -- and `host` is the JS/TS
/// analyzer for `language`.
#[allow(clippy::too_many_arguments)]
pub fn find_js_ts_usages(
    host: &dyn JsTsAnalyzerHost,
    analyzer: &dyn CodeUnitIndex,
    index: &JsTsUsageIndex,
    target: &CodeUnit,
    scan_scope: &UsageScanScope<'_>,
    language: Language,
    max_usages: usize,
) -> GraphUsageOutcome {
    let target_seed = target_seed_identifier(analyzer, target);
    let owner_seed_allowed = is_static_member(target)
        || !target.short_name().contains('.')
        || analyzer.parent_of(target).is_some();
    let exported_local_property =
        exported_local_property_binding(analyzer, index, target, language);
    let mut seeds = index.seeds_for_target(
        target.source(),
        &target_seed,
        target.short_name(),
        owner_seed_allowed,
    );
    if let Some(binding) = &exported_local_property {
        seeds.extend(
            binding
                .exported_names
                .iter()
                .cloned()
                .map(|name| (target.source().clone(), name)),
        );
    }
    let scan_hits = if seeds.is_empty() {
        let mut scan_files: HashSet<ProjectFile> =
            scan_scope.candidate_files().iter().cloned().collect();
        if scan_scope.allows(target.source()) {
            scan_files.insert(target.source().clone());
        }

        scan_files_for_seeds(
            host,
            analyzer,
            index,
            &scan_files,
            target,
            &BTreeSet::new(),
            language,
            exported_local_property
                .as_ref()
                .map(|binding| binding.receiver_root.as_str()),
            scan_scope.cancellation(),
        )
    } else {
        let candidate_files = scan_scope.candidate_files();
        let importers = index.importers_of_seeds(&seeds);
        let mut scan_files: HashSet<ProjectFile> = candidate_files.iter().cloned().collect();
        scan_files.extend(importers.into_iter().filter(|file| scan_scope.allows(file)));
        if scan_scope.allows(target.source()) {
            scan_files.insert(target.source().clone());
        }

        scan_files_for_seeds(
            host,
            analyzer,
            index,
            &scan_files,
            target,
            &seeds,
            language,
            exported_local_property
                .as_ref()
                .map(|binding| binding.receiver_root.as_str()),
            scan_scope.cancellation(),
        )
    };
    let (hits, unproven_hits): (BTreeSet<UsageHit>, BTreeSet<UsageHit>) = scan_hits
        .into_iter()
        .filter(|hit| &hit.enclosing != target)
        .partition(|hit| hit.proof == UsageProof::Proven);

    let external_hit_count = hits
        .iter()
        .filter(|hit| hit.kind.included_in(UsageHitSurface::ExternalUsages))
        .count();
    if external_hit_count > max_usages {
        return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
            short_name: target.short_name().to_string(),
            total_callsites: external_hit_count,
            limit: max_usages,
            sample_hits: hits,
        });
    }

    GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven(
        target.clone(),
        hits,
        unproven_hits,
    ))
}

fn target_seed_identifier(analyzer: &dyn CodeUnitIndex, target: &CodeUnit) -> String {
    if let Some(parent) = analyzer.parent_of(target)
        && !parent.is_module()
        && !parent.is_file_scope()
    {
        return parent.identifier().trim_end_matches("$static").to_string();
    }
    if is_static_member(target)
        && let Some((owner, _)) = target.short_name().rsplit_once('.') // fqname-M4: package-less short_name owner; fq.parent() would render the package-qualified owner, changing this string comparison
        && let Some(owner_name) = owner.rsplit('.').next()
    {
        return owner_name.to_string();
    }
    target.identifier().trim_end_matches("$static").to_string()
}

struct ExportedLocalPropertyBinding {
    receiver_root: String,
    exported_names: BTreeSet<String>,
}

fn exported_local_property_binding(
    analyzer: &dyn CodeUnitIndex,
    index: &JsTsUsageIndex,
    target: &CodeUnit,
    language: Language,
) -> Option<ExportedLocalPropertyBinding> {
    if language != Language::JavaScript || !target.is_field() {
        return None;
    }
    let target_member = member_name(target)?;
    let source = target.source().read_to_string().ok()?;
    let mut parser = Parser::new();
    let parser_language = js_ts_tree_sitter_language_for_file(target.source(), language)?;
    parser.set_language(&parser_language).ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let receiver_root = direct_property_definitions(
        tree.root_node(),
        source.as_str(),
        &analyzer.ranges(target),
        &target_member,
    )
    .into_iter()
    .find_map(|definition| {
        definition
            .receiver
            .members
            .is_empty()
            .then(|| slice(definition.receiver.root, source.as_str()).to_string())
    })?;

    let exported_names = index
        .exports_by_file
        .get(target.source())?
        .exports_by_name
        .iter()
        .filter_map(|(exported_name, entry)| match entry {
            ExportEntry::Local { local_name } if local_name == &receiver_root => {
                Some(exported_name.clone())
            }
            ExportEntry::Default {
                local_name: Some(local_name),
            } if local_name == &receiver_root => Some(exported_name.clone()),
            ExportEntry::Local { .. }
            | ExportEntry::Default { .. }
            | ExportEntry::ReexportedNamed { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    (!exported_names.is_empty()).then_some(ExportedLocalPropertyBinding {
        receiver_root,
        exported_names,
    })
}
