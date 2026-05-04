use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::hash::HashSet;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use crate::usages::model::{FuzzyResult, UsageHit};
use crate::usages::traits::UsageAnalyzer;
use rayon::prelude::*;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::Mutex;

/// Lines of context to include before/after a match in [`UsageHit::snippet`].
const SNIPPET_CONTEXT_LINES: usize = 3;
/// Hard cap on the confidence reported for a regex hit. The regex strategy never
/// disambiguates, so every hit it produces lands at 1.0.
const REGEX_HIT_CONFIDENCE: f64 = 1.0;

/// Dependency-light usage analyzer driven by language-specific regex templates.
///
/// Each candidate file is scanned in parallel; matches that pass `is_access_expression`
/// (which filters declarations and partial-word matches via the analyzer's tree-sitter pass)
/// are reported as [`UsageHit`]s. The strategy never invokes the JDT or LLM layers — it is
/// the universal fallback used by every language except Java.
pub struct RegexUsageAnalyzer;

impl RegexUsageAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RegexUsageAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl UsageAnalyzer for RegexUsageAnalyzer {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        if overloads.is_empty() {
            return FuzzyResult::empty_success();
        }

        let target = &overloads[0];
        let identifier = target.identifier().to_string();
        if identifier.is_empty() {
            return FuzzyResult::empty_success();
        }

        let lang = target
            .source()
            .rel_path()
            .extension()
            .and_then(|ext| ext.to_str())
            .map(Language::from_extension)
            .unwrap_or(Language::None);

        let templates = lang.search_patterns(target.kind());
        let quoted = regex::escape(&identifier);
        let patterns: Vec<Regex> = templates
            .iter()
            .filter_map(|template| {
                let raw = template.replace("$ident", &quoted);
                Regex::new(&raw).ok()
            })
            .collect();

        if patterns.is_empty() {
            return FuzzyResult::success(target.clone(), BTreeSet::new());
        }

        let bounded_pattern = format!(r"\b{}\b", quoted);
        let matching_units: BTreeSet<CodeUnit> = analyzer
            .search_definitions(&bounded_pattern, false)
            .into_iter()
            .filter(|cu| cu.identifier() == identifier)
            .collect();
        let is_unique = matching_units.len() <= 1;

        let hits: BTreeSet<UsageHit> = extract_usage_hits(analyzer, candidate_files, &patterns)
            .into_iter()
            .filter(|hit| &hit.enclosing != target)
            .collect();

        if hits.len() > max_usages {
            return FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: hits.len(),
                limit: max_usages,
            };
        }

        if is_unique {
            FuzzyResult::success(target.clone(), hits)
        } else {
            FuzzyResult::ambiguous(
                target.clone(),
                target.short_name().to_string(),
                matching_units,
                hits,
            )
        }
    }
}

fn extract_usage_hits(
    analyzer: &dyn IAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    patterns: &[Regex],
) -> BTreeSet<UsageHit> {
    let collected: Mutex<BTreeSet<UsageHit>> = Mutex::new(BTreeSet::new());

    let files: Vec<&ProjectFile> = candidate_files.iter().collect();
    files.par_iter().for_each(|file| {
        let Ok(is_binary) = file.is_binary() else {
            return;
        };
        if is_binary {
            return;
        }

        let Ok(content) = file.read_to_string() else {
            return;
        };
        if content.is_empty() {
            return;
        }

        let line_starts = compute_line_starts(&content);
        let line_count = line_starts.len();

        let mut local: BTreeSet<UsageHit> = BTreeSet::new();
        for pattern in patterns {
            for m in pattern.find_iter(&content) {
                let start_byte = m.start();
                let end_byte = m.end();

                if !analyzer.is_access_expression(file, start_byte, end_byte) {
                    continue;
                }

                let line_idx = find_line_index_for_offset(&line_starts, start_byte);
                let snippet_start = line_idx.saturating_sub(SNIPPET_CONTEXT_LINES);
                let snippet_end = line_idx
                    .saturating_add(SNIPPET_CONTEXT_LINES)
                    .min(line_count.saturating_sub(1));
                let snippet = if line_count == 0 {
                    String::new()
                } else {
                    let mut buf = String::new();
                    for idx in snippet_start..=snippet_end {
                        let start = line_starts[idx];
                        let end = if idx + 1 < line_count {
                            line_starts[idx + 1]
                        } else {
                            content.len()
                        };
                        let line = content[start..end]
                            .trim_end_matches('\n')
                            .trim_end_matches('\r');
                        if !buf.is_empty() {
                            buf.push('\n');
                        }
                        buf.push_str(line);
                    }
                    buf
                };

                let range = Range {
                    start_byte,
                    end_byte,
                    start_line: line_idx,
                    end_line: line_idx,
                };

                if let Some(enclosing) = analyzer.enclosing_code_unit(file, &range) {
                    local.insert(UsageHit::new(
                        (*file).clone(),
                        line_idx + 1,
                        start_byte,
                        end_byte,
                        enclosing,
                        REGEX_HIT_CONFIDENCE,
                        snippet,
                    ));
                }
            }
        }

        if !local.is_empty() {
            let mut sink = collected
                .lock()
                .expect("usage hit collector mutex poisoned");
            sink.extend(local);
        }
    });

    collected
        .into_inner()
        .expect("usage hit collector mutex poisoned")
}
