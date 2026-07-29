use super::*;
use crate::{AnalyzerConfig, FilesystemProject, WorkspaceAnalyzer};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    weights: UsageReferenceWeights,
}

const PROFILES: &[Profile] = &[
    Profile {
        name: "uniform",
        weights: UsageReferenceWeights::UNIFORM,
    },
    Profile {
        name: "gentle_behavioral",
        weights: UsageReferenceWeights {
            calls: 2.0,
            members: 1.5,
            types: 1.0,
            other: 0.75,
        },
    },
    Profile {
        name: "subtle_behavioral",
        weights: UsageReferenceWeights {
            calls: 1.5,
            members: 1.25,
            types: 1.0,
            other: 0.875,
        },
    },
    Profile {
        name: "conservative_behavioral",
        weights: UsageReferenceWeights {
            calls: 2.0,
            members: 1.5,
            types: 0.75,
            other: 0.75,
        },
    },
    Profile {
        name: "moderate_behavioral",
        weights: UsageReferenceWeights {
            calls: 2.5,
            members: 1.75,
            types: 0.75,
            other: 0.5,
        },
    },
    Profile {
        name: "balanced_behavioral",
        weights: UsageReferenceWeights {
            calls: 3.0,
            members: 2.0,
            types: 1.0,
            other: 0.5,
        },
    },
    Profile {
        name: "type_light",
        weights: UsageReferenceWeights {
            calls: 3.0,
            members: 2.0,
            types: 0.5,
            other: 0.5,
        },
    },
    Profile {
        name: "calls_first",
        weights: UsageReferenceWeights {
            calls: 4.0,
            members: 1.5,
            types: 0.5,
            other: 0.25,
        },
    },
];

#[derive(Default, Clone, Copy)]
struct Metrics {
    ndcg: f64,
    mrr: f64,
    recall: f64,
    samples: usize,
}

impl Metrics {
    fn record(&mut self, ranked: &[ProjectFile], relevant: &HashSet<ProjectFile>) {
        if relevant.is_empty() {
            return;
        }
        let mut dcg = 0.0;
        let mut found = 0usize;
        let mut reciprocal = 0.0;
        for (index, file) in ranked.iter().take(10).enumerate() {
            if relevant.contains(file) {
                dcg += 1.0 / ((index + 2) as f64).log2();
                found += 1;
                if reciprocal == 0.0 {
                    reciprocal = 1.0 / (index + 1) as f64;
                }
            }
        }
        let ideal_len = relevant.len().min(10);
        let idcg = (0..ideal_len)
            .map(|index| 1.0 / ((index + 2) as f64).log2())
            .sum::<f64>();
        self.ndcg += if idcg > 0.0 { dcg / idcg } else { 0.0 };
        self.mrr += reciprocal;
        self.recall += found as f64 / relevant.len() as f64;
        self.samples += 1;
    }

    fn mean(self) -> serde_json::Value {
        let divisor = self.samples.max(1) as f64;
        json!({
            "samples": self.samples,
            "ndcg_at_10": self.ndcg / divisor,
            "mrr_at_10": self.mrr / divisor,
            "recall_at_10": self.recall / divisor,
        })
    }

    fn add_repo_mean(&mut self, repo: Metrics) {
        if repo.samples == 0 {
            return;
        }
        let divisor = repo.samples as f64;
        self.ndcg += repo.ndcg / divisor;
        self.mrr += repo.mrr / divisor;
        self.recall += repo.recall / divisor;
        self.samples += 1;
    }
}

#[test]
#[ignore = "multi-repository calibration benchmark; set BIFROST_USAGE_WEIGHT_BENCH_REPOS"]
fn benchmark_usage_reference_weight_profiles() {
    let Some(repos) = std::env::var_os("BIFROST_USAGE_WEIGHT_BENCH_REPOS")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
    else {
        eprintln!("skipping benchmark: set BIFROST_USAGE_WEIGHT_BENCH_REPOS");
        return;
    };
    let sample_limit = env_usize("BIFROST_USAGE_WEIGHT_BENCH_SAMPLES", 30);
    let commit_limit = env_usize("BIFROST_USAGE_WEIGHT_BENCH_COMMITS", 300);
    let random_seed = env_usize("BIFROST_USAGE_WEIGHT_BENCH_SEED", 781) as u64;
    let mut macro_metrics = vec![Metrics::default(); PROFILES.len()];

    for root in repos {
        assert!(
            root.is_dir(),
            "benchmark repository is missing: {}",
            root.display()
        );
        let started = Instant::now();
        let project = Arc::new(FilesystemProject::new(root.clone()).unwrap());
        let workspace = WorkspaceAnalyzer::build(project, AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let analyzer_ms = started.elapsed().as_secs_f64() * 1000.0;

        let graph_started = Instant::now();
        let ranking_graph = build_usage_ranking_graph(analyzer);
        let graph_ms = graph_started.elapsed().as_secs_f64() * 1000.0;
        let labels = cochange_labels(analyzer, &ranking_graph, commit_limit);
        let mut seeds = labels.keys().cloned().collect::<Vec<_>>();
        seeds.sort_by_key(|file| stable_sample_key(file, random_seed));
        seeds.truncate(sample_limit);

        let mut repo_metrics = vec![Metrics::default(); PROFILES.len()];
        let mut examples = Vec::new();
        let rank_started = Instant::now();
        for (seed_index, seed) in seeds.iter().enumerate() {
            let relevant = &labels[seed];
            let seed_weights = HashMap::from_iter([(seed.clone(), 1.0)]);
            let mut example_profiles = serde_json::Map::new();
            for (profile_index, profile) in PROFILES.iter().enumerate() {
                let ranked = related_files_by_usage_graph(
                    &ranking_graph,
                    &seed_weights,
                    10,
                    profile.weights,
                );
                let files = ranked
                    .iter()
                    .map(|candidate| candidate.file.clone())
                    .collect::<Vec<_>>();
                repo_metrics[profile_index].record(&files, relevant);
                if seed_index < 3 {
                    example_profiles.insert(
                        profile.name.to_string(),
                        json!(
                            files
                                .iter()
                                .take(5)
                                .map(normalized_rel_path)
                                .collect::<Vec<_>>()
                        ),
                    );
                }
            }
            if seed_index < 3 {
                examples.push(json!({
                    "seed": normalized_rel_path(seed),
                    "relevant_count": relevant.len(),
                    "profiles": example_profiles,
                }));
            }
        }
        let rank_ms = rank_started.elapsed().as_secs_f64() * 1000.0;

        let mut counts = UsageReferenceCounts::default();
        for edge in &ranking_graph.graph.edges {
            counts += edge.counts;
        }
        let profile_results = PROFILES
            .iter()
            .zip(&repo_metrics)
            .map(|(profile, metrics)| {
                json!({
                    "profile": profile.name,
                    "weights": {
                        "calls": profile.weights.calls,
                        "members": profile.weights.members,
                        "types": profile.weights.types,
                        "other": profile.weights.other,
                    },
                    "metrics": metrics.mean(),
                })
            })
            .collect::<Vec<_>>();
        for (aggregate, repo) in macro_metrics.iter_mut().zip(&repo_metrics) {
            aggregate.add_repo_mean(*repo);
        }

        println!(
            "USAGE_WEIGHT_BENCH {}",
            json!({
                "repository": root.file_name().and_then(|name| name.to_str()).unwrap_or("unknown"),
                "commit": repository_head(&root),
                "nodes": ranking_graph.graph.nodes.len(),
                "edges": ranking_graph.graph.edges.len(),
                "reference_counts": {
                    "calls": counts.calls,
                    "members": counts.members,
                    "types": counts.types,
                    "other": counts.other,
                },
                "timing_ms": { "analyzer": analyzer_ms, "graph": graph_ms, "rank_all_profiles": rank_ms },
                "profiles": profile_results,
                "examples": examples,
            })
        );
    }

    println!(
        "USAGE_WEIGHT_BENCH_AGGREGATE {}",
        json!({
            "macro_average": PROFILES.iter().zip(macro_metrics).map(|(profile, metrics)| {
                json!({ "profile": profile.name, "metrics": metrics.mean() })
            }).collect::<Vec<_>>()
        })
    );
}

fn cochange_labels(
    analyzer: &dyn IAnalyzer,
    ranking_graph: &UsageRankingGraph,
    commit_limit: usize,
) -> HashMap<ProjectFile, HashSet<ProjectFile>> {
    let repo = GitProjectContext::discover(analyzer.project().root()).expect("git repository");
    let changes = repo
        .recent_commit_changes(commit_limit)
        .expect("read recent commit history");
    let eligible: HashSet<_> = ranking_graph.node_indices_by_file.keys().cloned().collect();
    let mut labels: HashMap<ProjectFile, HashSet<ProjectFile>> = HashMap::default();
    let mut canonicalizer = RenameCanonicalizer::default();
    for change in changes.into_iter().rev() {
        canonicalizer.record_renames(&change.renames);
        let mut files = change
            .paths
            .into_iter()
            .filter_map(|path| {
                let path = canonicalizer.canonicalize(&path);
                repo.repo_path_to_project_file(&path)
            })
            .filter(|file| eligible.contains(file))
            .collect::<Vec<_>>();
        files.sort();
        files.dedup();
        if !(2..=20).contains(&files.len()) {
            continue;
        }
        for seed in &files {
            labels
                .entry(seed.clone())
                .or_default()
                .extend(files.iter().filter(|target| *target != seed).cloned());
        }
    }
    labels.retain(|_, targets| !targets.is_empty());
    labels
}

fn stable_sample_key(file: &ProjectFile, seed: u64) -> u64 {
    normalized_rel_path(file)
        .bytes()
        .fold(0xcbf29ce484222325_u64 ^ seed, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
        })
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn repository_head(root: &Path) -> String {
    Repository::open(root)
        .ok()
        .and_then(|repo| repo.head().ok()?.target())
        .map(|oid| oid.to_string())
        .unwrap_or_default()
}
