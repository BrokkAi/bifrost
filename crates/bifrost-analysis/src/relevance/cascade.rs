//! The co-edit cascade: priority tiers over path, history and import evidence.
//!
//! Ported from the offline campaign scorer measured on 2026-08-14 and recorded
//! in `.agents/docs/coedit-retrieval-eval-2026-08-14.md`: 8,346 leave-one-out
//! cases over 18 repositories and 10 languages, recall@10 of 41.0 percent
//! against 24.7 percent for a directory-plus-popularity baseline and 29.1
//! percent for the shipped history-only co-edit ranking.
//!
//! The order encodes precision, strongest evidence first, and nothing in it is
//! trained, so nothing in it can be overfitted to that corpus. A file that is
//! the same subject as a seed in another tree, or shares its stem next door, is
//! the sibling of the change. Where the file-level co-edit leg fires it is
//! specific, so it outranks the broad priors. Directory membership, import
//! adjacency and directory-level affinity are those priors. Bare popularity is
//! not evidence at all, so tier 8 is dropped rather than returned.
//!
//! Every input except the path set is optional. A repository with no usable
//! history contributes no co-edit ranking, no popularity and no directory
//! affinity; the mirror, stem and directory tiers still rank from paths alone.

use crate::analyzer::ProjectFile;
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

/// A stem or mirror key shared by more files than this in one repository
/// describes a layout convention rather than a subject, so matching on it is a
/// popularity draw wearing a precision costume. `mod.rs`, `index.ts`,
/// `__init__.py` and `package-info.java` are the usual examples. The gate
/// measures that per repository instead of keeping a per-language name list:
/// the threshold is a property of the repository, not of a list someone has to
/// maintain. Adding it moved the campaign's recall@10 from 38.5 to 41.0 and
/// repaired its two worst per-repository regressions.
const STEM_GROUP_MAX: usize = 8;
/// Affixes stripped from a basename stem, in this order, at both ends. This is
/// what pairs `Foo.java` with `FooTest.java` and `foo.rb` with `foo_spec.rb`.
const AFFIXES: [&str; 4] = ["test", "tests", "spec", "specs"];
/// Segments that describe where a file sits in a build layout rather than what
/// it is about. Dropping them lets `spec/models/foo_spec.rb` line up with
/// `app/models/foo.rb`, and `src/main/java/...` with `src/test/java/...`.
const LAYOUT_SEGMENTS: [&str; 14] = [
    "src",
    "main",
    "test",
    "tests",
    "spec",
    "specs",
    "__tests__",
    "java",
    "scala",
    "kotlin",
    "resources",
    "app",
    "lib",
    "pkg",
];
/// A commit touching more directories than this is a sweep, not a co-change
/// observation, so it contributes nothing to directory affinity.
const MAX_COMMIT_DIRS: usize = 40;
/// How much of the co-edit ranking counts as its specific head.
const COEDIT_HEAD_DEPTH: usize = 10;

/// Mirror hit, or a stem hit that is also directory- or import-adjacent.
const TIER_MIRROR: u8 = 0;
/// Stem hit anywhere in the repository.
const TIER_STEM: u8 = 1;
/// The head of the file-level co-edit ranking.
const TIER_COEDIT_HEAD: u8 = 2;
const TIER_DIRECTORY_AND_IMPORT: u8 = 3;
const TIER_DIRECTORY: u8 = 4;
const TIER_IMPORT: u8 = 5;
/// The rest of the file-level co-edit ranking.
const TIER_COEDIT_TAIL: u8 = 6;
/// Positive directory-level co-change affinity.
const TIER_DIRECTORY_AFFINITY: u8 = 7;
/// Tier 8 is "everything else, by popularity". Popularity alone says a file
/// changes often, not that it has anything to do with the seeds, so results are
/// cut here rather than padded with it.
const LAST_EVIDENCE_TIER: u8 = TIER_DIRECTORY_AFFINITY;

/// The affix-stripped basename stem, lowercased.
///
/// Everything after the first `.` is an extension chain: `foo.test.ts` and
/// `foo.ts` are one subject. A basename that strips to nothing (a dotfile, or a
/// file named exactly `test`) keeps its whole lowercased basename instead.
pub(super) fn stem_of(path: &Path) -> String {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return String::new();
    };
    let lowercased = file_name.to_ascii_lowercase();
    let mut stem = lowercased.split('.').next().unwrap_or_default();
    for affix in AFFIXES {
        if stem.len() > affix.len() && stem.ends_with(affix) {
            stem = &stem[..stem.len() - affix.len()];
        }
        if stem.len() > affix.len() && stem.starts_with(affix) {
            stem = &stem[affix.len()..];
        }
    }
    let trimmed = stem.trim_matches(['_', '-']);
    if trimmed.is_empty() {
        lowercased
    } else {
        trimmed.to_string()
    }
}

/// The directory path with build-layout segments removed, plus the
/// affix-stripped stem. Two files with the same key are the same subject in
/// different trees, which is the pairing a same-directory ranker structurally
/// cannot see.
pub(super) fn mirror_key(path: &Path) -> (String, String) {
    let mut segments = Vec::new();
    if let Some(parent) = path.parent() {
        for component in parent.components() {
            let Component::Normal(segment) = component else {
                continue;
            };
            let segment = segment.to_string_lossy().to_ascii_lowercase();
            if !segment.is_empty() && !LAYOUT_SEGMENTS.contains(&segment.as_str()) {
                segments.push(segment);
            }
        }
    }
    (segments.join("/"), stem_of(path))
}

/// Keep only the keys that actually single a file out. See `STEM_GROUP_MAX`.
fn discriminative<K, F>(keys: HashSet<K>, key_of: F, universe: &[ProjectFile]) -> HashSet<K>
where
    K: Eq + std::hash::Hash,
    F: Fn(&Path) -> K,
{
    let mut group: HashMap<K, usize> = HashMap::default();
    for file in universe {
        *group.entry(key_of(file.rel_path())).or_insert(0) += 1;
    }
    keys.into_iter()
        .filter(|key| group.get(key).copied().unwrap_or_default() <= STEM_GROUP_MAX)
        .collect()
}

/// Directory-level co-change over the history window.
///
/// File-level co-edit is sparse: a specific pair of files may never have
/// changed together inside the window even when their directories constantly
/// do. Rolling the signal up to directories trades precision for coverage,
/// which is what the file-level leg lacks.
#[derive(Default)]
pub(super) struct DirCoChangeStats {
    ids: HashMap<PathBuf, u32>,
    dirs: Vec<PathBuf>,
    /// Commits in which each directory appears.
    freq: Vec<u32>,
    /// Commits in which each directory pair appears, keyed by ascending ids.
    pairs: HashMap<(u32, u32), u32>,
    /// The sum of `freq`, which is the corpus size the IDF is measured against.
    dir_appearances: u64,
}

impl DirCoChangeStats {
    fn intern(&mut self, dir: &Path) -> u32 {
        if let Some(id) = self.ids.get(dir) {
            return *id;
        }
        let id = u32::try_from(self.dirs.len()).expect("directory ids must fit in a u32");
        self.ids.insert(dir.to_path_buf(), id);
        self.dirs.push(dir.to_path_buf());
        self.freq.push(0);
        id
    }

    /// Record one commit from the directories of the files it changed.
    pub(super) fn record_commit(&mut self, dirs: &BTreeSet<PathBuf>) {
        if dirs.is_empty() || dirs.len() > MAX_COMMIT_DIRS {
            return;
        }
        let ids: Vec<u32> = dirs.iter().map(|dir| self.intern(dir)).collect();
        for id in &ids {
            self.freq[*id as usize] += 1;
            self.dir_appearances += 1;
        }
        for (index, left) in ids.iter().enumerate() {
            for right in &ids[index + 1..] {
                *self
                    .pairs
                    .entry((*left.min(right), *left.max(right)))
                    .or_insert(0) += 1;
            }
        }
    }

    /// `P(dir | seed dir)` times the square root of an IDF over the same
    /// window, mirroring how the file-level leg scores.
    fn affinity(&self, seed_dirs: &HashSet<PathBuf>) -> HashMap<PathBuf, f64> {
        let mut score: HashMap<PathBuf, f64> = HashMap::default();
        let seed_ids: HashSet<u32> = seed_dirs
            .iter()
            .filter_map(|dir| self.ids.get(dir).copied())
            .collect();
        if seed_ids.is_empty() {
            return score;
        }
        let total = self.dir_appearances.max(1) as f64;
        for ((left, right), joint) in &self.pairs {
            for (seed, other) in [(left, right), (right, left)] {
                if !seed_ids.contains(seed) {
                    continue;
                }
                let denominator = f64::from(self.freq[*seed as usize]);
                if denominator <= 0.0 {
                    continue;
                }
                let idf = 1.0 + total / f64::from(self.freq[*other as usize].max(1));
                *score
                    .entry(self.dirs[*other as usize].clone())
                    .or_insert(0.0) += (f64::from(*joint) / denominator) * idf.sqrt();
            }
        }
        score
    }
}

/// Everything the cascade ranks from. Each field independently degrades to
/// empty: see the module comment.
pub(super) struct CascadeEvidence<'a> {
    /// Every file the workspace can rank, seeds included: the rarity gate
    /// measures key frequency over the whole repository.
    pub universe: &'a [ProjectFile],
    pub seeds: &'a HashSet<ProjectFile>,
    /// The file-level co-edit ranking, best first.
    pub coedit: &'a [ProjectFile],
    /// Depth-1 import neighbourhood of the seeds, both directions.
    pub neighbours: &'a HashSet<ProjectFile>,
    /// Commits in the history window that changed each file.
    pub popularity: &'a HashMap<ProjectFile, u32>,
    pub dir_stats: &'a DirCoChangeStats,
}

struct CascadeCandidate {
    tier: u8,
    coedit_rank: usize,
    affinity: f64,
    popularity: u32,
    path: String,
    file: ProjectFile,
}

/// What the seeds are, reduced to the keys a candidate is matched against.
struct SeedProfile {
    dirs: HashSet<PathBuf>,
    stems: HashSet<String>,
    mirrors: HashSet<(String, String)>,
}

impl SeedProfile {
    /// The rarity gate runs over the whole repository, seeds included, so a key
    /// is judged by how many files carry it rather than by how it looks.
    fn of(seeds: &HashSet<ProjectFile>, universe: &[ProjectFile]) -> Self {
        Self {
            dirs: seeds.iter().map(ProjectFile::parent).collect(),
            stems: discriminative(
                seeds.iter().map(|seed| stem_of(seed.rel_path())).collect(),
                stem_of,
                universe,
            ),
            mirrors: discriminative(
                seeds
                    .iter()
                    .map(|seed| mirror_key(seed.rel_path()))
                    .collect(),
                mirror_key,
                universe,
            ),
        }
    }
}

/// Rank `evidence.universe` minus the seeds, best first, cut at `top_k`.
pub(super) fn cascade_ranking(evidence: CascadeEvidence<'_>, top_k: usize) -> Vec<ProjectFile> {
    if top_k == 0 || evidence.seeds.is_empty() {
        return Vec::new();
    }

    let seeds = SeedProfile::of(evidence.seeds, evidence.universe);
    let affinity = evidence.dir_stats.affinity(&seeds.dirs);
    let coedit_rank: HashMap<&ProjectFile, usize> = evidence
        .coedit
        .iter()
        .enumerate()
        .map(|(rank, file)| (file, rank))
        .collect();

    let mut ranked: Vec<CascadeCandidate> = evidence
        .universe
        .iter()
        .filter(|file| !evidence.seeds.contains(*file))
        .filter_map(|file| {
            let directory = file.parent();
            let candidate_affinity = affinity.get(&directory).copied().unwrap_or_default();
            let coedit_rank = coedit_rank.get(file).copied();
            let tier = tier_of(
                file,
                &directory,
                &seeds,
                evidence.neighbours,
                coedit_rank,
                candidate_affinity,
            );
            if tier > LAST_EVIDENCE_TIER {
                return None;
            }
            Some(CascadeCandidate {
                tier,
                coedit_rank: coedit_rank.unwrap_or(usize::MAX),
                affinity: candidate_affinity,
                popularity: evidence.popularity.get(file).copied().unwrap_or_default(),
                path: super::normalized_rel_path(file),
                file: file.clone(),
            })
        })
        .collect();

    ranked.sort_unstable_by(|left, right| {
        left.tier
            .cmp(&right.tier)
            .then_with(|| left.coedit_rank.cmp(&right.coedit_rank))
            .then_with(|| right.affinity.total_cmp(&left.affinity))
            .then_with(|| right.popularity.cmp(&left.popularity))
            .then_with(|| left.path.cmp(&right.path))
    });
    ranked.truncate(top_k);
    ranked.into_iter().map(|candidate| candidate.file).collect()
}

fn tier_of(
    file: &ProjectFile,
    directory: &Path,
    seeds: &SeedProfile,
    neighbours: &HashSet<ProjectFile>,
    coedit_rank: Option<usize>,
    affinity: f64,
) -> u8 {
    let mirror_hit = seeds.mirrors.contains(&mirror_key(file.rel_path()));
    let stem_hit = seeds.stems.contains(&stem_of(file.rel_path()));
    let directory_hit = seeds.dirs.contains(directory);
    let import_hit = neighbours.contains(file);
    if mirror_hit || (stem_hit && (directory_hit || import_hit)) {
        return TIER_MIRROR;
    }
    if stem_hit {
        return TIER_STEM;
    }
    if coedit_rank.is_some_and(|rank| rank < COEDIT_HEAD_DEPTH) {
        return TIER_COEDIT_HEAD;
    }
    if directory_hit && import_hit {
        return TIER_DIRECTORY_AND_IMPORT;
    }
    if directory_hit {
        return TIER_DIRECTORY;
    }
    if import_hit {
        return TIER_IMPORT;
    }
    if coedit_rank.is_some() {
        return TIER_COEDIT_TAIL;
    }
    if affinity > 0.0 {
        return TIER_DIRECTORY_AFFINITY;
    }
    LAST_EVIDENCE_TIER + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn files(root: &Path, paths: &[&str]) -> Vec<ProjectFile> {
        paths
            .iter()
            .map(|path| ProjectFile::new(root.to_path_buf(), *path))
            .collect()
    }

    fn set(files: &[ProjectFile]) -> HashSet<ProjectFile> {
        files.iter().cloned().collect()
    }

    fn paths_of(files: &[ProjectFile]) -> Vec<String> {
        files
            .iter()
            .map(|file| file.rel_path().to_string_lossy().replace('\\', "/"))
            .collect()
    }

    #[test]
    fn stem_strips_extension_chains_and_test_affixes() {
        for (path, expected) in [
            ("Foo.java", "foo"),
            ("src/test/java/FooTest.java", "foo"),
            ("pkg/foo_test.go", "foo"),
            ("spec/models/foo_spec.rb", "foo"),
            ("tests/test_foo.py", "foo"),
            ("src/foo.test.ts", "foo"),
            ("src/mod.rs", "mod"),
            ("src/foo.h", "foo"),
        ] {
            assert_eq!(expected, stem_of(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn stem_keeps_a_basename_that_strips_to_nothing() {
        // A dotfile has nothing before its first `.`, and a file named exactly
        // `test` is all affix. Both keep the whole lowercased basename rather
        // than collapsing every such file onto one empty key.
        assert_eq!(".eslintrc", stem_of(Path::new("web/.eslintrc")));
        assert_eq!("test", stem_of(Path::new("test")));
    }

    #[test]
    fn mirror_key_pairs_the_same_subject_across_trees() {
        assert_eq!(
            mirror_key(Path::new("src/foo/x.rs")),
            mirror_key(Path::new("tests/foo/x.rs"))
        );
        assert_eq!(
            mirror_key(Path::new("app/models/user.rb")),
            mirror_key(Path::new("spec/models/user_spec.rb"))
        );
        assert_eq!(
            mirror_key(Path::new("src/main/java/com/x/Parser.java")),
            mirror_key(Path::new("src/test/java/com/x/ParserTest.java"))
        );
        assert_ne!(
            mirror_key(Path::new("src/foo/x.rs")),
            mirror_key(Path::new("src/bar/x.rs"))
        );
    }

    #[test]
    fn rarity_gate_drops_a_stem_shared_by_too_many_files() {
        let temp = TempDir::new().unwrap();
        let mut paths: Vec<String> = (0..STEM_GROUP_MAX)
            .map(|index| format!("crate{index}/src/mod.rs"))
            .collect();
        let borrowed: Vec<&str> = paths.iter().map(String::as_str).collect();
        let universe = files(temp.path(), &borrowed);
        let keys: HashSet<String> = ["mod".to_string()].into_iter().collect();
        assert!(
            discriminative(keys.clone(), stem_of, &universe).contains("mod"),
            "a stem grouping exactly {STEM_GROUP_MAX} files is still evidence"
        );

        paths.push("one/more/mod.rs".to_string());
        let borrowed: Vec<&str> = paths.iter().map(String::as_str).collect();
        let universe = files(temp.path(), &borrowed);
        assert!(
            discriminative(keys, stem_of, &universe).is_empty(),
            "a stem grouping more than {STEM_GROUP_MAX} files is a layout convention"
        );
    }

    #[test]
    fn tiers_order_mirror_stem_coedit_directory_and_import_evidence() {
        let temp = TempDir::new().unwrap();
        let universe = files(
            temp.path(),
            &[
                "app/models/user.rb",       // seed
                "spec/models/user_spec.rb", // 0: mirror of the seed
                "app/other/user.rb",        // 1: stem hit, different directory
                "app/lib/churn.rb",         // 2: co-edit head
                "app/models/account.rb",    // 4: seed directory
                "app/net/client.rb",        // 5: import neighbour
                "app/lib/rare.rb",          // 6: co-edit tail
                "app/jobs/sweep.rb",        // 7: directory affinity only
                "app/dead/quiet.rb",        // 8: no evidence, cut
            ],
        );
        let seeds = set(&universe[..1]);
        // The tail file has to sit past the head depth, so the co-edit ranking
        // is padded with files this workspace no longer holds. A ranked file
        // outside the universe is simply never a candidate.
        let mut coedit = vec![universe[3].clone()];
        coedit.extend(files(
            temp.path(),
            &[
                "gone/1.rb",
                "gone/2.rb",
                "gone/3.rb",
                "gone/4.rb",
                "gone/5.rb",
            ],
        ));
        coedit.extend(files(
            temp.path(),
            &[
                "gone/6.rb",
                "gone/7.rb",
                "gone/8.rb",
                "gone/9.rb",
                "gone/10.rb",
            ],
        ));
        coedit.push(universe[6].clone());
        let tail_rank = coedit.len() - 1;
        assert!(
            tail_rank >= COEDIT_HEAD_DEPTH,
            "the tail file must rank past the head, got {tail_rank}"
        );
        let neighbours = set(&[universe[5].clone()]);
        let popularity = HashMap::default();
        let mut dir_stats = DirCoChangeStats::default();
        dir_stats.record_commit(
            &[PathBuf::from("app/models"), PathBuf::from("app/jobs")]
                .into_iter()
                .collect(),
        );
        dir_stats.record_commit(
            &[PathBuf::from("app/models"), PathBuf::from("app/jobs")]
                .into_iter()
                .collect(),
        );

        let ranked = cascade_ranking(
            CascadeEvidence {
                universe: &universe,
                seeds: &seeds,
                coedit: &coedit,
                neighbours: &neighbours,
                popularity: &popularity,
                dir_stats: &dir_stats,
            },
            20,
        );

        assert_eq!(
            vec![
                "spec/models/user_spec.rb",
                "app/other/user.rb",
                "app/lib/churn.rb",
                "app/models/account.rb",
                "app/net/client.rb",
                "app/lib/rare.rb",
                "app/jobs/sweep.rb",
            ],
            paths_of(&ranked),
            "tier 8 is cut and every other tier keeps its order"
        );
    }

    #[test]
    fn a_stem_hit_next_door_outranks_a_stem_hit_elsewhere() {
        let temp = TempDir::new().unwrap();
        let universe = files(
            temp.path(),
            &[
                "src/parser/lexer.rs",
                "src/parser/lexer_test.rs",
                "vendor/other/lexer.rs",
            ],
        );
        let seeds = set(&universe[..1]);
        let popularity = HashMap::default();
        let ranked = cascade_ranking(
            CascadeEvidence {
                universe: &universe,
                seeds: &seeds,
                coedit: &[],
                neighbours: &HashSet::default(),
                popularity: &popularity,
                dir_stats: &DirCoChangeStats::default(),
            },
            20,
        );

        assert_eq!(
            vec!["src/parser/lexer_test.rs", "vendor/other/lexer.rs"],
            paths_of(&ranked)
        );
    }

    #[test]
    fn paths_alone_rank_without_history_or_imports() {
        let temp = TempDir::new().unwrap();
        let universe = files(
            temp.path(),
            &["src/foo/x.rs", "tests/foo/x.rs", "src/foo/y.rs"],
        );
        let seeds = set(&universe[..1]);
        let popularity = HashMap::default();
        let ranked = cascade_ranking(
            CascadeEvidence {
                universe: &universe,
                seeds: &seeds,
                coedit: &[],
                neighbours: &HashSet::default(),
                popularity: &popularity,
                dir_stats: &DirCoChangeStats::default(),
            },
            20,
        );

        assert_eq!(vec!["tests/foo/x.rs", "src/foo/y.rs"], paths_of(&ranked));
    }

    #[test]
    fn popularity_orders_a_tier_but_never_earns_a_result() {
        let temp = TempDir::new().unwrap();
        let universe = files(
            temp.path(),
            &[
                "src/a/seed.rs",
                "src/a/quiet.rs",
                "src/a/busy.rs",
                "src/z/unrelated.rs",
            ],
        );
        let seeds = set(&universe[..1]);
        let popularity: HashMap<ProjectFile, u32> = [
            (universe[1].clone(), 1),
            (universe[2].clone(), 40),
            (universe[3].clone(), 900),
        ]
        .into_iter()
        .collect();

        let ranked = cascade_ranking(
            CascadeEvidence {
                universe: &universe,
                seeds: &seeds,
                coedit: &[],
                neighbours: &HashSet::default(),
                popularity: &popularity,
                dir_stats: &DirCoChangeStats::default(),
            },
            20,
        );

        assert_eq!(vec!["src/a/busy.rs", "src/a/quiet.rs"], paths_of(&ranked));
    }

    #[test]
    fn no_seeds_rank_nothing() {
        let temp = TempDir::new().unwrap();
        let universe = files(temp.path(), &["src/a.rs", "src/b.rs"]);
        let ranked = cascade_ranking(
            CascadeEvidence {
                universe: &universe,
                seeds: &HashSet::default(),
                coedit: &[],
                neighbours: &HashSet::default(),
                popularity: &HashMap::default(),
                dir_stats: &DirCoChangeStats::default(),
            },
            20,
        );
        assert!(ranked.is_empty());
    }

    #[test]
    fn directory_affinity_scores_partners_of_the_seed_directory() {
        let mut stats = DirCoChangeStats::default();
        for _ in 0..3 {
            stats.record_commit(
                &[PathBuf::from("app/models"), PathBuf::from("app/views")]
                    .into_iter()
                    .collect(),
            );
        }
        stats.record_commit(&[PathBuf::from("docs")].into_iter().collect());

        let seed_dirs: HashSet<PathBuf> = [PathBuf::from("app/models")].into_iter().collect();
        let affinity = stats.affinity(&seed_dirs);
        assert!(affinity.get(Path::new("app/views")).copied().unwrap() > 0.0);
        assert_eq!(None, affinity.get(Path::new("docs")).copied());
    }

    #[test]
    fn a_sweeping_commit_contributes_no_directory_affinity() {
        let mut stats = DirCoChangeStats::default();
        let sweep: BTreeSet<PathBuf> = (0..=MAX_COMMIT_DIRS)
            .map(|index| PathBuf::from(format!("dir{index}")))
            .collect();
        stats.record_commit(&sweep);
        let seed_dirs: HashSet<PathBuf> = [PathBuf::from("dir0")].into_iter().collect();
        assert!(stats.affinity(&seed_dirs).is_empty());
    }
}
