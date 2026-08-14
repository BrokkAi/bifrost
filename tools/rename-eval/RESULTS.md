# bifrost move/rename matching on the RefactoringMiner oracle

Real rename/move data: TP-validated `Rename Method`, `Move Method`, and
`Move And Rename Method` labels from RefactoringMiner's oracle, with
method bodies extracted from the cached before/after source trees.
Dataset built by `extract_pairs.py`; this file by `eval.py`.

## Dataset

- commits: 162, positives: 641 ({'Move And Rename Method': 79, 'Move Method': 225, 'Rename Method': 337})
- positives representable in the disappeared/appeared field: 585
- negative pairs (cross products, filtered): 331729
- drop reasons: {'before_ambiguous_overload': 29, 'commit_no_positive_extracted': 18, 'duplicate_label': 19, 'before_abstract_no_body': 38, 'class_file_not_found': 22, 'before_method_not_found': 8, 'after_ambiguous_overload': 40, 'desc_parse_fail': 9, 'after_abstract_no_body': 2, 'commit_dirs_missing': 1, 'sig_parse_fail': 1}
  (`*_abstract_no_body` = the labeled method is an abstract/interface declaration with no body -- unpairable by body similarity by design; `desc_parse_fail` = anonymous-class FQNs or oracle-truncated descriptions.)

- pairwise eval uses 639 positives / 329845 negatives after the <2-non-blank-line body filter (skipped 2 pos, 1884 neg).
- caveat: one commit (infinispan-8f446b6d) contributes ~47% of all negative pairs; per-type AUC shares the one negative pool. See the robustness table below.

Metric notes: `idf_background` weights tokens by IDF over ALL extracted method bodies (needs a shipped/background table); `idf_diff_local` computes df only over the same commit's extracted methods (median pool size is small) -- deployable at runtime with zero shipped data; `bigram_blend` = 0.6*bag + 0.4*bigram-set Jaccard.

## 1. Pairwise AUC (positives vs field negatives)

| metric | overall | Rename | Move | Move+Rename |
|---|---|---|---|---|
| bag (shipped) | 0.9801 | 0.9661 | 0.9956 | 0.9954 |
| idf_background | 0.9929 | 0.9874 | 0.9990 | 0.9987 |
| idf_diff_local | 0.9948 | 0.9909 | 0.9992 | 0.9990 |
| bigram_blend | 0.9849 | 0.9740 | 0.9971 | 0.9965 |
| idf+bigram | 0.9933 | 0.9884 | 0.9988 | 0.9986 |

### 1b. Robustness: excluding infinispan-8f446b6d negatives

Same positives, negatives reduced 329845 -> 173556.

| metric | overall | Rename | Move | Move+Rename |
|---|---|---|---|---|
| bag (shipped) | 0.9796 | 0.9655 | 0.9952 | 0.9945 |
| idf_background | 0.9906 | 0.9837 | 0.9982 | 0.9977 |
| idf_diff_local | 0.9934 | 0.9886 | 0.9987 | 0.9982 |
| bigram_blend | 0.9840 | 0.9727 | 0.9966 | 0.9956 |
| idf+bigram | 0.9915 | 0.9856 | 0.9981 | 0.9975 |

## 2. Whole-commit simulation (greedy 1:1, per metric)

Oracle positives in the field: 584 (of which 2 have a <2-line body on one side and can never be paired by the shipped rule). Predicted pairs that are unlabeled same-name matches or overlap an Extract/Inline/Pull-Up-family label are counted as `ignored`, not FP. `FN below-thr` = the true pair scores under the threshold; `FN outcompeted` = it scores at/above the threshold but greedy 1:1 gave an endpoint to a higher-or-tied competitor.

### bag (shipped)

| threshold | TP | FP | FN | FN below-thr | FN outcompeted | ignored | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| 0.50 | 498 | 272 | 86 | 44 | 42 | 709 | 0.647 | 0.853 | 0.736 |
| 0.55 | 485 | 203 | 99 | 62 | 37 | 672 | 0.705 | 0.830 | 0.763 |
| 0.60 | 466 | 142 | 118 | 85 | 33 | 635 | 0.766 | 0.798 | 0.782 |
| 0.65 | 447 | 105 | 137 | 113 | 24 | 596 | 0.810 | 0.765 | 0.787 |
| 0.70 | 416 | 65 | 168 | 146 | 22 | 558 | 0.865 | 0.712 | 0.781 |
| 0.75 | 402 | 53 | 182 | 162 | 20 | 534 | 0.884 | 0.688 | 0.774 |
| 0.80 | 381 | 42 | 203 | 186 | 17 | 472 | 0.901 | 0.652 | 0.757 |
| 0.85 | 341 | 27 | 243 | 229 | 14 | 442 | 0.927 | 0.584 | 0.716 |
| 0.90 | 284 | 8 | 300 | 292 | 8 | 413 | 0.973 | 0.486 | 0.648 |

### idf_background

| threshold | TP | FP | FN | FN below-thr | FN outcompeted | ignored | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| 0.50 | 448 | 30 | 136 | 116 | 20 | 573 | 0.937 | 0.767 | 0.844 |
| 0.55 | 413 | 27 | 171 | 155 | 16 | 544 | 0.939 | 0.707 | 0.807 |
| 0.60 | 388 | 19 | 196 | 182 | 14 | 522 | 0.953 | 0.664 | 0.783 |
| 0.65 | 366 | 10 | 218 | 208 | 10 | 486 | 0.973 | 0.627 | 0.762 |
| 0.70 | 342 | 6 | 242 | 233 | 9 | 456 | 0.983 | 0.586 | 0.734 |
| 0.75 | 320 | 6 | 264 | 256 | 8 | 427 | 0.982 | 0.548 | 0.703 |
| 0.80 | 294 | 4 | 290 | 283 | 7 | 405 | 0.987 | 0.503 | 0.667 |
| 0.85 | 268 | 4 | 316 | 311 | 5 | 388 | 0.985 | 0.459 | 0.626 |
| 0.90 | 237 | 4 | 347 | 343 | 4 | 377 | 0.983 | 0.406 | 0.575 |

### idf_diff_local

| threshold | TP | FP | FN | FN below-thr | FN outcompeted | ignored | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| 0.50 | 438 | 36 | 146 | 122 | 24 | 573 | 0.924 | 0.750 | 0.828 |
| 0.55 | 424 | 29 | 160 | 141 | 19 | 546 | 0.936 | 0.726 | 0.818 |
| 0.60 | 397 | 19 | 187 | 172 | 15 | 528 | 0.954 | 0.680 | 0.794 |
| 0.65 | 372 | 14 | 212 | 198 | 14 | 496 | 0.964 | 0.637 | 0.767 |
| 0.70 | 347 | 10 | 237 | 224 | 13 | 467 | 0.972 | 0.594 | 0.738 |
| 0.75 | 325 | 8 | 259 | 249 | 10 | 435 | 0.976 | 0.557 | 0.709 |
| 0.80 | 305 | 6 | 279 | 271 | 8 | 410 | 0.981 | 0.522 | 0.682 |
| 0.85 | 282 | 5 | 302 | 296 | 6 | 396 | 0.983 | 0.483 | 0.648 |
| 0.90 | 240 | 3 | 344 | 340 | 4 | 380 | 0.988 | 0.411 | 0.580 |

### bigram_blend

| threshold | TP | FP | FN | FN below-thr | FN outcompeted | ignored | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| 0.50 | 490 | 146 | 94 | 61 | 33 | 653 | 0.770 | 0.839 | 0.803 |
| 0.55 | 473 | 109 | 111 | 83 | 28 | 634 | 0.813 | 0.810 | 0.811 |
| 0.60 | 441 | 71 | 143 | 117 | 26 | 604 | 0.861 | 0.755 | 0.805 |
| 0.65 | 420 | 54 | 164 | 139 | 25 | 565 | 0.886 | 0.719 | 0.794 |
| 0.70 | 407 | 43 | 177 | 155 | 22 | 529 | 0.904 | 0.697 | 0.787 |
| 0.75 | 375 | 34 | 209 | 193 | 16 | 512 | 0.917 | 0.642 | 0.755 |
| 0.80 | 352 | 27 | 232 | 218 | 14 | 447 | 0.929 | 0.603 | 0.731 |
| 0.85 | 297 | 9 | 287 | 276 | 11 | 410 | 0.971 | 0.509 | 0.667 |
| 0.90 | 252 | 3 | 332 | 327 | 5 | 379 | 0.988 | 0.432 | 0.601 |

### Operating points (fine sweep 0.25-0.98 step 0.01)

Best-F1 point, and the precision-matched point = lowest threshold whose precision reaches 0.90 (each metric has its own score scale, so thresholds are not comparable across rows -- recall at matched precision is).

| metric | bestF1 thr | P | R | F1 | first P>=0.90 thr | P | R |
|---|---|---|---|---|---|---|---|
| bag (shipped) | 0.67 | 0.845 | 0.740 | 0.789 | 0.79 | 0.902 | 0.659 |
| idf_background | 0.35 | 0.890 | 0.848 | 0.868 | 0.38 | 0.902 | 0.836 |
| idf_diff_local | 0.36 | 0.885 | 0.832 | 0.858 | 0.41 | 0.904 | 0.807 |
| bigram_blend | 0.54 | 0.810 | 0.820 | 0.815 | 0.69 | 0.903 | 0.704 |

## 3. Symmetric margin-gate ablation

Accept (pre,post) only if score - score(runner-up) >= eps on BOTH endpoints; runner-ups computed statically among threshold-passing pairs, then greedy 1:1 over the survivors. `quads` = baseline outcompeted-FNs whose endpoint was consumed by a false positive (the sibling-steal cases). `resolved` = FP(s) gone AND true pair recovered; `fp-gone-tp-lost` = FP(s) gone but the true pair gated too (near-tie, both suppressed); `unresolved` = an FP survives.

### bag (shipped) @ 0.70 (6 sibling-steal quads at baseline)

| eps | TP | FP | FN | precision | recall | F1 | resolved | fp-gone-tp-lost | unresolved | TP lost | TP gained | FP removed |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 (base) | 416 | 65 | 168 | 0.865 | 0.712 | 0.781 | - | - | - | 0 | 0 | 0 |
| 0.02 | 378 | 13 | 206 | 0.967 | 0.647 | 0.775 | 0 | 6 | 0 | 38 | 0 | 52 |
| 0.05 | 354 | 8 | 230 | 0.978 | 0.606 | 0.748 | 0 | 6 | 0 | 62 | 0 | 57 |
| 0.10 | 329 | 8 | 255 | 0.976 | 0.563 | 0.714 | 0 | 6 | 0 | 87 | 0 | 57 |

### idf_background @ 0.35 (7 sibling-steal quads at baseline)

| eps | TP | FP | FN | precision | recall | F1 | resolved | fp-gone-tp-lost | unresolved | TP lost | TP gained | FP removed |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 (base) | 495 | 61 | 89 | 0.890 | 0.848 | 0.868 | - | - | - | 0 | 0 | 0 |
| 0.02 | 447 | 31 | 137 | 0.935 | 0.765 | 0.842 | 0 | 6 | 1 | 48 | 0 | 30 |
| 0.05 | 431 | 29 | 153 | 0.937 | 0.738 | 0.826 | 0 | 6 | 1 | 64 | 0 | 32 |
| 0.10 | 405 | 28 | 179 | 0.935 | 0.693 | 0.796 | 0 | 6 | 1 | 90 | 0 | 33 |

## 4. Small-pool behavior (idf_diff_local)

Production diffs skew to far smaller local df pools than the oracle commits, and with few methods the idf weights compress toward uniform, drifting scores back toward bag-Jaccard scale while the threshold assumes IDF scale. Stratification by local pool size (number of method bodies in the commit's df pool):

| pool size | commits | field positives | neg pairs | neg p50 | neg p90 | neg p99 | neg max | pos p10 | pos p50 |
|---|---|---|---|---|---|---|---|---|---|
| <10 | 45 | 48 | 128 | 0.046 | 0.171 | 0.690 | 0.714 | 0.345 | 0.793 |
| 10-29 | 49 | 103 | 1635 | 0.037 | 0.192 | 0.873 | 1.000 | 0.254 | 0.886 |
| 30-99 | 35 | 173 | 12324 | 0.024 | 0.095 | 0.413 | 1.000 | 0.428 | 0.900 |
| >=100 | 33 | 260 | 315758 | 0.016 | 0.061 | 0.183 | 1.000 | 0.259 | 0.744 |

### Per-bucket outcomes, idf_diff_local @ 0.40

| pool size | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|
| <10 | 38 | 0 | 10 | 1.000 | 0.792 |
| 10-29 | 83 | 7 | 20 | 0.922 | 0.806 |
| 30-99 | 158 | 6 | 15 | 0.963 | 0.913 |
| >=100 | 197 | 42 | 63 | 0.824 | 0.758 |

### Per-bucket outcomes, idf_diff_local @ 0.45

| pool size | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|
| <10 | 38 | 0 | 10 | 1.000 | 0.792 |
| 10-29 | 82 | 5 | 21 | 0.943 | 0.796 |
| 30-99 | 148 | 4 | 25 | 0.974 | 0.855 |
| >=100 | 189 | 33 | 71 | 0.851 | 0.727 |

### Rename-free FP exposure: negatives crossing the threshold

Oracle commits all contain a true rename, so the simulation understates FP risk on production diffs that contain none (the true partner is not there to win the endpoint). The direct stat is how many negative pairs cross each config's threshold:

| pool size | negs | idf>=0.40 | idf>=0.45 | bag>=0.70 (shipped) |
|---|---|---|---|---|
| <10 | 128 | 5 (3.91%) | 5 (3.91%) | 6 (4.69%) |
| 10-29 | 1635 | 83 (5.08%) | 65 (3.98%) | 93 (5.69%) |
| 30-99 | 12324 | 134 (1.09%) | 95 (0.77%) | 122 (0.99%) |
| >=100 | 315758 | 611 (0.19%) | 496 (0.16%) | 1294 (0.41%) |
| ALL | 329845 | 833 (0.25%) | 661 (0.20%) | 1515 (0.46%) |

### Reading the small-pool data

- The inflation concern is real only at the extreme tail (neg p90 is ~3x higher for pool<30 than pool>=100) but it does NOT convert into decisions: pool<10 has ZERO false positives at 0.40 (precision 1.000), and the worst stratum is the LARGEST bucket (>=100: many sibling candidates), not the smallest.
- The elevated small-pool negative tail is a property of small fields (few, semantically related changed methods), not an IDF artifact: bag-Jaccard@0.70 shows the same pattern and crosses its threshold MORE often than idf@0.40 in both small buckets (6 vs 5 in <10, 93 vs 83 in 10-29) and ~2x more overall (1515 vs 833). On rename-free diffs the proposed config is strictly safer than the shipped one.
- Every guard tested (bag@0.70 fallback for small pools, raised small-pool thresholds) is neutral or worse than pure idf_diff_local@0.40, because there are no small-pool FPs to remove -- guards only delete small-pool TPs. No guard is warranted.

## 5. Failure examples (bag @ 0.70)

### False positives (predicted pair, no oracle label)

| commit | disappeared | appeared | score |
|---|---|---|---|
| jfinal-881baed894540031bd55e402933bcad28b74ca88 | I18N | I18n | 1.000 |
| neo4j-001de307492df8f84ad15f6aaa0bd1e748d4ce27 | forceEverything | checkPointHappened | 1.000 |
| neo4j-8d9bedbf96b14beb027ebc1338bc6d5750e1feb5 | shouldNotCreateUniquenessConstraintThatAlreadyExists | shouldNotCreateMandatoryPropertyConstraintThatAlreadyExists | 0.951 |
| neo4j-8d9bedbf96b14beb027ebc1338bc6d5750e1feb5 | shouldNotStoreUniquenessConstraintThatIsRemovedInTheSameTransaction | shouldNotStoreMandatoryPropertyConstraintThatIsRemovedInTheSameTransaction | 0.932 |
| drools-1bf2875e9d73e2d1cd3b58200d5300485f890ff5 | run | execute | 0.917 |
| neo4j-8d9bedbf96b14beb027ebc1338bc6d5750e1feb5 | shouldNotRemoveConstraintThatGetsReAdded | shouldNotRemoveMandatoryPropertyConstraintThatGetsReAdded | 0.913 |
| neo4j-8d9bedbf96b14beb027ebc1338bc6d5750e1feb5 | shouldNotPersistUniquenessConstraintsCreatedInAbortedTransaction | shouldNotPersistMandatoryPropertyConstraintsCreatedInAbortedTransaction | 0.906 |
| checkstyle-0a1a4c6e94c9b3b73b21b323f14ae7b7337b1b44 | isInElseBlock | isInSpecificCodeBlock | 0.905 |
| infinispan-35b6c869546a7968b6fd2f640add6eea87e03c22 | comparePrimaryPredicateExpr | comparePrimaryPredicates | 0.898 |
| infinispan-8f446b6ddf540e1b1fefca34dd10f45ba7256095 | isCancelled | isShutdown | 0.882 |

### False negatives (oracle pair not predicted; score = true pair's score)

| commit | before | after | true-pair score |
|---|---|---|---|
| cascading-f9d3171f5020da5c359cdda28ef05172e858c464 | logInfo | logInfo | 1.000 |
| cascading-f9d3171f5020da5c359cdda28ef05172e858c464 | logWarn | logWarn | 1.000 |
| checkstyle-cdf3e56bacd3895262af8a1df9ca5c81f4071970 | Utils | TokenUtils | 1.000 |
| undertow-d5b2bb8cd1393f1c5a5bb623e3d8906cd57e53c4 | coerceToType | coerceToType | 0.996 |
| neo4j-8d9bedbf96b14beb027ebc1338bc6d5750e1feb5 | shouldNotCreateUniquenessConstraintThatAlreadyExists | shouldNotCreateUniquePropertyConstraintThatAlreadyExists | 0.951 |
| neo4j-8d9bedbf96b14beb027ebc1338bc6d5750e1feb5 | shouldNotStoreUniquenessConstraintThatIsRemovedInTheSameTransaction | shouldNotStoreUniquePropertyConstraintThatIsRemovedInTheSameTransaction | 0.932 |
| neo4j-8d9bedbf96b14beb027ebc1338bc6d5750e1feb5 | shouldNotRemoveConstraintThatGetsReAdded | shouldNotRemoveUniquePropertyConstraintThatGetsReAdded | 0.913 |
| neo4j-8d9bedbf96b14beb027ebc1338bc6d5750e1feb5 | shouldNotPersistUniquenessConstraintsCreatedInAbortedTransaction | shouldNotPersistUniquePropertyConstraintsCreatedInAbortedTransaction | 0.906 |
| buck-6ed4cf9e83fe24fc6ab6fc9ebede016c777c9725 | sanitizeWithoutAnyMatchesWithoutExpandPaths | sanitizeWithoutAnyMatches | 0.883 |
| checkstyle-cdf3e56bacd3895262af8a1df9ca5c81f4071970 | testIsProperUtilsClass | testIsProperUtilsClass | 0.882 |

### Reading the failures

- The dominant decision-level failure is NEAR-DUPLICATE SIBLINGS: when a method is copy-renamed into several variants (test-class splits like neo4j-8d9bedbf's `Uniqueness...` -> `UniqueProperty...` + `MandatoryProperty...`), the wrong sibling can outscore or tie the true partner, producing a matched FP+FN pair. The margin gate in section 3 targets exactly these.
- Oracle 1:many labels (class splits: one constructor labeled as moving to two new classes) are unsatisfiable under the shipped 1:1 greedy rule; one target is always an FN.
- A few top-score FPs are genuine relocations the oracle simply does not label (e.g. jfinal `I18N` -> `I18n` constructor during a class restructure), so measured precision is a floor.

## Bottom line

Ship `idf_diff_local` (commit-local IDF-weighted bag Jaccard; df over just the commit's extracted methods, so zero shipped table) at threshold ~0.40, with NO margin gate. At thr 0.41 it is precision-matched to the 0.90 bar with P 0.904 / R 0.807, vs the shipped bag@0.70's P 0.865 / R 0.712 -- about +9.5pt recall AND +4pt precision simultaneously; best-F1 is 0.858 @ 0.36 vs bag's 0.789 @ 0.67. The background-IDF table buys only ~3pt more recall at matched precision (R 0.836 @ 0.38) -- not worth shipping and maintaining a global df table. Pairwise AUC agrees (idf_diff_local 0.9948, first) and the ranking is unchanged after dropping infinispan-8f446b6d's 47% share of negatives (0.9934, still first). Do NOT adopt the margin gate as a default: it lowers F1 at every tested eps, it never actually rescues a stolen sibling (resolved = 0 everywhere -- the true pair is always within eps of the stealing FP, so both get suppressed and a matched FP+FN merely becomes an FN), and on the IDF config the pairs it removes are mostly RIGHT (48 TP lost vs 30 FP removed at eps=0.02). Its one legitimate niche is precision-max operation: bag@0.70 + eps=0.02 reaches P 0.967 / R 0.647, a better precision/recall point than any pure threshold. The small-pool concern (section 4) is resolved in favor of the pure config: tiny df pools inflate the negative tail slightly but produce ZERO false positives at 0.40, cross the threshold less often than shipped bag@0.70 does, and every guard tested only costs recall -- ship pure idf_diff_local@0.40 with no pool-size fallback. Caveat: thresholds are tuned on this same oracle; treat 0.40 as a starting point, not a certified constant.
