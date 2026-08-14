#!/usr/bin/env python3
"""Evaluate bifrost's fuzzy move/rename matcher (and candidate variants) on the
real RefactoringMiner-oracle dataset produced by extract_pairs.py.

1. PAIRWISE: AUC of oracle-positive pairs vs field-negative pairs for each
   candidate metric, overall and per refactoring type; plus a robustness
   recomputation excluding infinispan-8f446b6d's negatives (~47% of the pool).
2. WHOLE-COMMIT SIMULATION: per commit, replicate the shipped algorithm --
   score every disappeared x appeared pair, keep scores >= threshold, greedy
   best-first 1:1 (ties broken deterministically) -- for four metrics:
   bag (shipped), idf_background, idf_diff_local, bigram_blend.
3. MARGIN-GATE ABLATION: symmetric runner-up margin gate (accept a pair only
   if it beats the runner-up on BOTH endpoints by eps), with accounting of the
   sibling-steal quadruples (outcompeted FN + linked FP) it resolves.

Metric replicas match crates/bifrost-analysis/src/diff_analysis.rs:
  - own name blanked to NUL on whole-identifier boundaries;
  - tokens = [A-Za-z0-9_\\0]+ runs plus single non-whitespace punctuation;
  - bodies with <2 non-blank lines never participate (token_sig == None);
  - multiset (bag) Jaccard; threshold 0.70 shipped.

idf_background: weighted Jaccard, df over ALL extracted method bodies.
idf_diff_local: weighted Jaccard, df over ONLY the same commit's extracted
  methods (disappeared + appeared + positive sides not present in the field)
  -- computable at runtime with zero shipped table.

Writes RESULTS.md next to this script.
"""
import json
import math
import os
import re
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
DS = os.path.join(HERE, "dataset.json")
OUT = os.path.join(HERE, "RESULTS.md")

SHIPPED_THRESHOLD = 0.70
SWEEP = [round(0.50 + 0.05 * i, 2) for i in range(9)]   # coarse: 0.50 .. 0.90
FINE = [round(0.25 + 0.01 * i, 2) for i in range(74)]   # fine:   0.25 .. 0.98
FLOOR = 0.25
EPSILONS = [0.02, 0.05, 0.10]
BIG_NEG_COMMIT = "infinispan-8f446b6d"
SIM_METRICS = ["bag (shipped)", "idf_background", "idf_diff_local",
               "bigram_blend"]


# --- shipped-metric replicas (see diff_analysis.rs) ---

def blank(body, name):
    return re.sub(rf"\b{re.escape(name)}\b", "\0", body)


def toks(body, name):
    return re.findall(r"[A-Za-z0-9_\0]+|[^\s\w]", blank(body, name))


def substantial(body):
    return sum(1 for l in body.split("\n") if l.strip()) >= 2


class Sig:
    """Precomputed views of one method body's token signature."""
    __slots__ = ("bag", "tot", "bigrams", "wsum", "wsum_local", "ok")

    def __init__(self, body, name):
        self.ok = substantial(body)
        t = toks(body, name)
        self.bag = dict(Counter(t))
        self.tot = len(t)
        self.bigrams = set(zip(t, t[1:]))
        self.wsum = 0.0        # filled once background IDF is known
        self.wsum_local = 0.0  # filled once the commit-local IDF is known

    def weigh(self, idf, default, attr):
        setattr(self, attr,
                sum(idf.get(t, default) * c for t, c in self.bag.items()))


def inter_count(a, b):
    if len(b.bag) < len(a.bag):
        a, b = b, a
    return sum(min(c, b.bag.get(t, 0)) for t, c in a.bag.items())


def jac(a, b):
    i = inter_count(a, b)
    u = a.tot + b.tot - i
    return i / u if u else 0.0


def bigram_jac(a, b):
    if not a.bigrams or not b.bigrams:
        return 0.0
    i = len(a.bigrams & b.bigrams)
    return i / (len(a.bigrams) + len(b.bigrams) - i)


IDF_DEFAULT = math.log(2)


def make_idf(sigs):
    n = len(sigs)
    df = Counter()
    for s in sigs:
        for t in s.bag:
            df[t] += 1
    return {t: math.log((n + 1) / (c + 0.5)) for t, c in df.items()}


def wjac(a, b, idf, attr):
    small, big = (a, b) if len(a.bag) <= len(b.bag) else (b, a)
    wi = sum(idf.get(t, IDF_DEFAULT) * min(c, big.bag.get(t, 0))
             for t, c in small.bag.items())
    wu = getattr(a, attr) + getattr(b, attr) - wi
    return wi / wu if wu else 0.0


def blend(a, b):
    return 0.6 * jac(a, b) + 0.4 * bigram_jac(a, b)


def metric_fns(idf, lidf):
    """Pairwise metric set for one commit (lidf = its local IDF)."""
    return {
        "bag (shipped)": jac,
        "idf_background": lambda a, b: wjac(a, b, idf, "wsum"),
        "idf_diff_local": lambda a, b: wjac(a, b, lidf, "wsum_local"),
        "bigram_blend": blend,
        "idf+bigram": lambda a, b: (0.6 * wjac(a, b, idf, "wsum")
                                    + 0.4 * bigram_jac(a, b)),
    }


AUC_METRICS = ["bag (shipped)", "idf_background", "idf_diff_local",
               "bigram_blend", "idf+bigram"]


def auc(pos, neg):
    """Mann-Whitney AUC via average ranks; O(n log n)."""
    if not pos or not neg:
        return float("nan")
    combined = sorted((v, 1) for v in pos)
    combined += sorted((v, 0) for v in neg)
    combined.sort(key=lambda t: t[0])
    ranksum = 0.0
    i, n = 0, len(combined)
    rank = 1
    while i < n:
        j = i
        while j < n and combined[j][0] == combined[i][0]:
            j += 1
        avg = (rank + rank + (j - i) - 1) / 2.0
        for k in range(i, j):
            if combined[k][1]:
                ranksum += avg
        rank += j - i
        i = j
    u = ranksum - len(pos) * (len(pos) + 1) / 2.0
    return u / (len(pos) * len(neg))


def main():
    t0 = time.time()
    ds = json.load(open(DS))
    commits = ds["commits"]

    # ---- tokenize everything once ----
    all_sigs = []
    for co in commits:
        commit_sigs = []       # sigs weighed with this commit's local IDF
        local_pool = []        # sigs contributing to the local df (no dupes)
        for e in co["disappeared"] + co["appeared"]:
            e["sig"] = Sig(e["body"], e["name"])
            all_sigs.append(e["sig"])
            commit_sigs.append(e["sig"])
            local_pool.append(e["sig"])
        for p in co["positives"]:
            for side, idx in (("before", "d_idx"), ("after", "a_idx")):
                p[side]["sig"] = Sig(p[side]["body"], p[side]["name"])
                all_sigs.append(p[side]["sig"])
                commit_sigs.append(p[side]["sig"])
                if p.get(idx) is None:      # not already in the field
                    local_pool.append(p[side]["sig"])
        lidf = make_idf(local_pool)
        co["_lidf"] = lidf
        co["_lpool_n"] = len(local_pool)
        for s in commit_sigs:
            s.weigh(lidf, IDF_DEFAULT, "wsum_local")
    idf = make_idf(all_sigs)
    for s in all_sigs:
        s.weigh(idf, IDF_DEFAULT, "wsum")

    # ---- 1. pairwise AUC (negatives tagged by commit for robustness) ----
    pos_scores = defaultdict(lambda: defaultdict(list))  # metric -> type -> [s]
    neg_scores = defaultdict(list)                       # metric -> [(cid, s)]
    n_pos_skipped = n_neg_skipped = 0
    for co in commits:
        fns = metric_fns(idf, co["_lidf"])
        cid = co["commit"]
        for p in co["positives"]:
            a, b = p["before"]["sig"], p["after"]["sig"]
            if not (a.ok and b.ok):
                n_pos_skipped += 1
                continue
            for mname, fn in fns.items():
                pos_scores[mname][p["type"]].append(fn(a, b))
        for di, ai in co["neg_pairs"]:
            a, b = co["disappeared"][di]["sig"], co["appeared"][ai]["sig"]
            if not (a.ok and b.ok):
                n_neg_skipped += 1
                continue
            for mname, fn in fns.items():
                neg_scores[mname].append((cid, fn(a, b)))

    types = ["Rename Method", "Move Method", "Move And Rename Method"]

    def auc_table(neg_filter):
        rows = []
        for mname in AUC_METRICS:
            negs = [s for cid, s in neg_scores[mname] if neg_filter(cid)]
            allpos = [s for t in types for s in pos_scores[mname][t]]
            row = [mname, auc(allpos, negs)]
            row += [auc(pos_scores[mname][t], negs) for t in types]
            rows.append(row)
        return rows

    auc_rows = auc_table(lambda cid: True)
    auc_rows_noinf = auc_table(lambda cid: not cid.startswith(BIG_NEG_COMMIT))
    n_pos_used = sum(len(pos_scores["bag (shipped)"][t]) for t in types)
    n_neg_used = len(neg_scores["bag (shipped)"])
    n_neg_noinf = sum(1 for cid, _ in neg_scores["bag (shipped)"]
                      if not cid.startswith(BIG_NEG_COMMIT))

    # ---- 2. whole-commit simulation, all SIM_METRICS ----
    # Pre-score every commit's full field once per metric (floor 0.40, sound
    # cheap upper bounds skip most pairs); sweep thresholds over the lists.
    commit_meta = []   # (co, pos_idx, shared, movelike)
    sim_scores = {m: [] for m in SIM_METRICS}  # metric -> [per-commit list]
    denom = 0
    denom_insubstantial = 0
    for co in commits:
        D, A = co["disappeared"], co["appeared"]
        pos_idx = set()
        for p in co["positives"]:
            if p.get("d_idx") is not None and p.get("a_idx") is not None:
                pos_idx.add((p["d_idx"], p["a_idx"]))
                if not (D[p["d_idx"]]["sig"].ok and A[p["a_idx"]]["sig"].ok):
                    denom_insubstantial += 1
        denom += len(pos_idx)
        shared = set(co["shared_body_names"])
        movelike = {tuple(x) for x in co["movelike_name_pairs"]}
        commit_meta.append((co, pos_idx, shared, movelike))
        lidf = co["_lidf"]
        per_metric = {m: [] for m in SIM_METRICS}
        for di, d in enumerate(D):
            sd = d["sig"]
            if not sd.ok:
                continue
            for ai, a in enumerate(A):
                sa = a["sig"]
                if not sa.ok:
                    continue
                # cheap sound upper bounds (inter <= min mass, union >= max)
                tmin, tmax = min(sd.tot, sa.tot), max(sd.tot, sa.tot)
                ub_bag = tmin / tmax if tmax else 0.0
                nb1, nb2 = len(sd.bigrams), len(sa.bigrams)
                ub_bg = (min(nb1, nb2) / max(nb1, nb2)
                         if nb1 and nb2 else 0.0)
                if ub_bag >= FLOOR:
                    s = jac(sd, sa)
                    if s >= FLOOR:
                        per_metric["bag (shipped)"].append((s, di, ai))
                wmin = min(sd.wsum, sa.wsum)
                wmax = max(sd.wsum, sa.wsum)
                if wmax and wmin / wmax >= FLOOR:
                    s = wjac(sd, sa, idf, "wsum")
                    if s >= FLOOR:
                        per_metric["idf_background"].append((s, di, ai))
                lmin = min(sd.wsum_local, sa.wsum_local)
                lmax = max(sd.wsum_local, sa.wsum_local)
                if lmax and lmin / lmax >= FLOOR:
                    s = wjac(sd, sa, lidf, "wsum_local")
                    if s >= FLOOR:
                        per_metric["idf_diff_local"].append((s, di, ai))
                if 0.6 * ub_bag + 0.4 * ub_bg >= FLOOR:
                    s = blend(sd, sa)
                    if s >= FLOOR:
                        per_metric["bigram_blend"].append((s, di, ai))
        # greedy order: score desc, then deterministic tiebreak (fqn analogue)
        for m in SIM_METRICS:
            per_metric[m].sort(key=lambda t: (-t[0],
                                              D[t[1]]["path"], D[t[1]]["name"],
                                              A[t[2]]["path"], A[t[2]]["name"]))
            sim_scores[m].append(per_metric[m])

    def best_other(lst, s):
        """lst = top-2 scores (desc, with multiplicity) for an endpoint that
        includes this pair's own score s. Returns the runner-up score this
        pair must beat, or None if it has no competitor."""
        if len(lst) == 1:
            return None
        return lst[1] if lst[0] == s else lst[0]

    def simulate(metric, thr, eps=None):
        """One greedy pass; eps!=None applies the symmetric margin gate.
        Returns dict incl. predicted {(ci,di,ai): verdict} and FN list."""
        tp = fp = ignored = 0
        predicted = {}
        fn_list = []
        for ci, (co, pos_idx, shared, movelike) in enumerate(commit_meta):
            D, A = co["disappeared"], co["appeared"]
            scored = sim_scores[metric][ci]
            pairs = [t for t in scored if t[0] >= thr]
            if eps is not None and pairs:
                d_top, a_top = defaultdict(list), defaultdict(list)
                for s, di, ai in pairs:
                    d_top[di].append(s)
                    a_top[ai].append(s)
                for lst in list(d_top.values()) + list(a_top.values()):
                    lst.sort(reverse=True)
                    del lst[2:]
                kept = []
                for s, di, ai in pairs:
                    bd = best_other(d_top[di], s)
                    ba = best_other(a_top[ai], s)
                    if ((bd is None or s - bd >= eps)
                            and (ba is None or s - ba >= eps)):
                        kept.append((s, di, ai))
                pairs = kept
            used_d, used_a = set(), set()
            pred = set()
            for s, di, ai in pairs:
                if di in used_d or ai in used_a:
                    continue
                used_d.add(di)
                used_a.add(ai)
                pred.add((di, ai))
                dn, an = D[di]["name"], A[ai]["name"]
                if (di, ai) in pos_idx:
                    tp += 1
                    v = "tp"
                elif (dn == an or dn in shared or an in shared
                      or (dn, an) in movelike):
                    ignored += 1
                    v = "ignored"
                else:
                    fp += 1
                    v = "fp"
                predicted[(ci, di, ai)] = (v, s)
            for di, ai in pos_idx - pred:
                true_s = next((s for s, d, a in sim_scores[metric][ci]
                               if d == di and a == ai), 0.0)
                fn_list.append((ci, di, ai, true_s))
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / denom if denom else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        fn_below = sum(1 for _, _, _, s in fn_list if s < thr)
        return dict(metric=metric, thr=thr, eps=eps, tp=tp, fp=fp,
                    fn=denom - tp, ignored=ignored, fn_below=fn_below,
                    fn_out=len(fn_list) - fn_below, prec=prec, rec=rec, f1=f1,
                    predicted=predicted, fn_list=fn_list)

    coarse = {m: [simulate(m, t) for t in SWEEP] for m in SIM_METRICS}
    fine = {m: [simulate(m, t) for t in FINE] for m in SIM_METRICS}
    summary = {}
    for m in SIM_METRICS:
        best = max(fine[m], key=lambda r: r["f1"])
        pm = next((r for r in fine[m] if r["prec"] >= 0.90), None)
        summary[m] = (best, pm)

    # ---- sanity checks against the original single-metric run ----
    at70 = next(r for r in coarse["bag (shipped)"]
                if abs(r["thr"] - 0.70) < 1e-9)
    assert (at70["tp"], at70["fp"], at70["fn"]) == (416, 65, 168), at70
    assert (at70["fn_below"], at70["fn_out"], at70["ignored"]) == \
        (146, 22, 558), at70
    at65 = next(r for r in coarse["bag (shipped)"]
                if abs(r["thr"] - 0.65) < 1e-9)
    assert (at65["tp"], at65["fp"]) == (447, 105), at65
    bag_auc = next(r for r in auc_rows if r[0] == "bag (shipped)")
    assert abs(bag_auc[1] - 0.9801) < 5e-5, bag_auc
    # idf_diff_local spot-check vs an independent from-scratch computation
    neo = next(c for c in commits if c["commit"].startswith("neo4j-8d9bedbf"))
    assert neo["_lpool_n"] == 161, neo["_lpool_n"]
    pp = next(p for p in neo["positives"]
              if p["before"]["name"] ==
              "shouldNotPersistUniquenessConstraintsCreatedInAbortedTransaction"
              and "UniqueProperty" in p["after"]["name"])
    got = wjac(pp["before"]["sig"], pp["after"]["sig"],
               neo["_lidf"], "wsum_local")
    assert abs(got - 0.791208) < 1e-5, got
    print("sanity checks vs original run + independent idf_diff_local "
          "spot-check: OK")

    # ---- 3. margin-gate ablation ----
    best_idf = max(("idf_background", "idf_diff_local"),
                   key=lambda m: summary[m][0]["f1"])
    ablation_configs = [("bag (shipped)", SHIPPED_THRESHOLD),
                        (best_idf, summary[best_idf][0]["thr"])]

    def quad_cases(base):
        """Outcompeted FNs (true score >= thr) with >=1 linked FP consumer."""
        thr = base["thr"]
        by_commit = defaultdict(list)
        for (ci, di, ai), (v, s) in base["predicted"].items():
            by_commit[ci].append((di, ai, v))
        cases = []
        for ci, di, ai, true_s in base["fn_list"]:
            if true_s < thr:
                continue
            linked = [(ci, dj, aj) for dj, aj, v in by_commit[ci]
                      if v == "fp" and (dj == di or aj == ai)]
            if linked:
                cases.append(((ci, di, ai), linked))
        return cases

    ablation = []
    for metric, thr in ablation_configs:
        base = simulate(metric, thr)
        cases = quad_cases(base)
        base_tp = {k for k, (v, _) in base["predicted"].items() if v == "tp"}
        base_fp = {k for k, (v, _) in base["predicted"].items() if v == "fp"}
        rows = [dict(base, quads=len(cases), resolved="-", halfgone="-",
                     unresolved="-", tp_lost=0, tp_gained=0, fp_elim=0)]
        for eps in EPSILONS:
            r = simulate(metric, thr, eps)
            pred = r["predicted"]
            e_tp = {k for k, (v, _) in pred.items() if v == "tp"}
            e_fp = {k for k, (v, _) in pred.items() if v == "fp"}
            resolved = halfgone = unresolved = 0
            for true_pair, linked in cases:
                if any(p in pred for p in linked):
                    unresolved += 1
                elif true_pair in pred:
                    resolved += 1
                else:
                    halfgone += 1
            rows.append(dict(r, quads=len(cases), resolved=resolved,
                             halfgone=halfgone, unresolved=unresolved,
                             tp_lost=len(base_tp - e_tp),
                             tp_gained=len(e_tp - base_tp),
                             fp_elim=len(base_fp - e_fp)))
        ablation.append((metric, thr, len(cases), rows))

    # ---- 4. small-pool stratification for idf_diff_local ----
    def bucket_of(n):
        if n < 10:
            return "<10"
        if n < 30:
            return "10-29"
        if n < 100:
            return "30-99"
        return ">=100"

    BUCKETS = ["<10", "10-29", "30-99", ">=100"]
    ci_bucket = [bucket_of(co["_lpool_n"]) for co, _, _, _ in commit_meta]
    bucket_commits = Counter(ci_bucket)
    bucket_pos = Counter()
    for ci, (_, pos_idx, _, _) in enumerate(commit_meta):
        bucket_pos[ci_bucket[ci]] += len(pos_idx)

    def pct(vals, q):
        if not vals:
            return float("nan")
        vs = sorted(vals)
        return vs[min(len(vs) - 1, round(q * (len(vs) - 1)))]

    neg_dist = {b: [] for b in BUCKETS}
    neg_dist_bag = {b: [] for b in BUCKETS}
    pos_dist = {b: [] for b in BUCKETS}
    for ci, (co, pos_idx, _, _) in enumerate(commit_meta):
        b = ci_bucket[ci]
        lidf = co["_lidf"]
        D, A = co["disappeared"], co["appeared"]
        for di, ai in co["neg_pairs"]:
            sd, sa = D[di]["sig"], A[ai]["sig"]
            if sd.ok and sa.ok:
                neg_dist[b].append(wjac(sd, sa, lidf, "wsum_local"))
                neg_dist_bag[b].append(jac(sd, sa))
        for di, ai in pos_idx:
            sd, sa = D[di]["sig"], A[ai]["sig"]
            if sd.ok and sa.ok:
                pos_dist[b].append(wjac(sd, sa, lidf, "wsum_local"))

    def per_ci_counts(run):
        tpc, fpc = Counter(), Counter()
        for (ci, di, ai), (v, s) in run["predicted"].items():
            if v == "tp":
                tpc[ci] += 1
            elif v == "fp":
                fpc[ci] += 1
        return tpc, fpc

    guard_thrs = (0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70)
    runs_cache = {("idf", t): simulate("idf_diff_local", t)
                  for t in guard_thrs}
    runs_cache[("bag", 0.70)] = simulate("bag (shipped)", 0.70)
    percis = {k: per_ci_counts(r) for k, r in runs_cache.items()}

    def strat_rows(key):
        tpc, fpc = percis[key]
        agg = {b: [0, 0] for b in BUCKETS}
        for ci in range(len(commit_meta)):
            agg[ci_bucket[ci]][0] += tpc[ci]
            agg[ci_bucket[ci]][1] += fpc[ci]
        out = []
        for b in BUCKETS:
            tp, fp = agg[b]
            fn = bucket_pos[b] - tp
            prec = tp / (tp + fp) if tp + fp else 0.0
            rec = tp / bucket_pos[b] if bucket_pos[b] else 0.0
            out.append((b, tp, fp, fn, prec, rec))
        return out

    def mix(rule):
        tp = fp = 0
        for ci in range(len(commit_meta)):
            tpc, fpc = percis[rule(ci)]
            tp += tpc[ci]
            fp += fpc[ci]
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / denom if denom else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        return tp, fp, denom - tp, prec, rec, f1

    guard_rows = [
        ("pure idf_diff_local@0.40", mix(lambda ci: ("idf", 0.40))),
        ("pure idf_diff_local@0.45", mix(lambda ci: ("idf", 0.45))),
        ("bag@0.70 for pool<10, else idf@0.40",
         mix(lambda ci: ("bag", 0.70) if ci_bucket[ci] == "<10"
             else ("idf", 0.40))),
        ("bag@0.70 for pool<30, else idf@0.40",
         mix(lambda ci: ("bag", 0.70) if ci_bucket[ci] in ("<10", "10-29")
             else ("idf", 0.40))),
    ]
    for ts in (0.45, 0.50, 0.55, 0.60, 0.65, 0.70):
        guard_rows.append(
            (f"idf@{ts:.2f} for pool<10, else idf@0.40",
             mix(lambda ci, ts=ts: ("idf", ts) if ci_bucket[ci] == "<10"
                 else ("idf", 0.40))))
    guard_rows.append(
        ("idf@0.55 for pool<10, idf@0.45 for 10-29, else idf@0.40",
         mix(lambda ci: ("idf", 0.55) if ci_bucket[ci] == "<10"
             else ("idf", 0.45) if ci_bucket[ci] == "10-29"
             else ("idf", 0.40))))

    # ---- report ----
    st = ds["stats"]
    lines = []
    w = lines.append
    w("# bifrost move/rename matching on the RefactoringMiner oracle\n")
    w("Real rename/move data: TP-validated `Rename Method`, `Move Method`, and")
    w("`Move And Rename Method` labels from RefactoringMiner's oracle, with")
    w("method bodies extracted from the cached before/after source trees.")
    w("Dataset built by `extract_pairs.py`; this file by `eval.py`.\n")
    w("## Dataset\n")
    w(f"- commits: {st['commits']}, positives: {st['positives']} "
      f"({st['positives_by_type']})")
    w(f"- positives representable in the disappeared/appeared field: "
      f"{st['positives_in_field']}")
    w(f"- negative pairs (cross products, filtered): {st['negative_pairs']}")
    w(f"- drop reasons: {st['drop_reasons']}")
    w("  (`*_abstract_no_body` = the labeled method is an abstract/interface "
      "declaration with no body -- unpairable by body similarity by design; "
      "`desc_parse_fail` = anonymous-class FQNs or oracle-truncated "
      "descriptions.)\n")
    w(f"- pairwise eval uses {n_pos_used} positives / {n_neg_used} negatives "
      f"after the <2-non-blank-line body filter "
      f"(skipped {n_pos_skipped} pos, {n_neg_skipped} neg).")
    w(f"- caveat: one commit ({BIG_NEG_COMMIT}) contributes ~47% of all "
      "negative pairs; per-type AUC shares the one negative pool. "
      "See the robustness table below.\n")
    w("Metric notes: `idf_background` weights tokens by IDF over ALL "
      "extracted method bodies (needs a shipped/background table); "
      "`idf_diff_local` computes df only over the same commit's extracted "
      "methods (median pool size is small) -- deployable at runtime with "
      "zero shipped data; `bigram_blend` = 0.6*bag + 0.4*bigram-set Jaccard.\n")
    w("## 1. Pairwise AUC (positives vs field negatives)\n")
    w("| metric | overall | Rename | Move | Move+Rename |")
    w("|---|---|---|---|---|")
    for row in auc_rows:
        w("| " + row[0] + " | " + " | ".join(f"{v:.4f}" for v in row[1:]) + " |")
    w("")
    w(f"### 1b. Robustness: excluding {BIG_NEG_COMMIT} negatives\n")
    w(f"Same positives, negatives reduced {n_neg_used} -> {n_neg_noinf}.\n")
    w("| metric | overall | Rename | Move | Move+Rename |")
    w("|---|---|---|---|---|")
    for row in auc_rows_noinf:
        w("| " + row[0] + " | " + " | ".join(f"{v:.4f}" for v in row[1:]) + " |")
    w("")
    w("## 2. Whole-commit simulation (greedy 1:1, per metric)\n")
    w(f"Oracle positives in the field: {denom} "
      f"(of which {denom_insubstantial} have a <2-line body on one side and "
      f"can never be paired by the shipped rule). Predicted pairs that are "
      f"unlabeled same-name matches or overlap an Extract/Inline/Pull-Up-family "
      f"label are counted as `ignored`, not FP. "
      f"`FN below-thr` = the true pair scores under the threshold; "
      f"`FN outcompeted` = it scores at/above the threshold but greedy 1:1 "
      f"gave an endpoint to a higher-or-tied competitor.\n")
    for m in SIM_METRICS:
        w(f"### {m}\n")
        w("| threshold | TP | FP | FN | FN below-thr | FN outcompeted | "
          "ignored | precision | recall | F1 |")
        w("|---|---|---|---|---|---|---|---|---|---|")
        for r in coarse[m]:
            w(f"| {r['thr']:.2f} | {r['tp']} | {r['fp']} | {r['fn']} | "
              f"{r['fn_below']} | {r['fn_out']} | {r['ignored']} | "
              f"{r['prec']:.3f} | {r['rec']:.3f} | {r['f1']:.3f} |")
        w("")
    w("### Operating points (fine sweep 0.25-0.98 step 0.01)\n")
    w("Best-F1 point, and the precision-matched point = lowest threshold "
      "whose precision reaches 0.90 (each metric has its own score scale, "
      "so thresholds are not comparable across rows -- recall at matched "
      "precision is).\n")
    w("| metric | bestF1 thr | P | R | F1 | first P>=0.90 thr | P | R |")
    w("|---|---|---|---|---|---|---|---|")
    for m in SIM_METRICS:
        b, pm = summary[m]
        pmtxt = (f"{pm['thr']:.2f} | {pm['prec']:.3f} | {pm['rec']:.3f}"
                 if pm else "never | - | -")
        w(f"| {m} | {b['thr']:.2f} | {b['prec']:.3f} | {b['rec']:.3f} | "
          f"{b['f1']:.3f} | {pmtxt} |")
    w("")
    w("## 3. Symmetric margin-gate ablation\n")
    w("Accept (pre,post) only if score - score(runner-up) >= eps on BOTH "
      "endpoints; runner-ups computed statically among threshold-passing "
      "pairs, then greedy 1:1 over the survivors. `quads` = baseline "
      "outcompeted-FNs whose endpoint was consumed by a false positive "
      "(the sibling-steal cases). `resolved` = FP(s) gone AND true pair "
      "recovered; `fp-gone-tp-lost` = FP(s) gone but the true pair gated "
      "too (near-tie, both suppressed); `unresolved` = an FP survives.\n")
    for metric, thr, nquads, rows in ablation:
        w(f"### {metric} @ {thr:.2f} ({nquads} sibling-steal quads at "
          f"baseline)\n")
        w("| eps | TP | FP | FN | precision | recall | F1 | resolved | "
          "fp-gone-tp-lost | unresolved | TP lost | TP gained | FP removed |")
        w("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for r in rows:
            e = "0 (base)" if r["eps"] is None else f"{r['eps']:.2f}"
            w(f"| {e} | {r['tp']} | {r['fp']} | {r['fn']} | {r['prec']:.3f} | "
              f"{r['rec']:.3f} | {r['f1']:.3f} | {r['resolved']} | "
              f"{r['halfgone']} | {r['unresolved']} | {r['tp_lost']} | "
              f"{r['tp_gained']} | {r['fp_elim']} |")
        w("")
    w("## 4. Small-pool behavior (idf_diff_local)\n")
    w("Production diffs skew to far smaller local df pools than the oracle "
      "commits, and with few methods the idf weights compress toward "
      "uniform, drifting scores back toward bag-Jaccard scale while the "
      "threshold assumes IDF scale. Stratification by local pool size "
      "(number of method bodies in the commit's df pool):\n")
    w("| pool size | commits | field positives | neg pairs | neg p50 | "
      "neg p90 | neg p99 | neg max | pos p10 | pos p50 |")
    w("|---|---|---|---|---|---|---|---|---|---|")
    for b in BUCKETS:
        nd, pd = neg_dist[b], pos_dist[b]
        w(f"| {b} | {bucket_commits[b]} | {bucket_pos[b]} | {len(nd)} | "
          f"{pct(nd, 0.50):.3f} | {pct(nd, 0.90):.3f} | {pct(nd, 0.99):.3f} | "
          f"{pct(nd, 1.0):.3f} | {pct(pd, 0.10):.3f} | {pct(pd, 0.50):.3f} |")
    w("")
    for key, label in ((("idf", 0.40), "idf_diff_local @ 0.40"),
                       (("idf", 0.45), "idf_diff_local @ 0.45")):
        w(f"### Per-bucket outcomes, {label}\n")
        w("| pool size | TP | FP | FN | precision | recall |")
        w("|---|---|---|---|---|---|")
        for b, tp, fp, fn, prec, rec in strat_rows(key):
            w(f"| {b} | {tp} | {fp} | {fn} | {prec:.3f} | {rec:.3f} |")
        w("")
    w("### Rename-free FP exposure: negatives crossing the threshold\n")
    w("Oracle commits all contain a true rename, so the simulation "
      "understates FP risk on production diffs that contain none (the true "
      "partner is not there to win the endpoint). The direct stat is how "
      "many negative pairs cross each config's threshold:\n")
    w("| pool size | negs | idf>=0.40 | idf>=0.45 | bag>=0.70 (shipped) |")
    w("|---|---|---|---|---|")
    for b in BUCKETS:
        nd, nb = neg_dist[b], neg_dist_bag[b]
        c40 = sum(1 for s in nd if s >= 0.40)
        c45 = sum(1 for s in nd if s >= 0.45)
        cb = sum(1 for s in nb if s >= 0.70)
        w(f"| {b} | {len(nd)} | {c40} ({100*c40/len(nd):.2f}%) | "
          f"{c45} ({100*c45/len(nd):.2f}%) | {cb} ({100*cb/len(nb):.2f}%) |")
    a40 = sum(1 for b in BUCKETS for s in neg_dist[b] if s >= 0.40)
    a45 = sum(1 for b in BUCKETS for s in neg_dist[b] if s >= 0.45)
    ab = sum(1 for b in BUCKETS for s in neg_dist_bag[b] if s >= 0.70)
    an = sum(len(neg_dist[b]) for b in BUCKETS)
    w(f"| ALL | {an} | {a40} ({100*a40/an:.2f}%) | {a45} ({100*a45/an:.2f}%) "
      f"| {ab} ({100*ab/an:.2f}%) |")
    w("")
    w("### Reading the small-pool data\n")
    w("- The inflation concern is real only at the extreme tail (neg p90 is "
      "~3x higher for pool<30 than pool>=100) but it does NOT convert into "
      "decisions: pool<10 has ZERO false positives at 0.40 (precision "
      "1.000), and the worst stratum is the LARGEST bucket (>=100: many "
      "sibling candidates), not the smallest.")
    w("- The elevated small-pool negative tail is a property of small "
      "fields (few, semantically related changed methods), not an IDF "
      "artifact: bag-Jaccard@0.70 shows the same pattern and crosses its "
      "threshold MORE often than idf@0.40 in both small buckets (6 vs 5 in "
      "<10, 93 vs 83 in 10-29) and ~2x more overall (1515 vs 833). On "
      "rename-free diffs the proposed config is strictly safer than the "
      "shipped one.")
    w("- Every guard tested (bag@0.70 fallback for small pools, raised "
      "small-pool thresholds) is neutral or worse than pure "
      "idf_diff_local@0.40, because there are no small-pool FPs to remove "
      "-- guards only delete small-pool TPs. No guard is warranted.")
    w("")
    w("## 5. Failure examples (bag @ 0.70)\n")
    w("### False positives (predicted pair, no oracle label)\n")
    w("| commit | disappeared | appeared | score |")
    w("|---|---|---|---|")
    fp_ex = [(commits[ci]["commit"], commits[ci]["disappeared"][di]["name"],
              commits[ci]["appeared"][ai]["name"], s)
             for (ci, di, ai), (v, s) in at70["predicted"].items()
             if v == "fp"]
    for cid, dn, an, s in sorted(fp_ex, key=lambda t: -t[3])[:10]:
        w(f"| {cid} | {dn} | {an} | {s:.3f} |")
    w("")
    w("### False negatives (oracle pair not predicted; score = true pair's "
      "score)\n")
    w("| commit | before | after | true-pair score |")
    w("|---|---|---|---|")
    fn_ex = [(commits[ci]["commit"], commits[ci]["disappeared"][di]["name"],
              commits[ci]["appeared"][ai]["name"], s)
             for ci, di, ai, s in at70["fn_list"]]
    for cid, dn, an, s in sorted(fn_ex, key=lambda t: -t[3])[:10]:
        w(f"| {cid} | {dn} | {an} | {s:.3f} |")
    w("")
    w("### Reading the failures\n")
    w("- The dominant decision-level failure is NEAR-DUPLICATE SIBLINGS: when "
      "a method is copy-renamed into several variants (test-class splits like "
      "neo4j-8d9bedbf's `Uniqueness...` -> `UniqueProperty...` + "
      "`MandatoryProperty...`), the wrong sibling can outscore or tie the "
      "true partner, producing a matched FP+FN pair. The margin gate in "
      "section 3 targets exactly these.")
    w("- Oracle 1:many labels (class splits: one constructor labeled as moving "
      "to two new classes) are unsatisfiable under the shipped 1:1 greedy rule; "
      "one target is always an FN.")
    w("- A few top-score FPs are genuine relocations the oracle simply does "
      "not label (e.g. jfinal `I18N` -> `I18n` constructor during a class "
      "restructure), so measured precision is a floor.")
    w("")
    w("## Bottom line\n")
    w("Ship `idf_diff_local` (commit-local IDF-weighted bag Jaccard; df over "
      "just the commit's extracted methods, so zero shipped table) at "
      "threshold ~0.40, with NO margin gate. At thr 0.41 it is "
      "precision-matched to the 0.90 bar with P 0.904 / R 0.807, vs the "
      "shipped bag@0.70's P 0.865 / R 0.712 -- about +9.5pt recall AND +4pt "
      "precision simultaneously; best-F1 is 0.858 @ 0.36 vs bag's 0.789 @ "
      "0.67. The background-IDF table buys only ~3pt more recall at matched "
      "precision (R 0.836 @ 0.38) -- not worth shipping and maintaining a "
      "global df table. Pairwise AUC agrees (idf_diff_local 0.9948, first) "
      "and the ranking is unchanged after dropping infinispan-8f446b6d's "
      "47% share of negatives (0.9934, still first). Do NOT adopt the "
      "margin gate as a default: it lowers F1 at every tested eps, it never "
      "actually rescues a stolen sibling (resolved = 0 everywhere -- the "
      "true pair is always within eps of the stealing FP, so both get "
      "suppressed and a matched FP+FN merely becomes an FN), and on the IDF "
      "config the pairs it removes are mostly RIGHT (48 TP lost vs 30 FP "
      "removed at eps=0.02). Its one legitimate niche is precision-max "
      "operation: bag@0.70 + eps=0.02 reaches P 0.967 / R 0.647, a better "
      "precision/recall point than any pure threshold. The small-pool "
      "concern (section 4) is resolved in favor of the pure config: tiny "
      "df pools inflate the negative tail slightly but produce ZERO false "
      "positives at 0.40, cross the threshold less often than shipped "
      "bag@0.70 does, and every guard tested only costs recall -- ship "
      "pure idf_diff_local@0.40 with no pool-size fallback. Caveat: "
      "thresholds are tuned on this same oracle; treat 0.40 as a starting "
      "point, not a certified constant.")
    w("")
    open(OUT, "w").write("\n".join(lines))
    print("\n".join(lines))
    print(f"total runtime: {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
