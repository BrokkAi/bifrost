#!/usr/bin/env python3
"""Build a real-data move/rename evaluation dataset from RefactoringMiner's oracle.

Source: ~/Projects/RefactoringMiner/src/test/resources/oracle/
  - data.json lists 550 validated commits; we use validation=="TP" labels of
    type Rename Method / Move Method / Move And Rename Method as POSITIVES.
  - commits/<Repo>-<sha>/ holds the changed files of that commit; the sidecar
    commits/<Repo>-<sha>.json names parentCommitId, whose sibling dir
    commits/<Repo>-<parent>/ holds the BEFORE versions of the same files
    (verified: identical file list, differing content). Every resolved label is
    still validated by content: the old-named method must exist in the before
    tree and the new-named method in the after tree, else the label is dropped.

NEGATIVE FIELD (per commit): all methods extracted from the changed files on
both sides; disappeared = (path, name) present before, absent after (with file
renames mapped through renamedFilesHint); appeared = the reverse. Negative
pairs = disappeared x appeared minus
  (a) name pairs claimed by any move-like method label (Rename/Move/
      Move And Rename/Pull Up/Push Down Method, any validation) -- these are
      genuine or at least suspected same-body pairs, not clean negatives;
  (b) pairs touching any method named in an Extract/Inline-family label
      (an extracted method genuinely shares its body with its origin);
  (c) same-name pairs -- an unlabeled same-name disappear/appear is very often
      a genuine relocation riding a class move/rename, not a name clash.

Output: dataset.json next to this script.
"""
import json
import os
import re
import sys
from collections import Counter

ORACLE = os.path.expanduser("~/Projects/RefactoringMiner/src/test/resources/oracle")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset.json")

POS_TYPES = {"Rename Method", "Move Method", "Move And Rename Method"}
# Labels whose participants genuinely share body content with another method.
SHARED_BODY_TYPES = {
    "Extract Method", "Extract And Move Method", "Inline Method",
    "Move And Inline Method",
}
# Labels claiming "this (name_before, name_after) is the same method".
MOVE_LIKE_TYPES = POS_TYPES | {"Pull Up Method", "Push Down Method"}
# Class-level relocations: the class's CONSTRUCTORS genuinely change name with
# the class, so (old_simple, new_simple) pairs are not clean negatives either.
CLASS_TYPES = {"Rename Class", "Move Class", "Move And Rename Class"}

C_KEYWORDS = {"if", "for", "while", "switch", "catch", "synchronized", "return",
              "new", "else", "do", "try", "finally", "case", "break", "continue",
              "throw", "assert", "super", "this"}


# --- Java source handling ---------------------------------------------------

def mask_java(text):
    """Blank comment and string/char-literal CONTENTS with spaces (newlines
    kept) so signature regexes and brace matching cannot be fooled; indices are
    preserved, so bodies are sliced from the original text."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
        elif c == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n:
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    out.append("  ")
                    i += 2
                    break
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
        elif c == '"' or c == "'":
            q = c
            out.append(q)
            i += 1
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                    continue
                if text[i] == q:
                    out.append(q)
                    i += 1
                    break
                if text[i] == "\n":  # unterminated literal; bail
                    out.append("\n")
                    i += 1
                    break
                out.append(" ")
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


SIG = re.compile(
    r'(?:^|\n)[ \t]*'
    r'(?:(?:public|private|protected|static|final|synchronized|native|abstract|'
    r'default|strictfp|transient)\s+)*'
    r'[\w<>\[\]&:,.\s?]+?\b(\w+)\s*\(([^;{}]*)\)\s*'
    r'(?:throws\s+[\w.,\s]+?)?\{')


def count_params(params):
    """Top-level comma count in a parameter list (generics/parens nested)."""
    s = params.strip()
    if not s:
        return 0
    depth = 0
    count = 1
    for ch in s:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        elif ch == "," and depth == 0:
            count += 1
    return count


def extract_methods(text):
    """Brace-matched method extraction (hardened extract_c_methods): returns
    [{name, nparams, body, line}] for every method-like decl with a body."""
    masked = mask_java(text)
    out = []
    for m in SIG.finditer(masked):
        name = m.group(1)
        if name in C_KEYWORDS:
            continue
        pre = masked[:m.start(1)].rstrip()
        # reject calls (`executor.submit(... {`) and anon classes (`new Foo(){`)
        if pre.endswith(".") or re.search(r"\bnew$", pre):
            continue
        i = m.end() - 1
        depth = 0
        n = len(masked)
        while i < n:
            if masked[i] == "{":
                depth += 1
            elif masked[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth != 0:
            continue  # unbalanced (parse trouble); skip
        body = text[m.start():i + 1].strip("\n").strip()
        out.append({
            "name": name,
            "nparams": count_params(m.group(2)),
            "body": body,
            "line": masked.count("\n", 0, m.start(1)) + 1,
        })
    return out


# --- oracle description parsing ---------------------------------------------

def sig_name_nparams(sig):
    p = sig.find("(")
    if p < 0:
        return None
    m = re.search(r"([A-Za-z_$][\w$]*)\s*$", sig[:p])
    if not m:
        return None
    depth = 0
    i = p
    while i < len(sig):
        if sig[i] == "(":
            depth += 1
        elif sig[i] == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return m.group(1), count_params(sig[p + 1:i])


def parse_label(rtype, desc):
    """-> (sig_before, class_before, sig_after, class_after) or None."""
    desc = " ".join(desc.split())  # normalize whitespace
    if rtype == "Rename Method":
        m = re.match(r"^Rename Method (.*) renamed to (.*) in class ([\w.$]+)$", desc)
        if not m:
            return None
        s1, s2, cls = m.groups()
        return s1, cls, s2, cls
    prefix = rtype + " "
    if not desc.startswith(prefix):
        return None
    m = re.match(r"^(.*) from class ([\w.$]+) to (.*) from class ([\w.$]+)$",
                 desc[len(prefix):])
    if not m:
        return None
    return m.groups()


def label_name_pairs(rtype, desc):
    """(before_name, after_name) for a move-like label, for negative exclusion."""
    parsed = parse_label(rtype if rtype in POS_TYPES | {"Rename Method"} else rtype, desc)
    if rtype in {"Pull Up Method", "Push Down Method"}:
        m = re.match(r"^%s (.*) from class ([\w.$]+) to (.*) from class ([\w.$]+)$"
                     % re.escape(rtype), " ".join(desc.split()))
        parsed = m.groups() if m else None
    if not parsed:
        return None
    nb = sig_name_nparams(parsed[0])
    na = sig_name_nparams(parsed[2])
    if not nb or not na:
        return None
    return nb[0], na[0]


def class_name_pair(desc):
    """(old_simple, new_simple) from a Rename/Move/Move And Rename Class label;
    constructors are named after their immediate (possibly nested) class."""
    m = re.match(r"^(?:Rename Class|Move Class|Move And Rename Class) ([\w.$]+) "
                 r"(?:renamed|moved(?: and renamed)?) to ([\w.$]+)$",
                 " ".join(desc.split()))
    if not m:
        return None
    old, new = m.groups()
    return old.split(".")[-1], new.split(".")[-1]


def all_paren_names(desc):
    """Every identifier immediately preceding a '(' -- conservative superset of
    the method names an Extract/Inline-family label touches."""
    return set(re.findall(r"([A-Za-z_$][\w$]*)\s*\(", desc))


# --- class FQN -> file resolution -------------------------------------------

def outer_and_package(fqn):
    parts = fqn.split(".")
    for i, p in enumerate(parts):
        if p[:1].isupper():
            return p, parts[:i]
    return parts[-1], parts[:-1]


def resolve_file(index, fqn):
    """index: {basename -> [relpath,...]}. Returns relpath or None."""
    simple, package = outer_and_package(fqn)
    hits = index.get(simple + ".java", [])
    if not hits:
        return None
    if len(hits) == 1:
        return hits[0]
    suffix = "/".join(package + [simple + ".java"])
    exact = [h for h in hits if h == suffix or h.endswith("/" + suffix)]
    if len(exact) == 1:
        return exact[0]
    return None  # several equally-plausible files: drop rather than guess


def load_side(root):
    """-> (file_index, {relpath: [methods]}) for all .java files under root."""
    index = {}
    methods = {}
    for dp, _, fns in os.walk(root):
        for fn in fns:
            if not fn.endswith(".java"):
                continue
            rel = os.path.relpath(os.path.join(dp, fn), root).replace(os.sep, "/")
            index.setdefault(fn, []).append(rel)
            try:
                txt = open(os.path.join(dp, fn), encoding="utf-8",
                           errors="ignore").read()
            except OSError:
                continue
            methods[rel] = extract_methods(txt)
    return index, methods


def pick_method(methods, name, nparams, drop, side, root, relpath):
    cands = [m for m in methods if m["name"] == name]
    if not cands:
        # distinguish "declared but bodyless" (abstract/interface method --
        # unpairable by body similarity by design) from a real extraction miss
        try:
            txt = open(os.path.join(root, relpath), encoding="utf-8",
                       errors="ignore").read()
        except OSError:
            txt = ""
        if re.search(rf"\b{re.escape(name)}\s*\([^{{;()]*\)[^{{;()]*;", txt):
            drop[f"{side}_abstract_no_body"] += 1
        else:
            drop[f"{side}_method_not_found"] += 1
        return None
    if len(cands) == 1:
        return cands[0]
    byn = [m for m in cands if m["nparams"] == nparams]
    if len(byn) == 1:
        return byn[0]
    pool = byn or cands
    if len({m["body"] for m in pool}) == 1:
        return pool[0]
    drop[f"{side}_ambiguous_overload"] += 1
    return None


# --- main -------------------------------------------------------------------

def main():
    data = json.load(open(os.path.join(ORACLE, "data.json")))
    drop = Counter()
    kept_by_type = Counter()
    commits_out = []
    n_pos_in_field = 0
    n_neg_total = 0

    for c in data:
        pos_labels = [r for r in c["refactorings"]
                      if r["type"] in POS_TYPES and r["validation"] == "TP"]
        if not pos_labels:
            continue
        repo = c["repository"].rstrip("/").split("/")[-1]
        repo = repo[:-4] if repo.endswith(".git") else repo
        cid = f"{repo}-{c['sha1']}"
        after_dir = os.path.join(ORACLE, "commits", cid)
        sidecar = after_dir + ".json"
        if not (os.path.isdir(after_dir) and os.path.isfile(sidecar)):
            drop["commit_dirs_missing"] += len(pos_labels)
            continue
        meta = json.load(open(sidecar))
        before_dir = os.path.join(ORACLE, "commits", f"{repo}-{meta['parentCommitId']}")
        if not os.path.isdir(before_dir):
            drop["commit_before_dir_missing"] += len(pos_labels)
            continue
        renamed = {old.replace(os.sep, "/"): new.replace(os.sep, "/")
                   for old, new in meta.get("renamedFilesHint", {}).items()}

        b_index, b_methods = load_side(before_dir)
        a_index, a_methods = load_side(after_dir)

        # ---- positives ----
        positives = []
        seen = set()
        for r in pos_labels:
            parsed = parse_label(r["type"], r["description"])
            if not parsed:
                drop["desc_parse_fail"] += 1
                continue
            sig_b, cls_b, sig_a, cls_a = parsed
            nb, na = sig_name_nparams(sig_b), sig_name_nparams(sig_a)
            if not nb or not na:
                drop["sig_parse_fail"] += 1
                continue
            (bname, bnp), (aname, anp) = nb, na
            bfile = resolve_file(b_index, cls_b)
            afile = resolve_file(a_index, cls_a)
            if not bfile or not afile:
                drop["class_file_not_found"] += 1
                continue
            key = (bfile, bname, bnp, afile, aname, anp)
            if key in seen:
                drop["duplicate_label"] += 1
                continue
            seen.add(key)
            bm = pick_method(b_methods.get(bfile, []), bname, bnp, drop,
                             "before", before_dir, bfile)
            if bm is None:
                continue
            am = pick_method(a_methods.get(afile, []), aname, anp, drop,
                             "after", after_dir, afile)
            if am is None:
                continue
            positives.append({
                "type": r["type"],
                "before": {"name": bname, "class": cls_b, "path": bfile,
                           "body": bm["body"]},
                "after": {"name": aname, "class": cls_a, "path": afile,
                          "body": am["body"]},
            })
            kept_by_type[r["type"]] += 1
        if not positives:
            drop["commit_no_positive_extracted"] += 1
            continue

        # ---- negative field ----
        def field_keys(methods_by_file, mapper=None):
            keyed = {}
            for path, ms in methods_by_file.items():
                mpath = (mapper or {}).get(path, path)
                for m in ms:
                    keyed.setdefault((mpath, m["name"]), []).append((path, m))
            return keyed

        bkeys = field_keys(b_methods, renamed)
        akeys = field_keys(a_methods)
        disappeared, appeared = [], []
        for k in sorted(set(bkeys) - set(akeys)):
            for path, m in bkeys[k]:
                disappeared.append({"name": m["name"], "path": path,
                                    "nparams": m["nparams"], "body": m["body"]})
        for k in sorted(set(akeys) - set(bkeys)):
            for path, m in akeys[k]:
                appeared.append({"name": m["name"], "path": path,
                                 "nparams": m["nparams"], "body": m["body"]})

        # exclusion inputs from ALL labels on this commit (any validation)
        shared_body_names = set()
        movelike_pairs = set()
        for r in c["refactorings"]:
            if r["type"] in SHARED_BODY_TYPES:
                shared_body_names |= all_paren_names(r["description"])
            elif r["type"] in MOVE_LIKE_TYPES:
                np_ = label_name_pairs(r["type"], r["description"])
                if np_:
                    movelike_pairs.add(np_)
                else:
                    shared_body_names |= all_paren_names(r["description"])
            elif r["type"] in CLASS_TYPES:
                np_ = class_name_pair(r["description"])
                if np_:
                    movelike_pairs.add(np_)

        neg_pairs = []
        for di, d in enumerate(disappeared):
            for ai, a in enumerate(appeared):
                if d["name"] == a["name"]:
                    continue
                if (d["name"], a["name"]) in movelike_pairs:
                    continue
                if d["name"] in shared_body_names or a["name"] in shared_body_names:
                    continue
                neg_pairs.append([di, ai])

        # map positives into the field (for the whole-commit simulation)
        def locate(entries, name, path, body):
            for i, e in enumerate(entries):
                if e["name"] == name and e["path"] == path and e["body"] == body:
                    return i
            return None

        for p in positives:
            p["d_idx"] = locate(disappeared, p["before"]["name"],
                                p["before"]["path"], p["before"]["body"])
            p["a_idx"] = locate(appeared, p["after"]["name"],
                                p["after"]["path"], p["after"]["body"])
            if p["d_idx"] is not None and p["a_idx"] is not None:
                n_pos_in_field += 1

        n_neg_total += len(neg_pairs)
        commits_out.append({
            "commit": cid,
            "parent": meta["parentCommitId"],
            "positives": positives,
            "disappeared": disappeared,
            "appeared": appeared,
            "neg_pairs": neg_pairs,
            "shared_body_names": sorted(shared_body_names),
            "movelike_name_pairs": sorted(movelike_pairs),
        })

    n_pos = sum(kept_by_type.values())
    stats = {
        "commits": len(commits_out),
        "positives": n_pos,
        "positives_by_type": dict(kept_by_type),
        "positives_in_field": n_pos_in_field,
        "negative_pairs": n_neg_total,
        "drop_reasons": dict(drop),
    }
    json.dump({"stats": stats, "commits": commits_out}, open(OUT, "w"))
    print(json.dumps(stats, indent=2))
    print(f"wrote {OUT} ({os.path.getsize(OUT) // 1024} KiB)")


if __name__ == "__main__":
    main()
