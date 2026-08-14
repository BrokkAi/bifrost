#!/usr/bin/env python3
"""End-to-end smoke corpus for bifrost analyze_diff move/rename pairing.

Unlike eval.py (which scores a Python replica of the metric against the
RefactoringMiner oracle), this harness exercises the ACTUAL bifrost binary:
each case materializes a 2-commit git repo, runs `bifrost --tool analyze_diff`,
and checks how the target symbol was classified (`moved` vs delete+introduce).

Five cases: Rust pure move / move+rename / move+rename+internal-edit, a
false-positive guard (unrelated delete+add must NOT pair), and a real Java
method lifted from RefactoringMiner's own test corpus, moved and renamed.

Run after any change to diff_analysis.rs pairing/scoring:
    cargo build --release --bin bifrost && python3 tools/rename-eval/e2e_corpus.py
Exit code 0 = all pass. Binary path override: BIFROST_BIN env var.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BF = os.environ.get("BIFROST_BIN", os.path.join(REPO_ROOT, "target", "release", "bifrost"))
ROOT = tempfile.mkdtemp(prefix="bifrost-e2e-corpus-")

# A real method lifted verbatim from RefactoringMiner's test corpus
# (mappings/ExecutionUtil-v1.txt): genuine refactored code, not a toy.
RM_REAL_METHOD = '''  private static Icon getLiveIndicator(final Icon base) {
    return new LayeredIcon(base, new Icon() {
      @Override
      public void paintIcon(Component c, Graphics g, int x, int y) {
        Graphics2D g2d = (Graphics2D)g.create();
        try {
          GraphicsUtil.setupAAPainting(g2d);
          g2d.setColor(Color.GREEN);
          g2d.fill(new Ellipse2D.Double(x, y, 4, 4));
        }
        finally {
          g2d.dispose();
        }
      }
    });
  }
'''
RM_REAL_METHOD_RENAMED = RM_REAL_METHOD.replace("getLiveIndicator", "buildRunningBadge")


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def make_repo(name, c1_files, c2_files):
    d = os.path.join(ROOT, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    git(d, "init")
    git(d, "config", "user.email", "t@t")
    git(d, "config", "user.name", "t")
    for path, content in c1_files.items():
        os.makedirs(os.path.join(d, os.path.dirname(path)), exist_ok=True)
        open(os.path.join(d, path), "w").write(content)
    git(d, "add", "-A")
    git(d, "commit", "-m", "c1")
    for path in c1_files:
        if path not in c2_files:
            os.remove(os.path.join(d, path))
    for path, content in c2_files.items():
        os.makedirs(os.path.join(d, os.path.dirname(path)), exist_ok=True)
        open(os.path.join(d, path), "w").write(content)
    git(d, "add", "-A")
    git(d, "commit", "-m", "c2")
    return d


def analyze(d):
    out = subprocess.run([BF, "--root", d, "--tool", "analyze_diff",
                          "--args", '{"base":"HEAD^","target":"HEAD"}'],
                         capture_output=True, text=True)
    p = json.loads(out.stdout)["structuredContent"]["patch_symbols"]
    return {
        "moved": [(m["before"]["fqn"], m["after"]["fqn"]) for m in p["moved"]],
        "introduced": [s["after"]["fqn"] for s in p["introduced"]],
        "deleted": [s["before"]["fqn"] for s in p["deleted"]],
    }


def rust_accum(fn, acc):
    return (f"pub fn {fn}(items: &[i32]) -> i32 {{\n"
            f"    let mut {acc} = 0;\n    for it in items {{\n"
            f"        {acc} += *it;\n    }}\n    {acc}\n}}\n")


CASES = [
    # (name, c1 files, c2 files, expectation, before-fqn-substr, after-fqn-substr)
    ("rust_pure_move",
     {"src/helper.rs": rust_accum("compute_total", "sum") + "\npub fn kept() -> u8 { 1 }\n",
      "src/util.rs": "pub fn other() -> bool { true }\n"},
     {"src/helper.rs": "pub fn kept() -> u8 { 1 }\n",
      "src/util.rs": "pub fn other() -> bool { true }\n\n" + rust_accum("compute_total", "sum")},
     "moved", "helper.compute_total", "util.compute_total"),

    ("rust_move_rename",
     {"src/helper.rs": rust_accum("compute_total", "sum") + "\npub fn kept() -> u8 { 1 }\n",
      "src/util.rs": "pub fn other() -> bool { true }\n"},
     {"src/helper.rs": "pub fn kept() -> u8 { 1 }\n",
      "src/util.rs": "pub fn other() -> bool { true }\n\n" + rust_accum("sum_all", "sum")},
     "moved", "helper.compute_total", "util.sum_all"),

    ("rust_move_rename_edit",
     {"src/helper.rs": rust_accum("compute_total", "sum") + "\npub fn kept() -> u8 { 1 }\n",
      "src/util.rs": "pub fn other() -> bool { true }\n"},
     {"src/helper.rs": "pub fn kept() -> u8 { 1 }\n",
      "src/util.rs": "pub fn other() -> bool { true }\n\n" + rust_accum("sum_all", "total")},
     "moved", "helper.compute_total", "util.sum_all"),

    # NEGATIVE: an unrelated function deleted and a different one added.
    ("rust_negative_unrelated",
     {"src/a.rs": rust_accum("compute_total", "sum"),
      "src/b.rs": "pub fn placeholder() -> bool { false }\n"},
     {"src/a.rs": "pub fn placeholder2() -> bool { false }\n",
      "src/b.rs": "pub fn greet(name: &str) -> String {\n    let mut out = String::new();\n"
                  "    out.push_str(name);\n    out.push('!');\n    out\n}\n"},
     "not_moved", "compute_total", None),

    ("java_rm_real_move_rename",
     {"a/Exec.java": "package a;\nclass Exec {\n" + RM_REAL_METHOD + "}\n",
      "a/Other.java": "package a;\nclass Other { void keep() {} }\n"},
     {"a/Exec.java": "package a;\nclass Exec { void stub() {} }\n",
      "a/Other.java": "package a;\nclass Other {\n" + RM_REAL_METHOD_RENAMED + "}\n"},
     "moved", "getLiveIndicator", "buildRunningBadge"),
]


def main():
    if not os.path.isfile(BF):
        print(f"bifrost binary not found at {BF}; build it or set BIFROST_BIN", file=sys.stderr)
        return 2
    print(f"{'CASE':<28} {'EXPECT':<10} RESULT")
    print("-" * 78)
    fails = 0
    for name, c1, c2, expect, before_key, after_key in CASES:
        r = analyze(make_repo(name, c1, c2))
        moved = r["moved"]
        if expect == "moved":
            ok = any(before_key in b and after_key in a for b, a in moved)
        else:  # not_moved
            ok = not any(before_key in b for b, _ in moved)
        if not ok:
            fails += 1
        detail = f"moved={moved} intro={r['introduced']} del={r['deleted']}"
        print(f"{name:<28} {expect:<10} {'PASS' if ok else 'FAIL'}  {detail}")
    print("-" * 78)
    print("ALL PASS" if fails == 0 else f"{fails} FAILED")
    shutil.rmtree(ROOT, ignore_errors=True)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
