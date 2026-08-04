#!/usr/bin/env python3
"""Replay MCP reproductions and protocol stress scenarios over stdio.

Drives a `bifrost` binary as a real MCP client (roots capability included) on
either protocol stack, replaying the reproductions from the open latency
issues (#1423 #1419 #1411 #1430 #1416 #1435 #1398) plus cold-start,
cancellation, parallel-storm, roots-change, and per-tool coverage scenarios.
The two stacks disagreeing on the same input is the most useful signal while
both exist; run both and diff the summaries.

Usage:
  scripts/mcp-replay.py --binary target/release/bifrost --workspace . \
      [--stack rmcp|legacy] [--scenario NAME ...] [--warm] \
      [--budget-secs N] [--no-roots] [--mode 'symbol|extended']

Delete .bifrost/cache/bifrost_cache.v*.db* first for a true-cold run. Set
BIFROST_TIMING=1 and MCP_REPLAY_STDERR_FILE=/path to capture the server's
profiling scopes for any failing scenario.

Speaks newline-delimited JSON-RPC 2.0. Advertises the roots capability and
answers roots/list with the workspace (unless --no-roots), matching how real
agent clients bind the workspace. Prints one line per request with wall time
and outcome, then a scenario verdict.
"""

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time

class McpClient:
    def __init__(self, binary, workspace, stack, mode, use_roots, extra_env=None):
        env = dict(os.environ)
        env["BIFROST_MCP_RMCP"] = "on" if stack == "rmcp" else "off"
        env["BIFROST_SEMANTIC_INDEX"] = "off"
        if extra_env:
            env.update(extra_env)
        self.use_roots = use_roots
        self.workspace = os.path.abspath(workspace)
        self.proc = subprocess.Popen(
            [binary, "--mcp", mode],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=self.workspace, env=env, text=True,
            bufsize=1,
        )
        self.pending = {}          # id -> (queue, sent_time)
        self.pending_lock = threading.Lock()
        self.next_id = 1
        self.id_lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.notifications = queue.Queue()
        self.stderr_lines = []
        self.reader = threading.Thread(target=self._read_loop, daemon=True)
        self.reader.start()
        self.err_reader = threading.Thread(target=self._err_loop, daemon=True)
        self.err_reader.start()

    def _err_loop(self):
        for line in self.proc.stderr:
            self.stderr_lines.append(line.rstrip())

    def _send(self, obj):
        data = json.dumps(obj)
        with self.write_lock:
            self.proc.stdin.write(data + "\n")
            self.proc.stdin.flush()

    def _read_loop(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self.notifications.put({"_garbage": line})
                continue
            if "method" in msg and "id" in msg:
                # server -> client request
                self._handle_server_request(msg)
            elif "id" in msg:
                with self.pending_lock:
                    entry = self.pending.pop(msg["id"], None)
                if entry:
                    entry[0].put((time.monotonic(), msg))
            else:
                self.notifications.put(msg)
        # EOF: fail all pending
        with self.pending_lock:
            for rid, (q, _) in self.pending.items():
                q.put((time.monotonic(), {"_eof": True}))
            self.pending.clear()

    def _handle_server_request(self, msg):
        if msg["method"] == "roots/list":
            roots = []
            if self.use_roots:
                uri = "file://" + self.workspace
                roots = [{"uri": uri, "name": os.path.basename(self.workspace)}]
            self._send({"jsonrpc": "2.0", "id": msg["id"],
                        "result": {"roots": roots}})
        elif msg["method"] == "ping":
            self._send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
        else:
            self._send({"jsonrpc": "2.0", "id": msg["id"],
                        "error": {"code": -32601, "message": "unsupported"}})

    def request(self, method, params, timeout=90.0):
        with self.id_lock:
            rid = self.next_id
            self.next_id += 1
        q = queue.Queue()
        sent = time.monotonic()
        with self.pending_lock:
            self.pending[rid] = (q, sent)
        self._send({"jsonrpc": "2.0", "id": rid, "method": method,
                    "params": params})
        try:
            recv, msg = q.get(timeout=timeout)
        except queue.Empty:
            with self.pending_lock:
                self.pending.pop(rid, None)
            return {"_client_timeout": True, "_ms": (time.monotonic() - sent) * 1000}
        msg["_ms"] = (recv - sent) * 1000
        return msg

    def initialize(self):
        caps = {}
        if self.use_roots:
            caps["roots"] = {"listChanged": True}
        result = self.request("initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": caps,
            "clientInfo": {"name": "mcp-replay", "version": "0"},
        }, timeout=30)
        assert "result" in result, f"initialize failed: {result}"
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result

    def call_tool(self, name, arguments, timeout=90.0):
        return self.request("tools/call",
                            {"name": name, "arguments": arguments}, timeout)

    def call_tools_parallel(self, calls, timeout=90.0):
        """calls: list of (name, arguments). Returns list of results in order."""
        results = [None] * len(calls)
        threads = []
        def run(i, name, args):
            results[i] = self.call_tool(name, args, timeout)
        for i, (name, args) in enumerate(calls):
            t = threading.Thread(target=run, args=(i, name, args))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        return results

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def outcome(res):
    """Classify one tools/call result. Returns (kind, detail)."""
    if res.get("_client_timeout"):
        return "CLIENT_TIMEOUT", ""
    if res.get("_eof"):
        return "EOF", "server closed stdout"
    if "error" in res:
        e = res["error"]
        return "RPC_ERROR", f"{e.get('code')}: {e.get('message', '')[:160]}"
    r = res.get("result", {})
    text = ""
    for item in r.get("content", []):
        if item.get("type") == "text":
            text += item.get("text", "")
    lowered = text.lower()
    if r.get("isError"):
        return "TOOL_ERROR", text[:200].replace("\n", " ")
    for marker in ("cancelled", "canceled", "time budget", "wall-clock"):
        if marker in lowered:
            return "PARTIAL_OR_CANCELLED", text[:200].replace("\n", " ")
    return "OK", f"{len(text)} chars"


def report(label, results, calls, budget_ms=5000):
    ok = True
    for (name, _), res in zip(calls, results):
        kind, detail = outcome(res)
        ms = res.get("_ms", 0)
        flag = ""
        if kind != "OK":
            ok = False
            flag = " <-- FAIL"
        elif ms > budget_ms:
            ok = False
            flag = f" <-- SLOW (> {budget_ms} ms)"
        print(f"  [{label}] {name:28s} {ms:8.0f} ms  {kind:20s} {detail}{flag}")
    return ok


# ---------------------------------------------------------------- scenarios

def scenario_i1423(c):
    """Four parallel discovery calls (issue 1423)."""
    calls = [
        ("search_symbols", {"patterns": ["ExternalSemanticSummarySet", "ExternalSummaryCompatibilityKey", "SemanticProcedureSummary", "ExternalSummaryTarget"], "include_tests": True, "limit": 80}),
        ("search_symbols", {"patterns": ["CompiledProcedure", "ProcedureSummar", "SemanticArtifactKey", "SemanticLocator"], "include_tests": True, "limit": 120}),
        ("get_summaries", {"targets": ["crates/bifrost-analysis/src/semantic_model", "crates/bifrost-analysis/src/analyzer/structural"]}),
        ("find_files_containing", {"patterns": ["SemanticProcedureSummary"]}),
    ]
    return report("i1423", c.call_tools_parallel(calls), calls, budget_ms=10000)


def scenario_i1419(c):
    calls = [
        ("search_symbols", {"patterns": ["MatcherIndexes", "ResolvedActiveSemanticModels", "CompiledProcedureSummary", "CompiledProcedureSummaryPayload", "SemanticModelMatch", "RuntimeLimits"], "include_tests": True, "limit": 100}),
        ("get_summaries", {"targets": ["crates/bifrost-analysis/src/semantic_model/runtime.rs", "crates/bifrost-analysis/src/semantic_model/**/*.rs", "crates/bifrost-analysis/tests/**/*semantic*model*.rs"]}),
        ("most_relevant_files", {"seed_file_paths": ["crates/bifrost-analysis/src/semantic_model/runtime.rs"], "limit": 15, "ranking_mode": "history_imports"}),
    ]
    return report("i1419", c.call_tools_parallel(calls), calls, budget_ms=10000)


def scenario_i1411(c):
    calls = [("get_symbol_sources", {"symbols": ["SemanticLocator", "StableLocator", "StableCarrier", "render_carrier"]})]
    return report("i1411", c.call_tools_parallel(calls), calls, budget_ms=6000)


def scenario_i1430(c):
    calls = [
        ("get_symbol_sources", {"symbols": ["src/analyzer/semantic_model/overlay.rs"]}),
        ("get_summaries", {"targets": ["src/analyzer/semantic_model/overlay.rs"]}),
    ]
    results = c.call_tools_parallel(calls)
    # Expectation: both come back promptly as not-found; not a budget blowup.
    ok = True
    for (name, _), res in zip(calls, results):
        kind, detail = outcome(res)
        ms = res.get("_ms", 0)
        prompt = ms < 5000
        bad_budget = "budget" in detail.lower() or kind in ("CLIENT_TIMEOUT", "EOF", "PARTIAL_OR_CANCELLED")
        flag = ""
        if not prompt or bad_budget:
            ok = False
            flag = " <-- FAIL (want prompt not-found)"
        print(f"  [i1430] {name:28s} {ms:8.0f} ms  {kind:20s} {detail[:120]}{flag}")
    return ok


def scenario_i1416(c):
    calls = [("scan_usages_by_location", {"targets": [{"path": "crates/bifrost-analysis/src/analyzer/exception_handling.rs", "line": 163, "column": 15}], "include_tests": True})]
    first = report("i1416", c.call_tools_parallel(calls), calls, budget_ms=8000)
    second = report("i1416-retry", c.call_tools_parallel(calls), calls, budget_ms=8000)
    return first and second


def scenario_i1435(c):
    """Fairness: heavy scan + lightweight source lookup, several iterations."""
    ok = True
    for it in range(6):
        heavy = threading.Thread(target=c.call_tool, args=(
            "scan_usages_by_location",
            {"targets": [{"path": "crates/bifrost-analysis/src/analyzer/exception_handling.rs", "line": 163, "column": 15}], "include_tests": True}, 90))
        heavy.start()
        time.sleep(0.15)
        res = c.call_tool("get_symbol_sources", {"symbols": ["collect_nodes_by_kind"]}, timeout=90)
        kind, detail = outcome(res)
        ms = res.get("_ms", 0)
        flag = ""
        if kind == "RPC_ERROR" and "in-flight" in detail:
            ok = False
            flag = " <-- FAIL (cap rejection)"
        elif kind not in ("OK",):
            ok = False
            flag = " <-- FAIL"
        print(f"  [i1435] iter {it} light get_symbol_sources {ms:8.0f} ms  {kind:20s} {detail[:120]}{flag}")
        heavy.join()
    return ok


def scenario_i1504(c):
    """usage_graph most_relevant_files on self-repo taint seeds (issue 1504)."""
    calls = [("most_relevant_files", {
        "seed_file_paths": [
            "crates/bifrost-analysis/src/analyzer/structural/search/witness_projection.rs",
            "crates/bifrost-analysis/src/analyzer/policy/taint_policy.rs",
            "tests/suite_bench_policy/taint_policy_adapter.rs",
        ],
        "include_tests": True,
        "limit": 20,
        "ranking_mode": "usage_graph",
    })]
    return report("i1504", c.call_tools_parallel(calls, timeout=240.0), calls, budget_ms=5000)


def scenario_i1398(c):
    calls = [("run_policy", {"policy_packs": ["bifrost.code-smells"], "fail_on": "warning", "evaluation_date": time.strftime("%Y-%m-%d")})]
    results = c.call_tools_parallel(calls, timeout=120)
    ok = True
    for (name, _), res in zip(calls, results):
        kind, detail = outcome(res)
        ms = res.get("_ms", 0)
        text = detail
        bad = "unreliable" in text.lower() or kind not in ("OK",)
        flag = " <-- FAIL (unreliable/cancelled)" if bad else ""
        if bad:
            ok = False
        print(f"  [i1398] {name:28s} {ms:8.0f} ms  {kind:20s} {text[:140]}{flag}")
    return ok


def scenario_cancel(c):
    """Fire a heavy scan, cancel it, expect a prompt response and a healthy
    follow-up call. Every request must get exactly one response."""
    ok = True
    with c.id_lock:
        rid = c.next_id
        c.next_id += 1
    q = queue.Queue()
    sent = time.monotonic()
    with c.pending_lock:
        c.pending[rid] = (q, sent)
    c._send({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
             "params": {"name": "scan_usages_by_location", "arguments": {
                 "targets": [{"path": "crates/bifrost-analysis/src/analyzer/exception_handling.rs", "line": 163, "column": 15}],
                 "include_tests": True}}})
    time.sleep(0.3)
    c._send({"jsonrpc": "2.0", "method": "notifications/cancelled",
             "params": {"requestId": rid, "reason": "test cancel"}})
    try:
        recv, msg = q.get(timeout=30)
        ms = (recv - sent) * 1000
        kind, detail = outcome({**msg, "_ms": ms})
        # rmcp swallows the response for a cancelled request per MCP spec;
        # any prompt terminal signal is fine, a hang is not.
        print(f"  [cancel] cancelled scan responded in {ms:.0f} ms  {kind} {detail[:80]}")
        if ms > 15000:
            ok = False
    except queue.Empty:
        with c.pending_lock:
            c.pending.pop(rid, None)
        print("  [cancel] no response within 30s (spec allows swallowing; checking follow-up)")
    res = c.call_tool("get_symbol_sources", {"symbols": ["serial_tool_request"]}, timeout=30)
    kind, detail = outcome(res)
    flag = "" if kind == "OK" else " <-- FAIL"
    if kind != "OK":
        ok = False
    print(f"  [cancel] follow-up get_symbol_sources {res.get('_ms', 0):8.0f} ms  {kind} {detail[:80]}{flag}")
    return ok


def scenario_storm(c):
    """16 mixed parallel calls: every request must receive exactly one
    response (success, tool error, or cap rejection) -- no hangs, no losses."""
    calls = []
    for i in range(4):
        calls.append(("search_symbols", {"patterns": [f"McpServerSpec"], "limit": 5}))
        calls.append(("get_symbol_sources", {"symbols": ["serial_tool_request"]}))
        calls.append(("get_symbol_locations", {"symbols": ["McpServerSpec"]}))
        calls.append(("get_summaries", {"targets": ["crates/bifrost-mcp/src/rmcp_host.rs"]}))
    results = c.call_tools_parallel(calls, timeout=60)
    ok = True
    counts = {}
    for (name, _), res in zip(calls, results):
        kind, detail = outcome(res)
        counts[kind] = counts.get(kind, 0) + 1
        if kind in ("CLIENT_TIMEOUT", "EOF"):
            ok = False
            print(f"  [storm] {name}: {kind} <-- FAIL")
    print(f"  [storm] outcome counts: {counts}")
    return ok


def scenario_roots_change(c):
    """Notify a roots change mid-session; later calls must still be served
    against the (re-negotiated) workspace."""
    res = c.call_tool("get_symbol_sources", {"symbols": ["serial_tool_request"]}, timeout=60)
    kind, _ = outcome(res)
    ok = kind == "OK"
    print(f"  [roots] before change: {kind}")
    c._send({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"})
    time.sleep(0.2)
    res = c.call_tool("get_symbol_sources", {"symbols": ["serial_tool_request"]}, timeout=120)
    kind, detail = outcome(res)
    if kind != "OK":
        ok = False
    print(f"  [roots] after change: {res.get('_ms', 0):8.0f} ms {kind} {detail[:100]}{'' if kind == 'OK' else ' <-- FAIL'}")
    return ok


def scenario_smoke(c):
    calls = [
        ("most_relevant_files", {"seed_file_paths": ["crates/bifrost-mcp/src/rmcp_host.rs"], "limit": 5}),
        ("search_symbols", {"patterns": ["McpServerSpec"], "limit": 10}),
        ("get_symbol_sources", {"symbols": ["serial_tool_request"]}),
        ("get_symbol_locations", {"symbols": ["serial_tool_request"]}),
    ]
    return report("smoke", c.call_tools_parallel(calls), calls, budget_ms=10000)


def scenario_cold(c):
    """Immediately fire the i1423 batch with no warmup. Expect complete
    results (the initial index build must not be billed to these requests),
    even if the batch takes as long as the build."""
    calls = [
        ("search_symbols", {"patterns": ["ExternalSemanticSummarySet", "SemanticProcedureSummary"], "include_tests": True, "limit": 80}),
        ("get_summaries", {"targets": ["crates/bifrost-analysis/src/semantic_model"]}),
        ("find_files_containing", {"patterns": ["SemanticProcedureSummary"]}),
        ("get_symbol_sources", {"symbols": ["serial_tool_request"]}),
    ]
    return report("cold", c.call_tools_parallel(calls, timeout=180), calls, budget_ms=90000)


COVERAGE_ARGS = {
    "search_symbols": {"patterns": ["McpServerSpec"], "limit": 5},
    "get_symbol_sources": {"symbols": ["serial_tool_request"]},
    "get_summaries": {"targets": ["crates/bifrost-mcp/src/rmcp_host.rs"]},
    "most_relevant_files": {"seed_file_paths": ["crates/bifrost-mcp/src/rmcp_host.rs"], "limit": 5},
    "scan_usages_by_location": {"targets": [{"path": "crates/bifrost-mcp/src/mcp_common.rs", "line": 654, "column": 15}]},
    "scan_usages_by_reference": {"symbols": ["serial_tool_request"]},
    "get_symbol_locations": {"symbols": ["serial_tool_request"]},
    "get_declarations_by_location": {"references": [{"path": "crates/bifrost-mcp/src/mcp_common.rs", "line": 654}]},
    "get_definitions_by_location": {"references": [{"path": "crates/bifrost-mcp/src/mcp_common.rs", "line": 643, "column": 12}]},
    "get_type_by_location": {"references": [{"path": "crates/bifrost-mcp/src/mcp_common.rs", "line": 643, "column": 12}]},
    "get_symbol_ancestors": {"symbols": ["McpServerSpec"]},
    "usage_graph": {"paths": ["crates/bifrost-mcp/src/mcp_registry.rs"]},
    "query_code": {"match": {"kind": "function", "name": "serial_tool_request"}},
    "get_active_workspace": {},
    "list_policies": {},
    "search_git_commit_messages": {"pattern": "rmcp", "limit": 3},
    "get_git_log": {"limit": 3},
    "get_commit_diff": {"revision": "HEAD"},
    "get_summaries_pack": None,
    "rename_symbol": None,          # mutating: skip
    "activate_workspace": None,     # serial/mutating: skip
    "refresh": None,
    "update_paths": None,
    "run_policy": None,             # covered by i1398
}


def scenario_coverage(c):
    listing = c.request("tools/list", {}, timeout=30)
    tools = [t["name"] for t in listing.get("result", {}).get("tools", [])]
    print(f"  [coverage] {len(tools)} tools advertised: {sorted(tools)}")
    ok = True
    for name in sorted(tools):
        if name not in COVERAGE_ARGS:
            print(f"  [coverage] {name}: NO SMOKE ARGS DEFINED <-- add to harness")
            continue
        args = COVERAGE_ARGS[name]
        if args is None:
            continue
        res = c.call_tool(name, args, timeout=60)
        kind, detail = outcome(res)
        flag = ""
        if kind not in ("OK",):
            ok = False
            flag = " <-- FAIL"
        print(f"  [coverage] {name:28s} {res.get('_ms', 0):7.0f} ms  {kind:18s} {detail[:90]}{flag}")
    return ok


SCENARIOS = {
    "coverage": scenario_coverage,
    "cold": scenario_cold,
    "cancel": scenario_cancel,
    "storm": scenario_storm,
    "roots_change": scenario_roots_change,
    "smoke": scenario_smoke,
    "i1423": scenario_i1423,
    "i1419": scenario_i1419,
    "i1411": scenario_i1411,
    "i1430": scenario_i1430,
    "i1416": scenario_i1416,
    "i1435": scenario_i1435,
    "i1398": scenario_i1398,
    "i1504": scenario_i1504,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--stack", choices=["rmcp", "legacy"], default="rmcp")
    ap.add_argument("--mode", default="symbol|extended")
    ap.add_argument("--no-roots", action="store_true")
    ap.add_argument("--scenario", action="append", default=None)
    ap.add_argument("--warm", action="store_true",
                    help="run a smoke batch first to warm the analyzer, untimed")
    ap.add_argument("--budget-secs", default=None,
                    help="set BIFROST_MCP_REQUEST_BUDGET_SECS for the server")
    args = ap.parse_args()
    if args.budget_secs:
        os.environ["BIFROST_MCP_REQUEST_BUDGET_SECS"] = args.budget_secs

    names = args.scenario or list(SCENARIOS)
    client = McpClient(args.binary, args.workspace, args.stack, args.mode,
                       use_roots=not args.no_roots)
    try:
        init = client.initialize()
        server = init["result"].get("serverInfo", {})
        print(f"stack={args.stack} server={server.get('name')} {server.get('version')} roots={not args.no_roots}")
        if args.warm:
            t0 = time.monotonic()
            client.call_tool("search_symbols", {"patterns": ["warmup_nonexistent_zzz"], "limit": 1}, timeout=300)
            print(f"warmup finished in {(time.monotonic()-t0)*1000:.0f} ms")
        failures = []
        for name in names:
            print(f"-- scenario {name}")
            t0 = time.monotonic()
            ok = SCENARIOS[name](client)
            print(f"   scenario {name}: {'PASS' if ok else 'FAIL'} ({(time.monotonic()-t0):.1f}s)")
            if not ok:
                failures.append(name)
        print("== SUMMARY:", "ALL PASS" if not failures else f"FAILED: {', '.join(failures)}")
        stderr_path = os.environ.get("MCP_REPLAY_STDERR_FILE")
        if stderr_path:
            with open(stderr_path, "w") as fh:
                fh.write("\n".join(client.stderr_lines))
            print(f"== stderr written to {stderr_path} ({len(client.stderr_lines)} lines)")
        elif client.stderr_lines:
            print("== stderr (last 30 lines):")
            for line in client.stderr_lines[-30:]:
                print("   ", line)
        return 1 if failures else 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
