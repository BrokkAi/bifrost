# /// script
# requires-python = ">=3.10"
# dependencies = ["onnx>=1.16", "onnxruntime>=1.20", "numpy"]
# ///
"""Shrink ModernBERT-style ONNX exports by restructuring attention masks.

The onnx-community ModernBERT exports (granite-embedding-r2, gte-modernbert
rerankers) materialize attention bias at full per-head size: the padding mask
is expanded to (batch, 1, seq, seq), `Tile`d across all heads to
(batch, num_heads, seq, seq), and the sliding-window mask is derived from the
*tiled* tensor — ~6.4 GB of masks per batch item at 8k tokens before any
attention math.

The obvious fix (drop the Tile, let `com.microsoft.MultiHeadAttention`
broadcast the head dim) is NOT safe on ONNX Runtime 1.20 (bundled by
ort 2.0.0-rc.9): its CPU kernel computes the batch stride of a
(batch, 1, S, T) attention_bias as `batch * num_heads * S * T`, reading out
of bounds for every batch row past the first — silent garbage or SIGSEGV.
Shapes (1, 1, S, T), (1, H, S, T) and (B, H, S, T) are handled correctly.

So instead this script rewrites the graph to avoid per-batch bias entirely:

  - padding moves to MHA's `key_padding_mask` input — the original 2D
    (batch, seq) int mask, the kernel's oldest and best-tested path;
  - the sliding-window band becomes a single batch- and head-broadcast
    (1, 1, S, S) attention_bias shared by the local-attention layers,
    which ORT 1.20 indexes correctly (offset 0).

Output parity against the original graph is verified via onnxruntime before
writing a `<stem>.bifrost-opt.onnx` sibling, which bifrost's model resolution
prefers automatically when present. NOTE: the bundled Python onnxruntime is
newer than ort's; always re-verify through the Rust probe
(`BIFROST_PROBE_BATCH_LENS` + `BIFROST_PROBE_DUMP_VECTORS`) so the production
runtime is the one exercised.

Usage:
    uv run scripts/optimize_onnx_attention.py <model.onnx> [more models...]
    uv run scripts/optimize_onnx_attention.py --bench <model.onnx>

--bench additionally embeds a single max-length (8192-token) input with the
original and optimized graphs in separate subprocesses and reports peak RSS.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np
import onnx

NEG_INF = -3.4028234663852886e38


def optimized_path(model_path: Path) -> Path:
    return model_path.with_name(model_path.stem + ".bifrost-opt.onnx")


def load_model(model_path: Path) -> onnx.ModelProto:
    """Load a model, dereferencing HF-cache symlinks that onnx rejects for
    external data, and folding any external data into the proto so the
    optimized output is a single self-contained file."""
    data = model_path.with_name(model_path.name + "_data")
    if not data.exists():
        return onnx.load(str(model_path))
    with tempfile.TemporaryDirectory() as tmp:
        tmp_model = Path(tmp) / model_path.name
        shutil.copyfile(model_path, tmp_model)
        shutil.copyfile(data, Path(tmp) / data.name)
        model = onnx.load(str(tmp_model))
    onnx.external_data_helper.convert_model_from_external_data(model)
    return model


def reaches_greater(name: str, producers: dict[str, onnx.NodeProto]) -> bool:
    """True when `name`'s producer chain contains a Greater node — the
    sliding-window distance test, marking a local-attention bias."""
    stack, seen = [name], set()
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        node = producers.get(current)
        if node is None:
            continue
        if node.op_type == "Greater":
            return True
        stack.extend(node.input)
    return False


def to_key_padding_mask(model: onnx.ModelProto) -> int:
    """Rewire every MultiHeadAttention from per-batch attention_bias to
    key_padding_mask (+ a shared (1,1,S,S) window bias for local layers).

    Returns the number of MHA nodes rewired (0 when the pattern is absent).
    """
    graph = model.graph
    producers = {output: node for node in graph.node for output in node.output}
    mha_nodes = [
        node
        for node in graph.node
        if node.op_type == "MultiHeadAttention"
        and len(node.input) > 5
        and node.input[5]
    ]
    if not mha_nodes:
        return 0

    mask_input = next(
        (i.name for i in graph.input if "attention_mask" in i.name), None
    )
    if mask_input is None:
        return 0

    local_biases = {
        node.input[5]
        for node in mha_nodes
        if reaches_greater(node.input[5], producers)
    }

    # Padding mask: Cast the (batch, seq) graph input to int32 once.
    key_padding = "bifrost_key_padding_mask"
    cast_node = onnx.helper.make_node(
        "Cast",
        inputs=[mask_input],
        outputs=[key_padding],
        name="bifrost/key_padding_cast",
        to=onnx.TensorProto.INT32,
    )
    graph.node.insert(0, cast_node)

    window_bias = ""
    if local_biases:
        # The window condition (1,1,S,S bool) already exists: it is input 0 of
        # the Where that combined it with the padded global mask.
        some_local = next(iter(local_biases))
        local_where = producers[some_local]
        if local_where.op_type != "Where":
            raise SystemExit(
                f"unexpected local mask producer {local_where.op_type}; "
                "graph layout not recognized"
            )
        window_cond = local_where.input[0]
        window_bias = "bifrost_window_bias"
        neg_inf = onnx.helper.make_node(
            "Constant",
            inputs=[],
            outputs=["bifrost_neg_inf"],
            name="bifrost/neg_inf",
            value=onnx.numpy_helper.from_array(
                np.array(NEG_INF, dtype=np.float32), "bifrost_neg_inf_value"
            ),
        )
        zero = onnx.helper.make_node(
            "Constant",
            inputs=[],
            outputs=["bifrost_zero"],
            name="bifrost/zero",
            value=onnx.numpy_helper.from_array(
                np.array(0.0, dtype=np.float32), "bifrost_zero_value"
            ),
        )
        where = onnx.helper.make_node(
            "Where",
            inputs=[window_cond, "bifrost_neg_inf", "bifrost_zero"],
            outputs=[window_bias],
            name="bifrost/window_bias",
        )
        # Insert after the window condition's producer to keep topo order.
        cond_index = next(
            i for i, n in enumerate(graph.node) if window_cond in n.output
        )
        for offset, node in enumerate([neg_inf, zero, where], start=1):
            graph.node.insert(cond_index + offset, node)

    for node in mha_nodes:
        node.input[4] = key_padding
        node.input[5] = window_bias if node.input[5] in local_biases else ""

    prune_dead_nodes(graph)
    return len(mha_nodes)


def prune_dead_nodes(graph: onnx.GraphProto) -> None:
    """Drop nodes (and initializers/value_info) not reachable from outputs."""
    producers = {output: node for node in graph.node for output in node.output}
    needed: set[str] = set()
    stack = [output.name for output in graph.output]
    while stack:
        name = stack.pop()
        if not name or name in needed:
            continue
        needed.add(name)
        node = producers.get(name)
        if node is not None:
            stack.extend(node.input)
    for node in [n for n in graph.node if not any(o in needed for o in n.output)]:
        graph.node.remove(node)
    used = {name for node in graph.node for name in node.input}
    for init in [i for i in graph.initializer if i.name not in used]:
        graph.initializer.remove(init)
    alive = used | {output for node in graph.node for output in node.output}
    for info in [v for v in graph.value_info if v.name not in alive]:
        graph.value_info.remove(info)


def session(path: Path):
    import onnxruntime as ort

    options = ort.SessionOptions()
    return ort.InferenceSession(str(path), options, providers=["CPUExecutionProvider"])


def random_inputs(
    batch: int, seq: int, vocab: int, seed: int, padded: bool
) -> dict[str, np.ndarray]:
    rng = np.random.default_rng(seed)
    input_ids = rng.integers(1, vocab, size=(batch, seq), dtype=np.int64)
    attention_mask = np.ones((batch, seq), dtype=np.int64)
    if padded:
        # Give later rows trailing padding so the padding mask is exercised.
        for row in range(1, batch):
            attention_mask[row, seq - row * (seq // (batch + 1)) :] = 0
    return {"input_ids": input_ids, "attention_mask": attention_mask}


def is_quantized(model: onnx.ModelProto) -> bool:
    quant_ops = {"DynamicQuantizeLinear", "MatMulInteger", "QLinearMatMul"}
    return any(node.op_type in quant_ops for node in model.graph.node)


def pooled_output(outs: list[np.ndarray], valid: np.ndarray) -> np.ndarray:
    for out in outs:
        if out.ndim == 2:
            return out
    hidden = outs[0]
    weights = valid[..., None].astype(hidden.dtype)
    return (hidden * weights).sum(axis=1) / weights.sum(axis=1)


def row_cosine(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    norm = np.linalg.norm(left, axis=-1) * np.linalg.norm(right, axis=-1)
    return (left * right).sum(axis=-1) / norm


def verify_parity(original: Path, optimized: Path, quantized: bool) -> None:
    base = session(original)
    opt = session(optimized)
    vocab = 30000

    # Without padding the rewrite is a no-op (all-ones key_padding_mask adds
    # zeros; the window bias values are unchanged), so outputs must match
    # exactly — for quantized models too. Lengths cross the sliding window.
    for batch, seq in [(1, 16), (2, 96), (1, 300), (2, 2100)]:
        feeds = random_inputs(batch, seq, vocab, seed=batch * 1000 + seq, padded=False)
        for left, right in zip(base.run(None, feeds), opt.run(None, feeds)):
            diff = float(np.max(np.abs(left - right)))
            if diff > 1e-4:
                raise SystemExit(
                    f"parity FAILED for {optimized.name} (unpadded) at "
                    f"batch={batch} seq={seq}: max abs diff {diff}"
                )
        print(f"  parity ok (unpadded) at batch={batch} seq={seq}")

    # With padding, fully-padded query rows attend to different (equally
    # meaningless) key sets in the two graphs. fp32 confines that garbage to
    # the padded rows, which pooling discards — so valid positions must still
    # match. Dynamic quantization, however, folds the garbage into batch-wide
    # activation ranges, so quantized outputs legitimately differ; there we
    # require the rewrite to stay at least as close to the fp32 sibling as
    # the original quantized graph was.
    fp32_sibling = original.with_name("model.onnx")
    fp32 = (
        session(fp32_sibling) if quantized and fp32_sibling.is_file() else None
    )
    for batch, seq in [(2, 96), (3, 300), (4, 2100)]:
        feeds = random_inputs(batch, seq, vocab, seed=batch * 1000 + seq, padded=True)
        valid = feeds["attention_mask"].astype(bool)
        base_outs = base.run(None, feeds)
        opt_outs = opt.run(None, feeds)
        if not quantized:
            for left, right in zip(base_outs, opt_outs):
                if left.ndim == 3 and left.shape[:2] == valid.shape:
                    left, right = left[valid], right[valid]
                diff = float(np.max(np.abs(left - right)))
                if diff > 1e-4:
                    raise SystemExit(
                        f"parity FAILED for {optimized.name} (padded) at "
                        f"batch={batch} seq={seq}: max abs diff {diff}"
                    )
            print(f"  parity ok (padded) at batch={batch} seq={seq}")
        elif fp32 is not None:
            truth = pooled_output(fp32.run(None, feeds), valid)
            base_cos = row_cosine(pooled_output(base_outs, valid), truth)
            opt_cos = row_cosine(pooled_output(opt_outs, valid), truth)
            if np.any(opt_cos < base_cos - 0.02):
                raise SystemExit(
                    f"quantized quality regressed for {optimized.name} at "
                    f"batch={batch} seq={seq}: cos vs fp32 {opt_cos} "
                    f"(original {base_cos})"
                )
            print(
                f"  quantized ok (padded) at batch={batch} seq={seq}: "
                f"cos vs fp32 {np.round(opt_cos, 4)} (original {np.round(base_cos, 4)})"
            )
        else:
            cos = row_cosine(
                pooled_output(opt_outs, valid), pooled_output(base_outs, valid)
            )
            if np.any(cos < 0.9):
                raise SystemExit(
                    f"padded outputs diverged for {optimized.name} at "
                    f"batch={batch} seq={seq}: cos {cos}"
                )
            print(f"  quantized ok (padded, no fp32 sibling): cos {np.round(cos, 4)}")


def bench_peak_rss(model_path: Path, seq: int = 8192) -> float:
    """Run one long-sequence inference in a subprocess, return peak RSS in GiB."""
    program = f"""
import json, resource, sys
import numpy as np
import onnxruntime as ort
session = ort.InferenceSession({str(model_path)!r}, providers=["CPUExecutionProvider"])
rng = np.random.default_rng(0)
feeds = {{
    "input_ids": rng.integers(1, 30000, size=(1, {seq}), dtype=np.int64),
    "attention_mask": np.ones((1, {seq}), dtype=np.int64),
}}
session.run(None, feeds)
peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps(peak_kb))
"""
    result = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout.strip().splitlines()[-1]) / (1024 * 1024)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("models", nargs="+", type=Path)
    parser.add_argument("--bench", action="store_true", help="report peak RSS at 8k tokens")
    args = parser.parse_args()

    for model_path in args.models:
        print(f"{model_path}:")
        model = load_model(model_path)
        rewired = to_key_padding_mask(model)
        if rewired == 0:
            print("  no MultiHeadAttention bias pattern found; skipping")
            continue
        print(f"  rewired {rewired} MultiHeadAttention node(s) to key_padding_mask")
        onnx.checker.check_model(model)
        out_path = optimized_path(model_path)
        onnx.save(model, str(out_path))
        verify_parity(model_path, out_path, quantized=is_quantized(model))
        print(f"  wrote {out_path}")
        if args.bench:
            base_rss = bench_peak_rss(model_path)
            opt_rss = bench_peak_rss(out_path)
            print(f"  peak RSS at 8192 tokens: {base_rss:.2f} GiB -> {opt_rss:.2f} GiB")


if __name__ == "__main__":
    main()
