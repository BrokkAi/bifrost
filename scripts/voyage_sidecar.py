# /// script
# requires-python = ">=3.10"
# dependencies = ["torch>=2.5", "transformers>=4.53", "numpy"]
# ///
"""voyage-4-nano embedding sidecar — one process per GPU, fused (SDPA) attention.

bifrost's Rust side spawns this behind the Embedder seam (one per CUDA device, pinned
via CUDA_VISIBLE_DEVICES) and talks a small binary protocol over stdin/stdout:

  request  : u32_le length + JSON {"kind": "passage"|"query", "texts": [str, ...]}
  response : u32_le length + [u32_le n][u32_le dim] + n*dim float32 (little-endian)

After model load it emits one ready frame: JSON {"ready": true, "dim": 512}.
fd 1 is redirected to stderr so library logging can't corrupt the protocol; frames go
to a dup'd copy of the real stdout.

Attention is fused: weights and the Qwen block forward path come from HF, but the
sidecar registers a custom attention implementation. K/V are explicitly repeated to
full head count on every backend before SDPA. This matters on CUDA: with an additive
padding mask, `enable_gqa=True` makes both the flash and mem-efficient kernels
ineligible, so SDPA silently falls back to the math kernel, which materializes the
full (batch, heads, seq, seq) score tensor — tens of GB at 8k tokens, paging to host
memory under WSL and running ~100x slower. Repeated K/V with the mask keeps the
mem-efficient kernel eligible. MPS additionally blocks queries for long sequences,
because PyTorch's full-prompt MPS SDPA path otherwise materializes/caches large
score tensors. SDPA only fuses in fp16/bf16, so we run bf16 on CUDA and fp16 on
Apple Metal (MPS); CPU falls back to fp32 (math kernel).

Run the sidecar:   uv run scripts/voyage_sidecar.py
Self-test parity:  uv run scripts/voyage_sidecar.py --selftest
"""

from __future__ import annotations

import json
import os
import struct
import sys
import time

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

MODEL_ID = "voyageai/voyage-4-nano"
OUT_DIM = 512
MAX_SEQ = 8192
MPS_SDPA_QUERY_BLOCK = 512
MPS_CACHE_DRAIN_FRACTION = 0.80
# Max padded tokens (batch * longest_seq) per forward — bounds activation memory so a
# few long chunks can't balloon a batch. Mem-efficient SDPA lets this exceed candle's.
PADDED_TOKEN_BUDGET = 16384
PASSAGE_PREFIX = "Represent the document for retrieval: "
QUERY_PREFIX = "Represent the query for retrieving supporting documents: "


def log(*a):
    print("[sidecar]", *a, file=sys.stderr, flush=True)


def repeat_kv(hidden_states: torch.Tensor, n_rep: int) -> torch.Tensor:
    """Equivalent to HF repeat_kv, kept local so direct attention avoids HF dispatch."""
    batch, num_key_value_heads, seq, head_dim = hidden_states.shape
    if n_rep == 1:
        return hidden_states
    hidden_states = hidden_states[:, :, None, :, :].expand(
        batch, num_key_value_heads, n_rep, seq, head_dim
    )
    return hidden_states.reshape(batch, num_key_value_heads * n_rep, seq, head_dim)


def _slice_attention_mask(mask: torch.Tensor | None, start: int, end: int) -> torch.Tensor | None:
    if mask is None or mask.dim() < 4 or mask.shape[-2] == 1:
        return mask
    return mask[..., start:end, :]


def _mps_blocked_sdpa(
    query: torch.Tensor,
    key: torch.Tensor,
    value: torch.Tensor,
    attention_mask: torch.Tensor | None,
    scaling: float,
) -> torch.Tensor:
    q_len = query.shape[2]
    if q_len <= MPS_SDPA_QUERY_BLOCK:
        return F.scaled_dot_product_attention(
            query,
            key,
            value,
            attn_mask=attention_mask,
            dropout_p=0.0,
            scale=scaling,
            is_causal=False,
        )

    chunks = []
    for start in range(0, q_len, MPS_SDPA_QUERY_BLOCK):
        end = min(start + MPS_SDPA_QUERY_BLOCK, q_len)
        chunks.append(
            F.scaled_dot_product_attention(
                query[:, :, start:end, :],
                key,
                value,
                attn_mask=_slice_attention_mask(attention_mask, start, end),
                dropout_p=0.0,
                scale=scaling,
                is_causal=False,
            )
        )
    return torch.cat(chunks, dim=2)


def bifrost_attention_forward(
    module: nn.Module,
    query: torch.Tensor,
    key: torch.Tensor,
    value: torch.Tensor,
    attention_mask: torch.Tensor | None,
    dropout: float = 0.0,
    scaling: float | None = None,
    is_causal: bool | None = None,
    **kwargs,
) -> tuple[torch.Tensor, None]:
    if dropout != 0.0:
        raise RuntimeError("voyage sidecar attention is inference-only; dropout must be zero")
    scaling = scaling if scaling is not None else getattr(module, "scaling", None)

    # Repeat K/V to full head count on every backend. Never pass enable_gqa: with an
    # additive mask it disqualifies flash AND mem-efficient, silently dropping CUDA to
    # the math kernel (full seq x seq scores; ~100x slower and tens of GB at 8k tokens).
    if hasattr(module, "num_key_value_groups"):
        key = repeat_kv(key, module.num_key_value_groups)
        value = repeat_kv(value, module.num_key_value_groups)
    if query.device.type == "mps":
        attn_output = _mps_blocked_sdpa(query, key, value, attention_mask, scaling)
    else:
        attn_output = F.scaled_dot_product_attention(
            query,
            key,
            value,
            attn_mask=attention_mask,
            dropout_p=0.0,
            scale=scaling,
            is_causal=False,
        )

    return attn_output.transpose(1, 2).contiguous(), None


class Embedder:
    def __init__(self) -> None:
        from transformers import AutoModel, AutoTokenizer
        from transformers.modeling_utils import ALL_ATTENTION_FUNCTIONS

        # Device priority: CUDA -> Apple Metal (MPS) -> CPU. SDPA only fuses in fp16/bf16;
        # bf16 is the model's native dtype on CUDA, while MPS bf16 support is partial across
        # torch/macOS versions, so MPS uses fp16 (still a fused mem-efficient SDPA kernel).
        self.cuda = torch.cuda.is_available()
        self.mps = (not self.cuda) and torch.backends.mps.is_available()
        if self.cuda:
            self.device, self.dtype = torch.device("cuda:0"), torch.bfloat16
        elif self.mps:
            self.device, self.dtype = torch.device("mps"), torch.float16
        else:
            self.device, self.dtype = torch.device("cpu"), torch.float32
        log(f"loading {MODEL_ID} on {self.device} ({self.dtype})")
        model = AutoModel.from_pretrained(MODEL_ID, trust_remote_code=True, dtype=self.dtype,
                                          attn_implementation="sdpa").eval()
        # WSL CUDA context creation can transiently fail ("CUDA driver error: unknown
        # error") when spawned under load; retry a few times before giving up.
        import time
        for attempt in range(5):
            try:
                self.model = model.to(self.device)
                break
            except RuntimeError as e:
                if not self.cuda or "CUDA" not in str(e) or attempt == 4:
                    raise
                log(f"CUDA init failed (attempt {attempt + 1}): {e}; retrying")
                torch.cuda.empty_cache()
                time.sleep(2.0)
        ALL_ATTENTION_FUNCTIONS.register("bifrost_sdpa", bifrost_attention_forward)
        self.model.config._attn_implementation = "bifrost_sdpa"
        self.model.model.config._attn_implementation = "bifrost_sdpa"
        self.tok = AutoTokenizer.from_pretrained(MODEL_ID)
        layer_types = self.model.model.config.layer_types[: self.model.model.config.num_hidden_layers]
        if any(t != "full_attention" for t in layer_types):
            raise RuntimeError(f"voyage sidecar only supports full attention layers: {layer_types}")
        # Enable the fused SDPA kernels (CUDA only; MPS selects its own fused kernel).
        if self.cuda:
            torch.backends.cuda.enable_flash_sdp(True)
            torch.backends.cuda.enable_mem_efficient_sdp(True)
            torch.backends.cuda.enable_math_sdp(True)

        # Optional embed profiling (BIFROST_SIDECAR_PROFILE=1): tokenize vs GPU-forward
        # time and actual batch sizes, to tell whether embed is overhead- or GPU-bound.
        self._prof = os.environ.get("BIFROST_SIDECAR_PROFILE") == "1"
        self._tok_s = self._fwd_s = 0.0
        self._n_texts = self._n_calls = self._n_batches = self._sum_b = self._max_b = 0
        self._t_report = time.time()

    def _maybe_report(self) -> None:
        now = time.time()
        if now - self._t_report < 20:
            return
        self._t_report = now
        log(f"PROF texts={self._n_texts} calls={self._n_calls} batches={self._n_batches} "
            f"avg_texts/call={self._n_texts / max(self._n_calls, 1):.1f} "
            f"avg_batch={self._sum_b / max(self._n_batches, 1):.1f} max_batch={self._max_b} "
            f"tok_s={self._tok_s:.1f} fwd_s={self._fwd_s:.1f}")

    @torch.no_grad()
    def embed(self, texts: list[str], prefix: str) -> np.ndarray:
        # Tokenize ONCE (no padding), then length-bucket and pad each sub-batch from the
        # cached ids — avoids a second tokenization pass over every chunk. Bucketing
        # bounds padded tokens (b*seq) per forward so a few long chunks can't balloon a
        # batch. Process short->long.
        prefixed = [prefix + t for t in texts]
        _t = time.time()
        encoded = self.tok(prefixed, truncation=True, max_length=MAX_SEQ)["input_ids"]
        if self._prof:
            self._tok_s += time.time() - _t
            self._n_calls += 1
            self._n_texts += len(texts)
        lens = [len(e) for e in encoded]
        order = sorted(range(len(texts)), key=lambda i: lens[i])
        out: list[np.ndarray | None] = [None] * len(texts)

        batch: list[int] = []
        bmax = 0
        for i in order:
            new_max = max(bmax, lens[i])
            if batch and (len(batch) + 1) * new_max > PADDED_TOKEN_BUDGET:
                self._run_batch([encoded[j] for j in batch], batch, out)
                batch, bmax = [], 0
            batch.append(i)
            bmax = max(bmax, lens[i])
        self._run_batch([encoded[j] for j in batch], batch, out)
        if self._prof:
            self._maybe_report()
        return np.stack(out)  # type: ignore[arg-type]

    @torch.no_grad()
    def _run_batch(self, id_lists: list[list[int]], idxs: list[int], out: list) -> None:
        if not id_lists:
            return
        _t = time.time()
        b = len(id_lists)
        maxlen = max(len(x) for x in id_lists)
        pad_id = self.tok.pad_token_id or 0
        input_ids = torch.full((b, maxlen), pad_id, dtype=torch.long)
        attention_mask = torch.zeros((b, maxlen), dtype=torch.long)
        for row, ids in enumerate(id_lists):
            input_ids[row, : len(ids)] = torch.tensor(ids, dtype=torch.long)
            attention_mask[row, : len(ids)] = 1
        input_ids = input_ids.to(self.device)
        attention_mask = attention_mask.to(self.device)

        inner = self.model.model  # Qwen3Model
        embeds = inner.embed_tokens(input_ids)
        # Pass an explicit full-attention mask mapping so HF Qwen does not synthesize a
        # causal mask. The registered attention implementation handles MPS query blocking.
        min_val = torch.finfo(self.dtype).min
        key_valid = attention_mask[:, None, None, :].to(torch.bool)
        attention_bias = torch.zeros_like(key_valid, dtype=self.dtype).masked_fill(~key_valid, min_val)
        o = inner(inputs_embeds=embeds, attention_mask={"full_attention": attention_bias}, use_cache=False)
        hidden = self.model.linear(o.last_hidden_state)

        m = attention_mask[:, :, None].to(dtype=self.dtype)
        pooled = (hidden * m).sum(1) / m.sum(1)        # masked mean -> (b,2048)
        v = pooled[:, :OUT_DIM].float()                 # MRL truncate, then fp32
        v = v / (v.norm(dim=-1, keepdim=True) + 1e-12)  # renorm
        vecs = v.cpu().numpy().astype(np.float32)
        for j, i in enumerate(idxs):
            out[i] = vecs[j]
        if self.mps:
            del input_ids, attention_mask, attention_bias, hidden, m, pooled, v
            if torch.mps.driver_allocated_memory() > MPS_CACHE_DRAIN_FRACTION * torch.mps.recommended_max_memory():
                torch.mps.empty_cache()
        if self._prof:
            self._fwd_s += time.time() - _t
            self._n_batches += 1
            self._sum_b += b
            self._max_b = max(self._max_b, b)


def start_parent_watchdog() -> None:
    """Exit as soon as the parent's stdin pipe goes away, even mid model load.

    The sidecar's process group (led by `uv run`) survives the parent dying without
    running destructors (SIGKILL, process exit with the indexer thread parked).
    Without this, an orphan finishes a minutes-long model load or forward holding
    GPU memory, then dies on BrokenPipeError at the next protocol write.
    POLLHUP/POLLERR on stdin is the only reliable parent-death signal here: `uv run`
    stays alive as our direct parent, so getppid() never changes. Kill the whole
    group, not just this process — `uv` does not reliably exit when its child dies,
    and a lingering launcher would leak one process per respawn.
    """
    if os.name != "posix":
        return
    import select
    import signal
    import threading

    def watch() -> None:
        poller = select.poll()
        poller.register(0, 0)  # eventmask 0: only POLLHUP/POLLERR/POLLNVAL, no POLLIN wakeups
        while True:
            for _fd, event in poller.poll(2000):
                if event & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
                    log("parent pipe closed; killing process group")
                    os.killpg(0, signal.SIGKILL)

    threading.Thread(target=watch, name="parent-watchdog", daemon=True).start()


def _read_exact(stream, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def serve(emb: Embedder) -> None:
    proto_fd = os.dup(1)   # real stdout for protocol frames
    os.dup2(2, 1)          # fd1 -> stderr so logging can't corrupt the channel
    stdin = sys.stdin.buffer

    def send(payload: bytes) -> None:
        try:
            os.write(proto_fd, struct.pack("<I", len(payload)) + payload)
        except BrokenPipeError:
            log("protocol pipe closed; killing process group")
            import signal

            os.killpg(0, signal.SIGKILL)

    send(json.dumps({"ready": True, "dim": OUT_DIM}).encode())
    log("ready")

    while True:
        head = _read_exact(stdin, 4)
        if head is None:
            log("stdin closed; exiting")
            return
        (rlen,) = struct.unpack("<I", head)
        body = _read_exact(stdin, rlen)
        if body is None:
            return
        req = json.loads(body)
        prefix = QUERY_PREFIX if req.get("kind") == "query" else PASSAGE_PREFIX
        vecs = emb.embed(req["texts"], prefix)
        n, dim = vecs.shape
        send(struct.pack("<II", n, dim) + vecs.tobytes())


def selftest(emb: Embedder) -> None:
    # scripts/voyage_sidecar.py -> repo root -> tests/fixtures (works on any checkout/OS).
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ref_path = os.path.join(repo_root, "tests", "fixtures", "voyage_parity_ref.json")
    with open(ref_path) as f:
        ref = json.load(f)
    worst = 1.0
    for kind, prefix in [("docs", PASSAGE_PREFIX), ("queries", QUERY_PREFIX)]:
        texts = list(ref[kind].keys())
        got = emb.embed(texts, prefix)
        for t, g in zip(texts, got):
            e = np.array(ref[kind][t], dtype=np.float32)
            cos = float(np.dot(g, e) / (np.linalg.norm(g) * np.linalg.norm(e) + 1e-12))
            worst = min(worst, cos)
            print(f"[{kind}] cos={cos:.6f} {t[:48]!r}")
    print(f"\nworst cosine = {worst:.6f} ({'PASS' if worst > 0.999 else 'FAIL'} @ >0.999)")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest(Embedder())
    else:
        # Watchdog first: the parent can die during the (potentially minutes-long)
        # model load below, and only serve() would otherwise notice via stdin EOF.
        start_parent_watchdog()
        serve(Embedder())
