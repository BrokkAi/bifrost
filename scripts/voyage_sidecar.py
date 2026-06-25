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

Attention is fused: the HF model runs attn_implementation="sdpa"; with our additive
padding mask, torch selects the memory-efficient SDPA kernel (O(seq), Blackwell-ok).
SDPA only fuses in fp16/bf16, so we run bf16 on CUDA and fp16 on Apple Metal (MPS);
CPU falls back to fp32 (math kernel).

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

MODEL_ID = "voyageai/voyage-4-nano"
OUT_DIM = 512
MAX_SEQ = 8192
# Max padded tokens (batch * longest_seq) per forward — bounds activation memory so a
# few long chunks can't balloon a batch. Mem-efficient SDPA lets this exceed candle's.
PADDED_TOKEN_BUDGET = 16384
PASSAGE_PREFIX = "Represent the document for retrieval: "
QUERY_PREFIX = "Represent the query for retrieving supporting documents: "


def log(*a):
    print("[sidecar]", *a, file=sys.stderr, flush=True)


def patch_masking_kwargs() -> None:
    import transformers.masking_utils as mu

    orig = mu.create_causal_mask

    def patched(*args, **kw):
        kw.pop("input_embeds", None)
        return orig(*args, **kw)

    mu.create_causal_mask = patched


class Embedder:
    def __init__(self) -> None:
        from transformers import AutoModel, AutoTokenizer

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
        patch_masking_kwargs()
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
        self.tok = AutoTokenizer.from_pretrained(MODEL_ID)
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
        # Broadcast key-padding bias (b,1,1,seq): SDPA broadcasts over heads & queries,
        # so the dense (seq,seq) score matrix is never materialized (mem-efficient kernel).
        min_val = torch.finfo(self.dtype).min
        key_valid = attention_mask[:, None, None, :].to(torch.bool)
        bias = torch.zeros_like(key_valid, dtype=self.dtype).masked_fill(~key_valid, min_val)
        o = inner(inputs_embeds=embeds, attention_mask={"full_attention": bias},
                  use_cache=False)
        hidden = self.model.linear(o.last_hidden_state).float()  # (b,seq,2048) fp32

        m = attention_mask[:, :, None].float()
        pooled = (hidden * m).sum(1) / m.sum(1)        # masked mean -> (b,2048)
        v = pooled[:, :OUT_DIM]                         # MRL truncate
        v = v / (v.norm(dim=-1, keepdim=True) + 1e-12)  # renorm
        vecs = v.cpu().numpy().astype(np.float32)
        for j, i in enumerate(idxs):
            out[i] = vecs[j]
        if self._prof:
            self._fwd_s += time.time() - _t
            self._n_batches += 1
            self._sum_b += b
            self._max_b = max(self._max_b, b)


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
        os.write(proto_fd, struct.pack("<I", len(payload)) + payload)

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
    e = Embedder()
    if "--selftest" in sys.argv:
        selftest(e)
    else:
        serve(e)
