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
SDPA only fuses in fp16/bf16, so we run bf16 on GPU.

Run the sidecar:   uv run scripts/voyage_sidecar.py
Self-test parity:  uv run scripts/voyage_sidecar.py --selftest
"""

from __future__ import annotations

import json
import os
import struct
import sys

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

        self.cuda = torch.cuda.is_available()
        self.device = torch.device("cuda:0" if self.cuda else "cpu")
        self.dtype = torch.bfloat16 if self.cuda else torch.float32
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
        # backend selection report (helps confirm a fused kernel is eligible)
        torch.backends.cuda.enable_flash_sdp(True)
        torch.backends.cuda.enable_mem_efficient_sdp(True)
        torch.backends.cuda.enable_math_sdp(True)

    @torch.no_grad()
    def embed(self, texts: list[str], prefix: str) -> np.ndarray:
        # Length-bucketed sub-batching: bound padded tokens (b*seq) per forward so a few
        # long chunks can't pad a huge batch and blow up memory. Process short->long.
        prefixed = [prefix + t for t in texts]
        lens = [min(len(e), MAX_SEQ)
                for e in self.tok(prefixed, truncation=True, max_length=MAX_SEQ)["input_ids"]]
        order = sorted(range(len(texts)), key=lambda i: lens[i])
        out: list[np.ndarray | None] = [None] * len(texts)

        batch: list[int] = []
        bmax = 0
        for i in order:
            new_max = max(bmax, lens[i])
            if batch and (len(batch) + 1) * new_max > PADDED_TOKEN_BUDGET:
                self._run_batch([prefixed[j] for j in batch], batch, out)
                batch, bmax = [], 0
            batch.append(i)
            bmax = max(bmax, lens[i])
        self._run_batch([prefixed[j] for j in batch], batch, out)
        return np.stack(out)  # type: ignore[arg-type]

    @torch.no_grad()
    def _run_batch(self, sub: list[str], idxs: list[int], out: list) -> None:
        if not sub:
            return
        enc = self.tok(sub, padding=True, truncation=True, max_length=MAX_SEQ,
                       return_tensors="pt")
        input_ids = enc["input_ids"].to(self.device)
        attention_mask = enc["attention_mask"].to(self.device)

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
    ref_path = "/home/jonathan/Projects/bifrost/tests/fixtures/voyage_parity_ref.json"
    ref = json.load(open(ref_path))
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
