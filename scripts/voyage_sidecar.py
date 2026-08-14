# /// script
# requires-python = ">=3.10"
# dependencies = ["torch>=2.5", "transformers>=4.53", "numpy"]
# ///
"""Model-driven embedding sidecar with subprocess and loopback TCP transports.

bifrost's Rust side spawns this behind the Embedder seam (one per CUDA device, pinned
via CUDA_VISIBLE_DEVICES) and talks a small binary protocol over stdin/stdout:

  request  : u32_le length + JSON {"kind": "passage"|"query", "texts": [str, ...]}
  response : u32_le length + [u32_le n][u32_le dim][f64 queue_s][f64 service_s]
             + n*dim float32 (little-endian)

After model load it emits one ready frame with the model ID and output dimension.
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
"""

from __future__ import annotations

import json
import hashlib
import os
import socket
import struct
import sys
import time

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

def default_model_id() -> str:
    if torch.cuda.is_available() or torch.backends.mps.is_available():
        return "brokkai/Muninn"
    return "brokkai/Muninn-small"


MODEL_ID = os.environ.get("BIFROST_EMBED_MODEL_ID", default_model_id())
MODEL_SOURCE = os.environ.get("BIFROST_EMBED_MODEL_DIR", MODEL_ID)
MAX_SEQ = 8192
MPS_SDPA_QUERY_BLOCK = 512
MPS_CACHE_DRAIN_FRACTION = 0.80
# Max padded tokens (batch * longest_seq) per forward — bounds activation memory so a
# few long chunks can't balloon a batch. Mem-efficient SDPA lets this exceed candle's.
PADDED_TOKEN_BUDGET = 16384


def metadata_path(name: str) -> str:
    if os.path.isdir(MODEL_SOURCE):
        path = os.path.join(MODEL_SOURCE, name)
        if not os.path.isfile(path):
            raise RuntimeError(f"embedding artifact is missing {path}")
        return path
    from transformers.utils.hub import cached_file

    path = cached_file(MODEL_SOURCE, name)
    if path is None:
        raise RuntimeError(f"embedding model {MODEL_SOURCE} is missing {name}")
    return path


def load_metadata(name: str) -> dict:
    with open(metadata_path(name), encoding="utf-8") as stream:
        return json.load(stream)


def load_model_contract() -> dict:
    model_config = load_metadata("config.json")
    sentence_config = load_metadata("config_sentence_transformers.json")
    pooling_config = load_metadata("1_Pooling/config.json")
    prompts = sentence_config.get("prompts", {})
    query_prefix = prompts.get("query")
    passage_prefix = prompts.get("document")
    if not isinstance(query_prefix, str) or not isinstance(passage_prefix, str):
        raise RuntimeError(
            f"embedding model {MODEL_SOURCE} must define query and document prompts"
        )
    pooling = pooling_config.get("pooling_mode")
    if pooling not in ("mean", "cls"):
        raise RuntimeError(
            f"embedding model {MODEL_SOURCE} uses unsupported pooling {pooling!r}"
        )
    native_dim = int(pooling_config["embedding_dimension"])
    is_muninn_qwen = "Qwen3BidirectionalModel" in model_config.get(
        "architectures", []
    )
    return {
        "query_prefix": query_prefix,
        "passage_prefix": passage_prefix,
        "pooling": pooling,
        "out_dim": min(native_dim, 512) if is_muninn_qwen else native_dim,
        "is_muninn_qwen": is_muninn_qwen,
    }


def model_fingerprint(contract: dict) -> str:
    hasher = hashlib.sha256()
    if os.path.isdir(MODEL_SOURCE):
        for name in (
            "config.json",
            "config_sentence_transformers.json",
            "1_Pooling/config.json",
            "model.safetensors",
        ):
            path = os.path.join(MODEL_SOURCE, name)
            if not os.path.isfile(path):
                raise RuntimeError(f"embedding artifact is missing {path}")
            with open(path, "rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    hasher.update(chunk)
    else:
        hasher.update(MODEL_SOURCE.encode())
    for value in (
        contract["query_prefix"],
        contract["passage_prefix"],
        contract["pooling"],
        str(contract["out_dim"]),
        str(MAX_SEQ),
    ):
        hasher.update(b"\0")
        hasher.update(value.encode())
    return hasher.hexdigest()

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


def _slice_attention_mask(
    mask: torch.Tensor | None, start: int, end: int
) -> torch.Tensor | None:
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
        raise RuntimeError(
            "embedding sidecar attention is inference-only; dropout must be zero"
        )
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
        self.contract = load_model_contract()
        self.model_fingerprint = model_fingerprint(self.contract)
        self.is_qwen = self.contract["is_muninn_qwen"]
        log(f"loading {MODEL_SOURCE} on {self.device} ({self.dtype})")
        model = AutoModel.from_pretrained(
            MODEL_SOURCE,
            trust_remote_code=True,
            dtype=self.dtype,
            attn_implementation="sdpa",
        ).eval()
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
        self.tok = AutoTokenizer.from_pretrained(MODEL_SOURCE)
        if self.is_qwen:
            ALL_ATTENTION_FUNCTIONS.register("bifrost_sdpa", bifrost_attention_forward)
            self.model.config._attn_implementation = "bifrost_sdpa"
            self.model.model.config._attn_implementation = "bifrost_sdpa"
            layer_types = self.model.model.config.layer_types[
                : self.model.model.config.num_hidden_layers
            ]
            if any(t != "full_attention" for t in layer_types):
                raise RuntimeError(
                    f"Muninn sidecar only supports full attention layers: {layer_types}"
                )
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
        log(
            f"PROF texts={self._n_texts} calls={self._n_calls} batches={self._n_batches} "
            f"avg_texts/call={self._n_texts / max(self._n_calls, 1):.1f} "
            f"avg_batch={self._sum_b / max(self._n_batches, 1):.1f} max_batch={self._max_b} "
            f"tok_s={self._tok_s:.1f} fwd_s={self._fwd_s:.1f}"
        )

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

        if self.is_qwen:
            inner = self.model.model  # Qwen3Model
            embeds = inner.embed_tokens(input_ids)
            # Prevent HF Qwen from synthesizing a causal mask.
            min_val = torch.finfo(self.dtype).min
            key_valid = attention_mask[:, None, None, :].to(torch.bool)
            attention_bias = torch.zeros_like(key_valid, dtype=self.dtype).masked_fill(
                ~key_valid, min_val
            )
            o = inner(
                inputs_embeds=embeds,
                attention_mask={"full_attention": attention_bias},
                use_cache=False,
            )
            hidden = self.model.linear(o.last_hidden_state)
            m = attention_mask[:, :, None].to(dtype=self.dtype)
            pooled = (hidden * m).sum(1) / m.sum(1)
            v = pooled[:, : self.contract["out_dim"]].float()
        else:
            hidden = self.model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                return_dict=True,
            ).last_hidden_state
            if self.contract["pooling"] == "mean":
                mask = attention_mask[:, :, None].to(dtype=self.dtype)
                pooled = (hidden * mask).sum(1) / mask.sum(1)
            else:
                pooled = hidden[:, 0]
            v = pooled[:, : self.contract["out_dim"]].float()
        v = v / (v.norm(dim=-1, keepdim=True) + 1e-12)  # renorm
        vecs = v.cpu().numpy().astype(np.float32)
        for j, i in enumerate(idxs):
            out[i] = vecs[j]
        if self.mps:
            del input_ids, attention_mask, hidden, v
            if (
                torch.mps.driver_allocated_memory()
                > MPS_CACHE_DRAIN_FRACTION * torch.mps.recommended_max_memory()
            ):
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
        poller.register(
            0, 0
        )  # eventmask 0: only POLLHUP/POLLERR/POLLNVAL, no POLLIN wakeups
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


def serve_stream(emb: Embedder, stdin, send, model_lock=None) -> None:
    send(
        json.dumps(
            {
                "ready": True,
                "dim": emb.contract["out_dim"],
                "model_id": MODEL_ID,
                "model_fingerprint": emb.model_fingerprint,
            }
        ).encode()
    )
    log("client ready")

    while True:
        head = _read_exact(stdin, 4)
        if head is None:
            return
        (rlen,) = struct.unpack("<I", head)
        body = _read_exact(stdin, rlen)
        if body is None:
            return
        req = json.loads(body)
        prefix = (
            emb.contract["query_prefix"]
            if req.get("kind") == "query"
            else emb.contract["passage_prefix"]
        )
        queue_started = time.perf_counter()
        if model_lock is not None:
            model_lock.acquire()
            queue_seconds = time.perf_counter() - queue_started
        else:
            queue_seconds = 0.0
        service_started = time.perf_counter()
        try:
            vecs = emb.embed(req["texts"], prefix)
        finally:
            if model_lock is not None:
                model_lock.release()
        service_seconds = time.perf_counter() - service_started
        n, dim = vecs.shape
        send(
            struct.pack("<IIdd", n, dim, queue_seconds, service_seconds)
            + vecs.tobytes()
        )


def serve(emb: Embedder) -> None:
    proto_fd = os.dup(1)  # real stdout for protocol frames
    os.dup2(2, 1)  # fd1 -> stderr so logging can't corrupt the channel
    stdin = sys.stdin.buffer

    def send(payload: bytes) -> None:
        try:
            os.write(proto_fd, struct.pack("<I", len(payload)) + payload)
        except BrokenPipeError:
            log("protocol pipe closed; killing process group")
            import signal

            os.killpg(0, signal.SIGKILL)

    serve_stream(emb, stdin, send)


def serve_tcp(emb: Embedder, address: str) -> None:
    import threading

    host, port_text = address.rsplit(":", 1)
    lock = threading.Lock()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, int(port_text)))
    listener.listen()
    log(f"listening on {host}:{port_text}")

    def handle(conn: socket.socket) -> None:
        with conn:
            stream = conn.makefile("rb")

            def send(payload: bytes) -> None:
                conn.sendall(struct.pack("<I", len(payload)) + payload)

            # Serialize model forwards across clients. Prewarming intentionally has one
            # caller; eval query requests are tiny and queue here without duplicating the model.
            serve_stream(emb, stream, send, lock)

    while True:
        conn, _ = listener.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def main() -> None:
    if "--listen" in sys.argv:
        address = sys.argv[sys.argv.index("--listen") + 1]
        serve_tcp(Embedder(), address)
    else:
        # Watchdog first: the parent can die during the (potentially minutes-long)
        # model load below, and only serve() would otherwise notice via stdin EOF.
        start_parent_watchdog()
        serve(Embedder())


if __name__ == "__main__":
    main()
