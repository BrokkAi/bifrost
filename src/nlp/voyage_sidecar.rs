//! PyTorch SDPA embedding sidecar client.
//!
//! Each [`SingleSidecar`] owns one child process (`scripts/voyage_sidecar.py`) pinned to
//! one GPU; the child runs voyage-4-nano under PyTorch with fused (memory-efficient)
//! SDPA attention. N sidecars are wrapped in the existing [`ScheduledEmbedder`] so a
//! batch fans across every GPU. `count_tokens` stays in-process (the `tokenizers`
//! crate) so the hot chunker path never pays IPC.
//!
//! Wire protocol (little-endian), one frame each way:
//!   request : u32 len + JSON {"kind":"passage"|"query","texts":[...]}
//!   response: u32 len + [u32 n][u32 dim] + n*dim f32
//! The child emits one ready frame (`{"ready":true,"dim":512}`) after model load.

use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

use tokenizers::Tokenizer;

use super::engine::{Embedder, ScheduledEmbedder, fingerprint_for, resolve_embed_model_dir};

const OUT_DIM: usize = 512;
const SCRIPT_ENV: &str = "BIFROST_SIDECAR_SCRIPT";
const DEVICES_ENV: &str = "BIFROST_SIDECAR_DEVICES";
const DEFAULT_SCRIPT: &str = "scripts/voyage_sidecar.py";

/// One sidecar child process bound to one device.
struct SidecarProc {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl SidecarProc {
    fn write_frame(&mut self, payload: &[u8]) -> Result<(), String> {
        let len = u32::try_from(payload.len()).map_err(|_| "frame too large".to_string())?;
        self.stdin
            .write_all(&len.to_le_bytes())
            .and_then(|()| self.stdin.write_all(payload))
            .and_then(|()| self.stdin.flush())
            .map_err(|e| format!("sidecar write: {e}"))
    }

    fn read_frame(&mut self) -> Result<Vec<u8>, String> {
        let mut head = [0u8; 4];
        self.stdout
            .read_exact(&mut head)
            .map_err(|e| format!("sidecar read len: {e}"))?;
        let len = u32::from_le_bytes(head) as usize;
        let mut buf = vec![0u8; len];
        self.stdout
            .read_exact(&mut buf)
            .map_err(|e| format!("sidecar read body: {e}"))?;
        Ok(buf)
    }
}

impl Drop for SidecarProc {
    fn drop(&mut self) {
        // `uv run` forks a python grandchild; killing only the direct child orphans it
        // (and leaves a GPU wedged). The child leads its own process group (see
        // `spawn_sidecar`), so signal the whole group.
        #[cfg(unix)]
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Embedder backed by a single sidecar process (one GPU).
pub struct SingleSidecar {
    proc: Mutex<SidecarProc>,
    tokenizer: Arc<Tokenizer>,
    label: String,
}

impl SingleSidecar {
    fn embed(&self, texts: &[&str], kind: &str) -> Result<Vec<Vec<f32>>, String> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let req = serde_json::json!({ "kind": kind, "texts": texts });
        let body = serde_json::to_vec(&req).map_err(|e| format!("encode request: {e}"))?;
        let mut proc = self.proc.lock().expect("sidecar mutex poisoned");
        proc.write_frame(&body)?;
        let resp = proc.read_frame()?;
        drop(proc);
        decode_matrix(&resp, texts.len())
    }
}

impl Embedder for SingleSidecar {
    fn dim(&self) -> usize {
        OUT_DIM
    }

    fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
        self.embed(texts, "passage")
    }

    fn embed_query(&self, text: &str) -> Result<Vec<f32>, String> {
        let mut out = self.embed(&[text], "query")?;
        out.pop().ok_or_else(|| "empty query embedding".to_string())
    }

    fn count_tokens(&self, text: &str) -> usize {
        self.tokenizer
            .encode(text, false)
            .map(|enc| enc.get_ids().len())
            .unwrap_or(usize::MAX)
    }

    fn fingerprint(&self) -> String {
        // bf16 sidecar vectors differ slightly from the candle f32 path, so use a
        // distinct contract id — switching backends rebuilds the cache.
        fingerprint_for(&format!("{}:sidecar-bf16", self.label), OUT_DIM)
    }
}

/// Decode a response frame ([u32 n][u32 dim] + f32 matrix) into row vectors.
fn decode_matrix(buf: &[u8], expected_rows: usize) -> Result<Vec<Vec<f32>>, String> {
    if buf.len() < 8 {
        return Err("sidecar response too short".to_string());
    }
    let n = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    let dim = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
    if n != expected_rows || dim != OUT_DIM {
        return Err(format!(
            "sidecar returned {n}x{dim}, expected {expected_rows}x{OUT_DIM}"
        ));
    }
    let floats = &buf[8..];
    if floats.len() != n * dim * 4 {
        return Err("sidecar response payload size mismatch".to_string());
    }
    let mut out = Vec::with_capacity(n);
    for row in floats.chunks_exact(dim * 4) {
        out.push(
            row.chunks_exact(4)
                .map(|b| f32::from_le_bytes(b.try_into().unwrap()))
                .collect(),
        );
    }
    Ok(out)
}

/// The CUDA_VISIBLE_DEVICES value for each sidecar: `BIFROST_SIDECAR_DEVICES`
/// (comma-separated, UUIDs or indices) if set, else every GPU `nvidia-smi` reports,
/// else a single CPU sidecar (empty string).
fn sidecar_devices() -> Vec<String> {
    if let Ok(v) = std::env::var(DEVICES_ENV) {
        return v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    }
    let out = Command::new("nvidia-smi")
        .args(["--query-gpu=uuid", "--format=csv,noheader"])
        .output();
    if let Ok(out) = out {
        let uuids: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if !uuids.is_empty() {
            return uuids;
        }
    }
    vec![String::new()] // CPU fallback (one sidecar, no CUDA pin)
}

fn script_path() -> PathBuf {
    std::env::var(SCRIPT_ENV).map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(DEFAULT_SCRIPT))
}

/// Spawn one sidecar pinned to `device` (a CUDA_VISIBLE_DEVICES value) and wait for its
/// ready frame.
fn spawn_sidecar(device: &str, tokenizer: Arc<Tokenizer>, label: String) -> Result<SingleSidecar, String> {
    let script = script_path();
    let mut cmd = Command::new("uv");
    cmd.arg("run").arg(&script);
    cmd.env("CUDA_VISIBLE_DEVICES", device);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
    // Lead a new process group so Drop can kill `uv` and its python grandchild together.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn sidecar ({}): {e}", script.display()))?;
    let stdin = child.stdin.take().ok_or("sidecar stdin missing")?;
    let stdout = child.stdout.take().ok_or("sidecar stdout missing")?;
    let mut proc = SidecarProc { child, stdin, stdout: BufReader::new(stdout) };

    // First frame is the ready handshake (blocks through model load).
    let ready = proc.read_frame()?;
    let info: serde_json::Value =
        serde_json::from_slice(&ready).map_err(|e| format!("sidecar ready frame: {e}"))?;
    if info.get("ready").and_then(|v| v.as_bool()) != Some(true) {
        return Err(format!("sidecar did not report ready: {info}"));
    }
    Ok(SingleSidecar { proc: Mutex::new(proc), tokenizer, label })
}

/// Spawn one sidecar per device and fan a batch across them via `ScheduledEmbedder`.
pub fn load_sidecar_embedder() -> Result<Arc<dyn Embedder>, String> {
    let dir = resolve_embed_model_dir()?;
    let tokenizer = Arc::new(
        Tokenizer::from_file(dir.join("tokenizer.json"))
            .map_err(|e| format!("load tokenizer: {e}"))?,
    );
    let label = super::engine::embed_repo_id();
    let devices = sidecar_devices();
    let mut workers: Vec<Arc<dyn Embedder>> = Vec::with_capacity(devices.len());
    for device in &devices {
        let worker = spawn_sidecar(device, tokenizer.clone(), label.clone())?;
        let _ = worker.embed_passages(&["warmup"]);
        workers.push(Arc::new(worker));
    }
    eprintln!("bifrost semantic index: {} sidecar device(s)", workers.len());
    Ok(Arc::new(ScheduledEmbedder::new(workers)))
}
