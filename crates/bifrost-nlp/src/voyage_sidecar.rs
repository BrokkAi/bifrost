//! PyTorch SDPA embedding sidecar client.
//!
//! Each [`SingleSidecar`] owns one child process (`scripts/voyage_sidecar.py`) pinned to
//! one GPU; the child runs voyage-4-nano under PyTorch with fused (memory-efficient)
//! SDPA attention. N sidecars are wrapped in the existing [`ScheduledEmbedder`] so a
//! batch fans across every GPU.
//!
//! Wire protocol (little-endian), one frame each way:
//!   request : u32 len + JSON {"kind":"passage"|"query","texts":[...]}
//!   response: u32 len + [u32 n][u32 dim][f64 queue_s][f64 service_s] + n*dim f32
//! The child emits one ready frame (`{"ready":true,"dim":512}`) after model load.

use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

#[cfg(all(test, unix))]
use super::engine::VOYAGE_PROFILE;
use super::engine::{
    EMBED_ENDPOINT_ENV, Embedder, EmbeddingTiming, ModelProfile, ScheduledEmbedder, embed_repo_id,
    fingerprint_for, selected_model_profile,
};

const SCRIPT_ENV: &str = "BIFROST_SIDECAR_SCRIPT";
const DEVICES_ENV: &str = "BIFROST_SIDECAR_DEVICES";
const READY_TIMEOUT_ENV: &str = "BIFROST_SIDECAR_READY_TIMEOUT_SECS";
const DEFAULT_SCRIPT: &str = "scripts/embedding_sidecar.py";
const DEFAULT_READY_TIMEOUT_SECS: u64 = 900;

/// One sidecar child process bound to one device.
struct SidecarProc {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

enum SidecarConnection {
    Process(SidecarProc),
    Tcp(BufReader<TcpStream>),
}

impl SidecarConnection {
    fn write_frame(&mut self, payload: &[u8]) -> Result<(), String> {
        match self {
            Self::Process(proc) => proc.write_frame(payload),
            Self::Tcp(stream) => write_frame(stream.get_mut(), payload),
        }
    }

    fn read_frame(&mut self) -> Result<Vec<u8>, String> {
        match self {
            Self::Process(proc) => proc.read_frame(),
            Self::Tcp(stream) => read_frame(stream),
        }
    }
}

fn write_frame(stream: &mut impl Write, payload: &[u8]) -> Result<(), String> {
    let len = u32::try_from(payload.len()).map_err(|_| "frame too large".to_string())?;
    stream
        .write_all(&len.to_le_bytes())
        .and_then(|()| stream.write_all(payload))
        .and_then(|()| stream.flush())
        .map_err(|e| format!("sidecar write: {e}"))
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .map_err(|e| format!("sidecar read len: {e}"))?;
    let len = u32::from_le_bytes(head) as usize;
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("sidecar read body: {e}"))?;
    Ok(buf)
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
    connection: Mutex<SidecarConnection>,
    label: String,
    model_fingerprint: String,
    profile: ModelProfile,
}

impl SingleSidecar {
    fn embed(&self, texts: &[&str], kind: &str) -> Result<SidecarEmbedding, String> {
        if texts.is_empty() {
            return Ok(SidecarEmbedding {
                vectors: Vec::new(),
                timing: EmbeddingTiming::default(),
            });
        }
        let req = serde_json::json!({ "kind": kind, "texts": texts });
        let body = serde_json::to_vec(&req).map_err(|e| format!("encode request: {e}"))?;
        let mut connection = self.connection.lock().expect("sidecar mutex poisoned");
        connection.write_frame(&body)?;
        let resp = connection.read_frame()?;
        drop(connection);
        decode_matrix(&resp, texts.len(), self.profile.dimension)
    }
}

impl Embedder for SingleSidecar {
    fn profile(&self) -> ModelProfile {
        self.profile
    }

    fn embed_passages(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
        self.embed(texts, "passage")
            .map(|response| response.vectors)
    }

    fn embed_query(&self, text: &str) -> Result<Vec<f32>, String> {
        self.embed_query_timed(text).map(|(vector, _)| vector)
    }

    fn embed_query_timed(&self, text: &str) -> Result<(Vec<f32>, EmbeddingTiming), String> {
        let mut response = self.embed(&[text], "query")?;
        let vector = response
            .vectors
            .pop()
            .ok_or_else(|| "empty query embedding".to_string())?;
        Ok((vector, response.timing))
    }

    fn fingerprint(&self) -> String {
        // bf16 sidecar vectors differ slightly from the fp32 reference, so use a
        // distinct contract id — switching backends rebuilds the cache.
        fingerprint_for(
            &format!("{}:{}:sidecar-bf16", self.label, self.model_fingerprint),
            self.profile,
        )
    }
}

struct SidecarEmbedding {
    vectors: Vec<Vec<f32>>,
    timing: EmbeddingTiming,
}

/// Decode a response frame and its server-side queue/service timings.
fn decode_matrix(
    buf: &[u8],
    expected_rows: usize,
    expected_dim: usize,
) -> Result<SidecarEmbedding, String> {
    const HEADER_BYTES: usize = 24;
    if buf.len() < HEADER_BYTES {
        return Err("sidecar response too short".to_string());
    }
    let n = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    let dim = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
    if n != expected_rows || dim != expected_dim {
        return Err(format!(
            "sidecar returned {n}x{dim}, expected {expected_rows}x{expected_dim}"
        ));
    }
    let queue_seconds = f64::from_le_bytes(buf[8..16].try_into().unwrap());
    let service_seconds = f64::from_le_bytes(buf[16..24].try_into().unwrap());
    if !queue_seconds.is_finite()
        || queue_seconds < 0.0
        || !service_seconds.is_finite()
        || service_seconds < 0.0
    {
        return Err("sidecar returned invalid timing values".to_string());
    }
    let floats = &buf[HEADER_BYTES..];
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
    Ok(SidecarEmbedding {
        vectors: out,
        timing: EmbeddingTiming {
            queue_wait: Duration::from_secs_f64(queue_seconds),
            service: Duration::from_secs_f64(service_seconds),
        },
    })
}

/// The CUDA_VISIBLE_DEVICES value for each sidecar: `BIFROST_SIDECAR_DEVICES`
/// (comma-separated, UUIDs or indices) if set, else every GPU `nvidia-smi` reports,
/// else a single CPU sidecar (empty string).
fn sidecar_devices() -> Vec<String> {
    if let Ok(v) = std::env::var(DEVICES_ENV) {
        return v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    // Honor CUDA_VISIBLE_DEVICES: a GPU-pinned worker (e.g. the mass-gen orchestrator)
    // sets it to one device and must spawn exactly one sidecar there.
    if let Ok(v) = std::env::var("CUDA_VISIBLE_DEVICES") {
        let devs: Vec<String> = v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !devs.is_empty() {
            return devs;
        }
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
    std::env::var(SCRIPT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SCRIPT))
}

fn ready_timeout() -> Duration {
    let secs = std::env::var(READY_TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_READY_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

fn kill_sidecar_pid(pid: u32) {
    #[cfg(unix)]
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
        libc::kill(pid as i32, libc::SIGKILL);
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status();
    }
}

/// Spawn one sidecar pinned to `device` (a CUDA_VISIBLE_DEVICES value) and wait for its
/// ready frame.
fn spawn_sidecar(
    device: &str,
    label: String,
    profile: ModelProfile,
) -> Result<SingleSidecar, String> {
    spawn_sidecar_with_timeout(device, label, profile, script_path(), ready_timeout(), None)
}

fn spawn_sidecar_with_timeout(
    device: &str,
    label: String,
    profile: ModelProfile,
    script: PathBuf,
    timeout: Duration,
    uv_cache_dir: Option<&Path>,
) -> Result<SingleSidecar, String> {
    let mut cmd = Command::new("uv");
    cmd.arg("run").arg("--no-project").arg(&script);
    if let Some(cache_dir) = uv_cache_dir {
        cmd.env("UV_CACHE_DIR", cache_dir);
    }
    cmd.env("CUDA_VISIBLE_DEVICES", device);
    cmd.env(super::engine::EMBED_PROFILE_ENV, profile.name);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
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
    let mut proc = SidecarProc {
        child,
        stdin,
        stdout: BufReader::new(stdout),
    };
    let pid = proc.child.id();

    // First frame is the ready handshake (blocks through model load).
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::Builder::new()
        .name("bifrost-sidecar-ready".to_string())
        .spawn(move || {
            let result = proc.read_frame().and_then(|ready| {
                let info: serde_json::Value = serde_json::from_slice(&ready)
                    .map_err(|e| format!("sidecar ready frame: {e}"))?;
                if info.get("ready").and_then(|v| v.as_bool()) != Some(true) {
                    return Err(format!("sidecar did not report ready: {info}"));
                }
                let model_fingerprint = validate_ready(&info, profile)?;
                Ok((proc, model_fingerprint))
            });
            tx.send(result).ok();
        })
        .map_err(|err| format!("spawn sidecar ready thread: {err}"))?;
    let (proc, model_fingerprint) = match rx.recv_timeout(timeout) {
        Ok(result) => {
            handle
                .join()
                .map_err(|_| "sidecar ready thread panicked".to_string())?;
            result?
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            kill_sidecar_pid(pid);
            let _ = handle.join();
            return Err(format!(
                "sidecar ({}, pid {pid}) did not become ready within {}s",
                script.display(),
                timeout.as_secs()
            ));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            handle
                .join()
                .map_err(|_| "sidecar ready thread panicked".to_string())?;
            return Err("sidecar ready thread exited without reporting readiness".to_string());
        }
    };
    Ok(SingleSidecar {
        connection: Mutex::new(SidecarConnection::Process(proc)),
        label,
        model_fingerprint,
        profile,
    })
}

fn validate_ready(info: &serde_json::Value, profile: ModelProfile) -> Result<String, String> {
    if info.get("ready").and_then(|v| v.as_bool()) != Some(true) {
        return Err(format!("sidecar did not report ready: {info}"));
    }
    let dim = info.get("dim").and_then(|v| v.as_u64());
    let reported_profile = info.get("profile").and_then(|v| v.as_str());
    if dim != Some(profile.dimension as u64) || reported_profile != Some(profile.name) {
        return Err(format!(
            "sidecar contract mismatch: reported profile={reported_profile:?} dim={dim:?}, expected profile={} dim={}",
            profile.name, profile.dimension
        ));
    }
    info.get("model_fingerprint")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "sidecar ready frame omitted model_fingerprint".to_string())
}

fn connect_sidecar(
    endpoint: &str,
    label: String,
    profile: ModelProfile,
) -> Result<SingleSidecar, String> {
    let address = endpoint
        .strip_prefix("tcp://")
        .ok_or_else(|| format!("{EMBED_ENDPOINT_ENV} must use tcp://host:port"))?;
    let stream = TcpStream::connect(address)
        .map_err(|err| format!("connect embedding sidecar at {endpoint}: {err}"))?;
    stream
        .set_nodelay(true)
        .map_err(|err| format!("configure embedding sidecar TCP: {err}"))?;
    let mut connection = SidecarConnection::Tcp(BufReader::new(stream));
    let ready = connection.read_frame()?;
    let info: serde_json::Value =
        serde_json::from_slice(&ready).map_err(|err| format!("sidecar ready frame: {err}"))?;
    let model_fingerprint = validate_ready(&info, profile)?;
    Ok(SingleSidecar {
        connection: Mutex::new(connection),
        label,
        model_fingerprint,
        profile,
    })
}

/// Spawn one sidecar per device and fan a batch across them via `ScheduledEmbedder`.
pub fn load_sidecar_embedder() -> Result<Arc<dyn Embedder>, String> {
    let profile = selected_model_profile()?;
    let label = embed_repo_id();
    if let Ok(endpoint) = std::env::var(EMBED_ENDPOINT_ENV) {
        let worker = connect_sidecar(&endpoint, label, profile)?;
        worker
            .embed_passages(&["warmup"])
            .map_err(|err| format!("sidecar warmup failed at '{endpoint}': {err}"))?;
        return Ok(Arc::new(worker));
    }
    let devices = sidecar_devices();
    let mut workers: Vec<Arc<dyn Embedder>> = Vec::with_capacity(devices.len());
    for device in &devices {
        let worker = spawn_sidecar(device, label.clone(), profile)?;
        worker
            .embed_passages(&["warmup"])
            .map_err(|err| format!("sidecar warmup failed on device '{device}': {err}"))?;
        workers.push(Arc::new(worker));
    }
    eprintln!(
        "bifrost semantic index: {} sidecar device(s)",
        workers.len()
    );
    Ok(Arc::new(ScheduledEmbedder::new(workers)))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;

    fn process_exists(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }

    fn timeout_pid(message: &str) -> i32 {
        let (_, after_pid) = message
            .split_once("pid ")
            .expect("timeout error includes pid");
        let (pid, _) = after_pid
            .split_once(')')
            .expect("timeout error terminates pid");
        pid.parse().expect("pid is numeric")
    }

    #[test]
    fn response_decodes_vectors_and_server_timings() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1_u32.to_le_bytes());
        payload.extend_from_slice(&2_u32.to_le_bytes());
        payload.extend_from_slice(&0.25_f64.to_le_bytes());
        payload.extend_from_slice(&0.5_f64.to_le_bytes());
        payload.extend_from_slice(&1.0_f32.to_le_bytes());
        payload.extend_from_slice(&2.0_f32.to_le_bytes());

        let response = decode_matrix(&payload, 1, 2).unwrap();
        assert_eq!(response.vectors, vec![vec![1.0, 2.0]]);
        assert_eq!(response.timing.queue_wait, Duration::from_millis(250));
        assert_eq!(response.timing.service, Duration::from_millis(500));
    }

    #[test]
    fn spawn_sidecar_times_out_and_reaps_child() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("sleep_sidecar.py");
        let uv_cache_dir = dir.path().join("uv-cache");
        let mut file = std::fs::File::create(&script).unwrap();
        writeln!(file, "import time").unwrap();
        writeln!(file, "time.sleep(60)").unwrap();

        let result = spawn_sidecar_with_timeout(
            "",
            "test-sidecar".to_string(),
            VOYAGE_PROFILE,
            script,
            Duration::from_secs(1),
            Some(&uv_cache_dir),
        );
        let err = match result {
            Ok(_) => panic!("sleeping sidecar should hit ready timeout"),
            Err(err) => err,
        };

        assert!(
            err.contains("did not become ready within 1s"),
            "unexpected timeout error: {err}"
        );
        let pid = timeout_pid(&err);
        assert!(!process_exists(pid), "timed-out sidecar child still exists");
    }
}
