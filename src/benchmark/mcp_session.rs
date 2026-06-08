use serde_json::{Value, json};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

pub struct McpSession {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    stderr: ChildStderr,
    next_id: u64,
}

impl McpSession {
    pub fn start(root: &Path) -> Result<Self, String> {
        let bifrost_binary = bifrost_binary_path()?;
        let mut child = Command::new(&bifrost_binary)
            .arg("--root")
            .arg(root)
            .arg("--server")
            .arg("searchtools")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                format!(
                    "failed to spawn bifrost MCP server `{}`: {err}",
                    bifrost_binary.display()
                )
            })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "missing bifrost stdin".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "missing bifrost stdout".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "missing bifrost stderr".to_string())?;

        Ok(Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
            stderr,
            next_id: 1,
        })
    }

    pub fn initialize(&mut self) -> Result<(), String> {
        let response = self.request(json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "bifrost-benchmark",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }))?;
        if response.get("error").is_some() {
            return Err(format!("bifrost initialize failed: {response}"));
        }

        self.notify(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
    }

    pub fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value, String> {
        let id = self.take_id();
        let response = self.request(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }))?;

        if let Some(error) = response.get("error") {
            return Err(format!("bifrost MCP request failed for `{name}`: {error}"));
        }

        let result = response.get("result").cloned().ok_or_else(|| {
            format!("bifrost MCP response missing result for `{name}`: {response}")
        })?;
        if result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let message = result["content"][0]["text"]
                .as_str()
                .unwrap_or("tool returned isError without text");
            return Err(format!("bifrost tool `{name}` failed: {message}"));
        }

        Ok(result)
    }

    fn request(&mut self, payload: Value) -> Result<Value, String> {
        self.write_line(&payload)?;
        self.read_line()
    }

    fn notify(&mut self, payload: Value) -> Result<(), String> {
        self.write_line(&payload)
    }

    fn write_line(&mut self, payload: &Value) -> Result<(), String> {
        writeln!(self.stdin, "{payload}")
            .and_then(|_| self.stdin.flush())
            .map_err(|err| format!("failed to write MCP request: {err}"))
    }

    fn read_line(&mut self) -> Result<Value, String> {
        let mut line = String::new();
        let bytes = self
            .reader
            .read_line(&mut line)
            .map_err(|err| format!("failed to read MCP response: {err}"))?;
        if bytes == 0 {
            let mut stderr = String::new();
            let _ = self.stderr.read_to_string(&mut stderr);
            return Err(format!(
                "bifrost MCP server closed early; stderr:\n{stderr}"
            ));
        }

        serde_json::from_str(&line)
            .map_err(|err| format!("failed to parse MCP JSON response: {err}; line={line}"))
    }

    fn take_id(&mut self) -> u64 {
        let next = self.next_id;
        self.next_id += 1;
        next
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bifrost_binary_path() -> Result<PathBuf, String> {
    if let Some(explicit) = std::env::var_os("BIFROST_BENCHMARK_BIFROST_BIN") {
        return Ok(PathBuf::from(explicit));
    }

    let current = std::env::current_exe()
        .map_err(|err| format!("failed to locate current executable: {err}"))?;
    let binary_name = bifrost_binary_name();
    for candidate in [
        current.parent().map(|dir| dir.join(&binary_name)),
        current
            .parent()
            .and_then(|dir| dir.parent())
            .map(|dir| dir.join(&binary_name)),
    ]
    .into_iter()
    .flatten()
    {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "failed to locate sibling bifrost binary near `{}`; set BIFROST_BENCHMARK_BIFROST_BIN",
        current.display()
    ))
}

fn bifrost_binary_name() -> OsString {
    #[cfg(windows)]
    {
        OsString::from("bifrost.exe")
    }
    #[cfg(not(windows))]
    {
        OsString::from("bifrost")
    }
}
