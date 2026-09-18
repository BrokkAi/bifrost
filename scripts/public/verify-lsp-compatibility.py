#!/usr/bin/env python3

"""Verify a shipped Bifrost binary's structured LSP compatibility identity."""

import argparse
import json
import subprocess
from pathlib import Path


def framed(message: object) -> bytes:
    body = json.dumps(message, separators=(",", ":")).encode()
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def read_message(stream) -> object:
    content_length = None
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("LSP server closed stdout before replying to initialize")
        if line == b"\r\n":
            break
        name, value = line.decode().split(":", 1)
        if name.lower() == "content-length":
            content_length = int(value.strip())
    if content_length is None:
        raise RuntimeError("LSP response omitted Content-Length")
    return json.loads(stream.read(content_length))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--engine-version", required=True)
    args = parser.parse_args()

    process = subprocess.Popen(
        [args.binary, "--lsp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write(
        framed(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"processId": None, "rootUri": None, "capabilities": {}},
            }
        )
    )
    process.stdin.flush()
    response = read_message(process.stdout)
    identity = response["result"]["capabilities"]["experimental"]["bifrost"]
    expected = {"protocolVersion": 1, "engineVersion": args.engine_version}
    if identity != expected:
        raise RuntimeError(f"unexpected LSP compatibility identity: {identity!r} != {expected!r}")
    process.terminate()
    process.wait(timeout=30)
    print(f"Verified Bifrost LSP protocol 1 with engine {args.engine_version}.")


if __name__ == "__main__":
    main()
