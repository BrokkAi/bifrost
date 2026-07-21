import fs from "node:fs";
import readline from "node:readline";

const recordPath = process.env.BIFROST_FAKE_MCP_RECORD;
const record = (event) => {
  if (recordPath) {
    fs.appendFileSync(recordPath, `${JSON.stringify(event)}\n`);
  }
};

record({ type: "started", pid: process.pid, cwd: process.cwd(), args: process.argv.slice(2) });

const input = readline.createInterface({ input: process.stdin });
input.on("line", (line) => {
  const message = JSON.parse(line);
  if (message.method === "notifications/cancelled") {
    record({ type: "cancelled", params: message.params });
    return;
  }
  if (message.id === undefined) {
    return;
  }

  if (message.method === "initialize") {
    respond(message.id, {
      protocolVersion: process.env.BIFROST_FAKE_MCP_FAIL_INIT === "1"
        ? "unsupported-protocol-version"
        : message.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "fake-bifrost", version: "0.8.4" },
    });
    return;
  }
  if (message.method === "tools/list") {
    respond(message.id, {
      tools: [{
        name: "fake_lookup",
        description: "Look up a fake symbol.",
        inputSchema: {
          type: "object",
          properties: { symbol: { type: "string" } },
          required: ["symbol"],
          additionalProperties: false,
        },
      }, {
        name: "slow_lookup",
        description: "Wait until cancelled.",
        inputSchema: { type: "object", properties: {} },
      }],
    });
    return;
  }
  if (message.method === "tools/call") {
    record({ type: "call", params: message.params });
    if (message.params.name === "slow_lookup") {
      setTimeout(() => respond(message.id, { content: [{ type: "text", text: "late" }] }), 10_000).unref();
      return;
    }
    respond(message.id, {
      content: [{ type: "text", text: `found ${message.params.arguments.symbol}` }],
      structuredContent: { symbol: message.params.arguments.symbol, file: "src/fake.rs" },
    });
    return;
  }
  respondError(message.id, -32601, `Unknown method: ${message.method}`);
});

process.on("SIGTERM", () => {
  record({ type: "stopped", signal: "SIGTERM" });
  process.exit(0);
});

function respond(id, result) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
}

function respondError(id, code, message) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } })}\n`);
}
