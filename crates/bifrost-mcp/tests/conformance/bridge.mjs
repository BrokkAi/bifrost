// Raw pass-through Streamable-HTTP -> stdio bridge for MCP.
//
// The official @modelcontextprotocol/conformance runner tests servers only over
// Streamable HTTP (`conformance server --url ...`). Bifrost's MCP server speaks
// newline-delimited JSON-RPC 2.0 over stdin/stdout and has no HTTP transport.
// This bridge is the smallest honest adapter between the two: it owns the
// transport-layer concerns that stdio does not have (session id header, SSE
// framing, HTTP status codes) and relays JSON-RPC message content verbatim.
//
// "Verbatim" is the point. Bifrost's bytes are parsed exactly once, to read the
// JSON-RPC `id` and `method` for routing, and are re-serialized from that parsed
// value with no shape changes, no defaulting, and no SDK types in the path. The
// runner's built-in `wire-schema-valid` check therefore judges Bifrost's message
// shapes, not an SDK's re-serialization of them.
//
// Usage:
//   node bridge.mjs <port> <server-cmd> [server-args...]
//
// `<port>` may be 0, in which case the bridge prints
//   BRIDGE_LISTENING <port>
// as a single parseable line on stdout once the listener is bound. The endpoint
// is always http://127.0.0.1:<port>/mcp (the path is not checked; the runner
// only ever posts to the URL it was given).
//
// One child process per bridge lifetime. run.mjs starts a fresh bridge and a
// fresh child for every (scenario, revision) pair, which is required anyway:
// Bifrost rejects a second `initialize` on one connection.
//
// SIGTERM (and SIGINT) shut the child down and exit 0.
import http from 'node:http';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';

const [, , portArg, cmd, ...args] = process.argv;
if (portArg === undefined || cmd === undefined) {
  console.error('usage: node bridge.mjs <port> <server-cmd> [server-args...]');
  console.error('       <port> may be 0; the bound port is printed as "BRIDGE_LISTENING <port>"');
  process.exit(2);
}
const port = Number(portArg);
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  console.error(`bridge.mjs: invalid port ${portArg}`);
  process.exit(2);
}

const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'inherit'] });
let shuttingDown = false;

child.on('error', (err) => {
  console.error(`[bridge] failed to spawn child: ${err.message}`);
  process.exit(2);
});
child.on('exit', (code, signal) => {
  if (shuttingDown) return;
  console.error(`[bridge] child exited code=${code} signal=${signal}`);
  process.exit(code ?? 1);
});
// The child's stdin is closed when the child goes away; a late write must not
// crash the bridge with EPIPE while a scenario is being torn down.
child.stdin.on('error', (err) => {
  console.error(`[bridge] child stdin error: ${err.message}`);
});

// ---- outbound streams ------------------------------------------------------

const pendingById = new Map(); // JSON.stringify(id) -> stream awaiting that response
const openPostStreams = new Set(); // insertion-ordered; newest is last
let standaloneStream = null; // the SSE stream opened by a bare GET, if any
let sessionId = null; // minted on `initialize`, echoed back on every response

function sseStream(res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    ...(sessionId ? { 'mcp-session-id': sessionId } : {}),
  });
  const stream = {
    expected: new Set(),
    send(line) {
      res.write(`event: message\ndata: ${line}\n\n`);
    },
    end() {
      openPostStreams.delete(stream);
      res.end();
    },
  };
  res.on('close', () => openPostStreams.delete(stream));
  return stream;
}

function routeFromChild(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    console.error(`[bridge] non-JSON line from child: ${line.slice(0, 400)}`);
    return;
  }
  const wire = JSON.stringify(msg);
  const isResponse = msg.id !== undefined && msg.method === undefined;
  if (isResponse) {
    const key = JSON.stringify(msg.id);
    const stream = pendingById.get(key);
    if (stream) {
      pendingById.delete(key);
      stream.send(wire);
      stream.expected.delete(key);
      if (stream.expected.size === 0) stream.end();
      return;
    }
  }
  // Server-initiated request or notification. Prefer the newest open POST
  // stream (that POST is the request whose handling produced this message);
  // otherwise the standalone GET stream.
  const target = [...openPostStreams].at(-1) ?? standaloneStream;
  if (target) {
    target.send(wire);
    return;
  }
  console.error(`[bridge] dropped child message, no open stream: ${wire.slice(0, 400)}`);
}

let buf = '';
child.stdout.on('data', (chunk) => {
  buf += chunk.toString('utf8');
  let nl;
  while ((nl = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (line) routeFromChild(line);
  }
});

// ---- HTTP server -----------------------------------------------------------

function writeToChild(messages) {
  for (const m of messages) child.stdin.write(JSON.stringify(m) + '\n');
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    if (req.method === 'DELETE') {
      // Explicit session teardown. The child dies with the bridge, so there is
      // nothing else to release.
      res.writeHead(200, sessionId ? { 'mcp-session-id': sessionId } : {}).end();
      return;
    }
    if (req.method === 'GET') {
      const stream = sseStream(res);
      standaloneStream = stream;
      res.on('close', () => {
        if (standaloneStream === stream) standaloneStream = null;
      });
      return;
    }
    if (req.method !== 'POST') {
      res.writeHead(405).end();
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/plain' }).end('invalid JSON body');
      return;
    }
    const messages = Array.isArray(parsed) ? parsed : [parsed];
    // Mint the session on `initialize` (stateful revisions only; the 2026-07-28
    // stateless lifecycle never sends one, so no session id is ever minted).
    if (sessionId === null && messages.some((m) => m && m.method === 'initialize')) {
      sessionId = randomUUID();
    }
    const requests = messages.filter((m) => m && m.method !== undefined && m.id !== undefined);
    if (requests.length === 0) {
      // Notifications and client->server responses carry no reply.
      writeToChild(messages);
      res.writeHead(202, sessionId ? { 'mcp-session-id': sessionId } : {}).end();
      return;
    }
    const stream = sseStream(res);
    openPostStreams.add(stream);
    for (const r of requests) {
      const key = JSON.stringify(r.id);
      stream.expected.add(key);
      pendingById.set(key, stream);
    }
    writeToChild(messages);
  });
});

server.listen(port, '127.0.0.1', () => {
  const bound = server.address().port;
  process.stdout.write(`BRIDGE_LISTENING ${bound}\n`);
  console.error(`[bridge] listening on http://127.0.0.1:${bound}/mcp -> ${cmd} ${args.join(' ')}`);
});

function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  server.close();
  child.stdin.end();
  child.kill('SIGTERM');
  // Give the child a moment to exit on its own before insisting.
  const hard = setTimeout(() => child.kill('SIGKILL'), 2000);
  hard.unref();
  child.on('exit', () => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
