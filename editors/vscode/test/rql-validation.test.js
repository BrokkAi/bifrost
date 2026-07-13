const assert = require("node:assert/strict");
const test = require("node:test");

const {
  RQL_QUERY_HOVER_METHOD,
  RQL_VALIDATION_DELAY_MS,
  RqlValidationController,
  VALIDATE_RQL_QUERY_METHOD,
  queryHoverParams
} = require("../out-test/rql_validation.js");
const { RQL_LANGUAGE_ID } = require("../out-test/rql_query.js");

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function harness() {
  const timers = [];
  const requests = [];
  const published = [];
  const cleared = [];
  const documents = new Map();
  const cancellations = [];
  const controller = new RqlValidationController({
    validate: (query, token) => {
      const pending = deferred();
      requests.push({ query, token, pending });
      return pending.promise;
    },
    publish: (uri, diagnostics) => published.push([uri, diagnostics]),
    clear: (uri) => cleared.push(uri),
    isCurrent: (document) => {
      const current = documents.get(document.uri);
      return current?.languageId === RQL_LANGUAGE_ID && current.version === document.version;
    },
    createCancellationSource: () => {
      const source = {
        token: {},
        cancelled: false,
        disposed: false,
        cancel() { this.cancelled = true; },
        dispose() { this.disposed = true; }
      };
      cancellations.push(source);
      return source;
    },
    setTimer: (callback, delayMs) => {
      const timer = { callback, delayMs, cleared: false };
      timers.push(timer);
      return timer;
    },
    clearTimer: (timer) => { timer.cleared = true; }
  });
  const schedule = (version, text, languageId = RQL_LANGUAGE_ID, uri = "file:///query.rql") => {
    const document = { uri, version, text, languageId };
    documents.set(uri, document);
    controller.schedule(document);
    return document;
  };
  const fire = (index) => timers[index].callback();
  return { controller, timers, requests, published, cleared, documents, cancellations, schedule, fire };
}

test("exports the server method contracts and 300ms debounce", () => {
  assert.equal(VALIDATE_RQL_QUERY_METHOD, "bifrost/validateQuery");
  assert.equal(RQL_QUERY_HOVER_METHOD, "bifrost/queryHover");
  assert.equal(RQL_VALIDATION_DELAY_MS, 300);
});

test("wires unsaved query text and position into hover params", () => {
  assert.deepEqual(queryHoverParams("(call)", { line: 2, character: 4 }), {
    query: "(call)",
    position: { line: 2, character: 4 }
  });
});

test("debounces edits and cancels an in-flight request", async () => {
  const h = harness();
  h.schedule(1, "(call)");
  assert.equal(h.timers[0].delayMs, 300);
  h.schedule(2, "(class)");
  assert.equal(h.timers[0].cleared, true);

  h.fire(1);
  assert.equal(h.requests[0].query, "(class)");
  h.schedule(3, "(function)");
  assert.equal(h.cancellations[0].cancelled, true);
  h.requests[0].pending.resolve({ diagnostics: [{ message: "stale" }] });
  await Promise.resolve();
  assert.deepEqual(h.published, []);
});

test("rejects stale versions even when an old response wins the race", async () => {
  const h = harness();
  h.schedule(1, "(call)");
  h.fire(0);
  h.documents.set("file:///query.rql", {
    uri: "file:///query.rql",
    version: 2,
    languageId: RQL_LANGUAGE_ID,
    text: "(class)"
  });
  h.requests[0].pending.resolve({ diagnostics: [{ message: "old" }] });
  await Promise.resolve();
  assert.deepEqual(h.published, []);
});

test("publishes current diagnostics and clears after fixes", async () => {
  const h = harness();
  h.schedule(1, "(call :wat 1)");
  h.fire(0);
  const diagnostics = [{ message: "unknown property" }];
  h.requests[0].pending.resolve({ diagnostics });
  await Promise.resolve();
  assert.deepEqual(h.published, [["file:///query.rql", diagnostics]]);

  h.schedule(2, "(call)");
  h.fire(1);
  h.requests[1].pending.resolve({ diagnostics: [] });
  await Promise.resolve();
  assert.deepEqual(h.published.at(-1), ["file:///query.rql", []]);
});

test("close and stop cancel work and clear diagnostics", () => {
  const h = harness();
  h.schedule(1, "(call)");
  h.controller.close("file:///query.rql");
  assert.equal(h.timers[0].cleared, true);
  assert.deepEqual(h.cleared, ["file:///query.rql"]);

  h.schedule(1, "(class)", RQL_LANGUAGE_ID, "file:///second.rql");
  h.controller.stop();
  assert.equal(h.timers[1].cleared, true);
  assert.deepEqual(h.cleared, ["file:///query.rql", "file:///second.rql"]);
});

test("ignores ordinary JSON documents even when they look like CodeQuery", () => {
  const h = harness();
  h.schedule(1, '{"match":{"kind":"call"}}', "json", "file:///query.json");
  assert.equal(h.timers.length, 0);
  assert.equal(h.requests.length, 0);
  assert.deepEqual(h.cleared, ["file:///query.json"]);
});
