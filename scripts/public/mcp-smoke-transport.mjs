export function waitForSpawn(child) {
  return new Promise((resolve, reject) => {
    child.once("spawn", resolve);
    child.once("error", reject);
  });
}

export function writeMessage(child, message) {
  child.stdin.write(`${JSON.stringify(message)}\n`);
}

export function roundTrip(
  child,
  reader,
  message,
  timeoutMessage = (method) => `Timed out waiting for MCP response to ${method}`,
) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(timeoutMessage(message.method)));
    }, 90_000);
    const onLine = (line) => {
      let response;
      try {
        response = JSON.parse(line);
      } catch (error) {
        cleanup();
        reject(new Error(`MCP emitted non-JSON stdout: ${error.message}`));
        return;
      }
      if (response.id !== message.id) {
        return;
      }
      cleanup();
      if (response.error) {
        reject(new Error(`MCP ${message.method} failed: ${JSON.stringify(response.error)}`));
        return;
      }
      resolve(response);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      clearTimeout(timeout);
      reader.off("line", onLine);
      child.off("error", onError);
    };
    reader.on("line", onLine);
    child.on("error", onError);
    writeMessage(child, message);
  });
}
