import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { createBifrostSession } from "./bifrost-session.ts";

export default function bifrostExtension(pi: ExtensionAPI) {
  const session = createBifrostSession(pi);

  pi.on("session_start", async (_event, ctx) => {
    await session.start(ctx.cwd);
  });

  pi.on("session_shutdown", async () => {
    await session.shutdown();
  });

  pi.registerCommand("bifrost", {
    description: "Show the Bifrost MCP connection status.",
    handler: async (_args, ctx) => {
      const status = session.status();
      const workspace = status.workspace ?? "not set";
      ctx.ui.notify(
        `Bifrost: ${status.state}; workspace: ${workspace}; registered tools: ${status.toolCount}.`,
        status.state === "error" ? "error" : "info",
      );
    },
  });
}
