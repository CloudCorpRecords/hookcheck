/**
 * hookcheck MCP server. Tools: scan_hooks, explain_hook.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { explainHook, scanHooks, VERSION } from "./core.js";

const server = new McpServer({ name: "hookcheck", version: VERSION });

server.tool(
  "scan_hooks",
  "Scan a local repo directory for auto-exec hooks: npm install scripts, Claude Code settings hooks, VS Code folderOpen tasks, husky, lefthook, pre-commit, Cursor and Codex configs, MCP autostart configs, and GitHub workflow run steps. Classifies each hook SAFE, RISKY, or UNKNOWN and returns a CLEAN, REVIEW, or COMPROMISED-PATTERN verdict with evidence per finding. Deterministic, local only, no network.",
  { path: z.string().describe("Local directory to scan, e.g. /home/user/project") },
  async ({ path }) => {
    const report = scanHooks(path);
    return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
  },
);

server.tool(
  "explain_hook",
  "Explain one hook found by scan_hooks: its command, classification, rules that fired, and what the classification means. Pass the hook id (e.g. package.json:postinstall) or its file path.",
  {
    path: z.string().describe("Local directory to scan"),
    hookId: z.string().optional().describe("Hook id from a scan report, e.g. package.json:postinstall"),
    file: z.string().optional().describe("File path of the hook as an alternative selector"),
  },
  async ({ path, hookId, file }) => {
    const selector = hookId ?? file ?? "";
    const result = explainHook(path, selector);
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  },
);

async function main(): Promise<void> {
  await server.connect(new StdioServerTransport());
}

void main();
