#!/usr/bin/env node
/**
 * hookcheck CLI.
 *   hookcheck scan [path] [--json]
 *   hookcheck mcp
 *   hookcheck --version
 * Exit codes: 0 CLEAN, 1 REVIEW or COMPROMISED-PATTERN, 2 usage error.
 */
import { explainHook, renderReport, scanHooks, VERSION } from "./core.js";

function usage(): never {
  console.error(`Usage:
  hookcheck scan [path] [--json]
  hookcheck explain [path] <hookId-or-file>
  hookcheck mcp
  hookcheck --version`);
  process.exit(2);
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "--version" || cmd === "-v") { console.log(VERSION); return; }
  if (cmd === "mcp") { await import("./mcp.js"); return; }
  if (!cmd) usage();
  try {
    if (cmd === "scan") {
      const asJson = rest.includes("--json");
      const target = rest.find((a) => !a.startsWith("--")) ?? ".";
      const report = scanHooks(target);
      if (asJson) console.log(JSON.stringify(report, null, 2));
      else console.log(renderReport(report));
      process.exit(report.verdict === "CLEAN" ? 0 : 1);
    } else if (cmd === "explain") {
      const args = rest.filter((a) => !a.startsWith("--"));
      const asJson = rest.includes("--json");
      let target = "."; let id = "";
      if (args.length === 1) id = args[0];
      else if (args.length >= 2) { target = args[0]; id = args[1]; }
      else usage();
      const result = explainHook(target, id);
      if (asJson) console.log(JSON.stringify(result, null, 2));
      else console.log(result.explanation);
      process.exit(result.finding ? 0 : 1);
    } else {
      usage();
    }
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }
}

void main();
