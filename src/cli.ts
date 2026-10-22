#!/usr/bin/env node
/**
 * hookcheck CLI.
 *   hookcheck scan [path] [--json]
 *   hookcheck mcp
 *   hookcheck --version
 * Exit codes: 0 CLEAN, 1 REVIEW or COMPROMISED-PATTERN, 2 usage error.
 */
import { existsSync, statSync } from "node:fs";
import { explainHook, renderReport, scanHooks, VERSION } from "./core.js";

/** A scan target must be an existing directory; anything else is a usage error (exit 2). */
function requireDirectory(target: string): void {
  if (!existsSync(target)) {
    console.error(`error: path does not exist: ${target}`);
    process.exit(2);
  }
  let isDir = false;
  try { isDir = statSync(target).isDirectory(); } catch { isDir = false; }
  if (!isDir) {
    console.error(`error: path is not a directory: ${target}`);
    process.exit(2);
  }
}

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
      requireDirectory(target);
      const report = scanHooks(target);
      if (asJson) console.log(JSON.stringify(report, null, 2));
      else console.log(renderReport(report));
      // exitCode, not process.exit: stdout to a pipe is async in Node, and
      // process.exit right after console.log truncates large reports at
      // exactly 65,536 characters (measured during v0.1.2 re-validation
      // on a sparse cli/cli checkout). Letting main return lets the
      // runtime flush stdout in full before exiting with this code.
      process.exitCode = report.verdict === "CLEAN" ? 0 : 1;
    } else if (cmd === "explain") {
      const args = rest.filter((a) => !a.startsWith("--"));
      const asJson = rest.includes("--json");
      let target = "."; let id = "";
      if (args.length === 1) id = args[0];
      else if (args.length >= 2) { target = args[0]; id = args[1]; }
      else usage();
      requireDirectory(target);
      const result = explainHook(target, id);
      if (asJson) console.log(JSON.stringify(result, null, 2));
      else console.log(result.explanation);
      process.exitCode = result.finding ? 0 : 1;
    } else {
      usage();
    }
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
  }
}

void main();
