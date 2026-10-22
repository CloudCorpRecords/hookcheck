#!/usr/bin/env node
/**
 * hookcheck CLI.
 *   hookcheck scan [path] [--json]
 *   hookcheck mcp
 *   hookcheck --version
 * Exit codes: 0 CLEAN, 1 REVIEW or COMPROMISED-PATTERN, 2 usage error,
 * 141 when the reader closed the output pipe before the report was
 * delivered (the shell-visible equivalent of death by SIGPIPE).
 *
 * Every report goes through emit(), which waits for stdout to flush
 * before the exit code takes effect. This is the factory emit
 * contract (~/workspace/security-wave/FACTORY-NOTES.md). The P-017 fix
 * in v0.1.3 replaced process.exit() with process.exitCode, which made
 * delivery reliable for cooperative readers, but the CLI still printed
 * with console.log and had no EPIPE handling at all: on a very large
 * report (35 MB on the chaos big-workflow target), a reader that
 * closed the pipe early still received the verdict exit code,
 * reporting silent truncation as success (P-071). Sibling tools
 * actionpin (P-001) and injectcheck (P-021) exit 141 in that case;
 * hookcheck now does the same.
 */
import { existsSync, statSync } from "node:fs";
import { explainHook, renderReport, scanHooks, VERSION } from "./core.js";

function exitBrokenPipe(): never {
  // The reader closed the pipe before the report was delivered. A Unix
  // writer in this position dies from SIGPIPE; exit 141 (128 + 13) is
  // the equivalent a shell reports, and it guarantees an undelivered
  // report is never mistaken for a successful run.
  process.exit(141);
}

process.stdout.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EPIPE") exitBrokenPipe();
  throw err;
});

/** Write one full report and resolve only after stdout has flushed it. */
async function emit(text: string, code: number): Promise<void> {
  process.exitCode = code;
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(`${text}\n`, (err) => {
      if (!err) {
        resolve();
        return;
      }
      if ((err as NodeJS.ErrnoException).code === "EPIPE") exitBrokenPipe();
      reject(err);
    });
  });
}

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
      await emit(asJson ? JSON.stringify(report, null, 2) : renderReport(report), report.verdict === "CLEAN" ? 0 : 1);
    } else if (cmd === "explain") {
      const args = rest.filter((a) => !a.startsWith("--"));
      const asJson = rest.includes("--json");
      let target = "."; let id = "";
      if (args.length === 1) id = args[0];
      else if (args.length >= 2) { target = args[0]; id = args[1]; }
      else usage();
      requireDirectory(target);
      const result = explainHook(target, id);
      await emit(asJson ? JSON.stringify(result, null, 2) : result.explanation, result.finding ? 0 : 1);
    } else {
      usage();
    }
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
  }
}

void main();
