/**
 * P-108 follow-on (v0.1.13), found by the v0.1.12 acceptance run
 * against a fresh clone of github/docs: the real package-lock-lint
 * step has a second message line the distilled fixture omits,
 *
 *   echo "::error::Could not scan .npmrc and package-lock.json for
 *   package feed URLs."
 *
 * An output message that NAMES the files a search scanned is a
 * reference, not credential access, exactly as a credential-path
 * string used as a search target is (P-108) and exactly as a data
 * literal in a script file already is for this rule. The shell
 * credential view therefore blanks echo and printf argument text,
 * except command substitution interiors, which are code that runs:
 * echo "$(cat ~/.npmrc)" still reads the file and still fires.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { classifyCommand, computeVerdict } from "../src/core.js";
import type { HookFinding } from "../src/core.js";

const DOCS_STEP = [
  "status=0",
  "grep -inE 'https?://[^/\"]*(pkgs\\.visualstudio\\.com|pkgs\\.dev\\.azure\\.com|packagefeedproxy\\.microsoft\\.io)' .npmrc package-lock.json || status=$?",
  'if [ "$status" -eq 0 ]; then',
  '  echo "::error::Found Microsoft package feed URLs. Use https://registry.npmjs.org/ instead."',
  "  exit 1",
  'elif [ "$status" -ne 1 ]; then',
  '  echo "::error::Could not scan .npmrc and package-lock.json for package feed URLs."',
  '  exit "$status"',
  "fi",
].join("\n");

function finding(over: Partial<HookFinding>): HookFinding {
  return {
    id: "x", file: ".github/workflows/ci.yml", source: "github-workflow", hook: "run",
    command: "", classification: "RISKY", rules: [], evidence: "", ...over,
  } as HookFinding;
}

describe("P-108 follow-on: output text naming a credential file is a reference", () => {
  it("the real github/docs lint step carries no CRED-ACCESS and verdicts REVIEW", () => {
    const c = classifyCommand(DOCS_STEP);
    assert.ok(!c.rules.includes("CRED-ACCESS"), `rules: ${c.rules.join(",")}`);
    const v = computeVerdict([finding({ rules: [...c.rules], command: DOCS_STEP })]);
    assert.equal(v, "REVIEW");
  });

  it("an echo message naming a credential file does not fire CRED-ACCESS", () => {
    const c = classifyCommand('echo "::error::Could not scan .npmrc and package-lock.json for package feed URLs."');
    assert.ok(!c.rules.includes("CRED-ACCESS"), `rules: ${c.rules.join(",")}`);
  });

  it("a printf message naming a credential path does not fire CRED-ACCESS", () => {
    const c = classifyCommand('printf "%s\\n" "missing ~/.ssh/id_rsa - generate one first"');
    assert.ok(!c.rules.includes("CRED-ACCESS"), `rules: ${c.rules.join(",")}`);
  });

  it("control: a command substitution inside an echo still reads the file", () => {
    const c = classifyCommand('echo "$(cat ~/.npmrc)"');
    assert.ok(c.rules.includes("CRED-ACCESS"), `rules: ${c.rules.join(",")}`);
  });

  it("control: a backtick substitution inside an echo still reads the file", () => {
    const c = classifyCommand("echo \"`cat ~/.npmrc`\"");
    assert.ok(c.rules.includes("CRED-ACCESS"), `rules: ${c.rules.join(",")}`);
  });

  it("control: reading the credential file directly still fires", () => {
    const c = classifyCommand("cat ~/.npmrc");
    assert.ok(c.rules.includes("CRED-ACCESS"), `rules: ${c.rules.join(",")}`);
  });

  it("control: an echo plus a real read in the same step still fires", () => {
    const c = classifyCommand('echo "scanning .npmrc now"\ncat ~/.npmrc | head -1');
    assert.ok(c.rules.includes("CRED-ACCESS"), `rules: ${c.rules.join(",")}`);
  });
});
