# hookcheck

**Find the hooks that run before you do. One scan, every auto-exec surface, one verdict.**

Modern supply chain attacks do not need you to run anything. They persist through hooks that run automatically: an npm `postinstall` script, a Claude Code `SessionStart` hook in `.claude/settings.json`, a VS Code task set to run on folder open. The Shai-Hulud npm worm used exactly this pattern, planting a preinstall dropper and then persisting through agent and editor hooks so it survived cleanup and stole credentials on the next open.

hookcheck scans a local repo for every auto-exec hook, classifies each one, and prints a single verdict: CLEAN, REVIEW, or COMPROMISED-PATTERN, with the file, command, rules, and evidence for every finding. Deterministic only. No LLM, no network in the core scan.

## Why this exists

Reports in October 2026 described AI agents orchestrating attacks and a self-propagating npm worm that backdoored hundreds of packages. Its persistence layer was not exotic malware. It was ordinary config files that every developer and every coding agent already trusts: package.json install scripts, `.claude/settings.json` hooks, and `.vscode/tasks.json` folderOpen tasks. Defenders needed a fast local check that an agent itself can call before opening, installing, or trusting a repo. That is hookcheck.

## What it checks

| surface | what it looks for |
| --- | --- |
| `package.json` | preinstall, install, postinstall, prepare scripts |
| `.claude/settings.json` and `settings.local.json` | SessionStart, PreToolUse, and other hook commands. Also discovered: the GNU stow layout (`claude/settings.json`, no dot) and settings nested one level under a config dir (for example `config/.claude/settings.json`). A settings path that exists as a directory is reported as a warning, not silently skipped |
| `.vscode/tasks.json` | tasks with runOn folderOpen, plus task inventory |
| `.husky/` | every hook file and its full command content |
| `lefthook.yml` | run commands |
| `.pre-commit-config.yaml` | entry commands and remote repo URLs |
| `.cursor/` and `.codex/` | config commands and files |
| MCP configs | `.mcp.json`, `mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json` servers that autostart |
| `.github/workflows/` | run steps, as inventory, including block scalar bodies (`run: |` and `run: >`, with chomping variants). Every workflow finding carries the line number of its `run:` key |
| `.githooks/` | hook files |

Classification per hook:

- **SAFE**: matches known safe dev patterns such as test, lint, build, typecheck, husky, or lint-staged, and matches no risky rule.
- **RISKY**: matches at least one risky rule: network fetch, curl piped to an interpreter, base64 decode piped to an interpreter, credential store paths or credential files (matched on content and paths, never on a script filename that merely contains the word credentials), credential shaped environment names (token, secret, password, api key) or bulk environment access, base64 decoding or eval style obfuscation, inline code execution, or a remote URL. Ordinary single named environment reads (NODE_ENV, HOME, RUNNER_DEBUG) are not flagged. Neither are operations that are not reads: `env -u NAME` unsets a variable, `os.environ.setdefault(...)` writes one key with a default, and a `[ -n "$NAME" ]` test checks existence. A hook whose target is a shell script is classified by that script's contents, not by the fact that it is a shell script. Comments are stripped before classification, so a docs URL inside a comment is not a fetch, and a fetch whose every URL is loopback (a localhost health check) is not treated as network behavior. In script files (JavaScript, Python), the contents of string and regex literals are data, not behavior: a defensive guard whose pattern list quotes `eval(` or `curl | sh` performs neither, and hookcheck does not classify it as an attacker. Literals handed to exec style calls (`execSync("...")`, `os.system("...")`) are code by construction and are still matched. Two rules are about value flow, not co-occurrence: ENV-EXFIL fires only when a credential value demonstrably flows into an outbound send (a request payload, a query string, a pipe into a network tool, or printed output next to a send), and CRED-EXFIL when credential store contents are piped or posted straight into a network send. A token used as authentication (an Authorization header, the userinfo of a push URL to the repo's own host, a `--token` flag) is authentication, not exfiltration, and never fires either rule. The flow analysis follows code references only: a variable named inside prose (help text, a banner string, a docstring) is mentioned, not used, and cannot make a send look tainted.
- **UNKNOWN**: matches neither safe nor risky patterns. A local script name alone is UNKNOWN until a human reads it. When a hook runs a local file such as `node setup.mjs`, hookcheck reads that file and escalates the finding if the file itself matches risky rules. The same one hop following applies to direct script execution (`./setup.sh`), `node --require ./setup.mjs`, and package.json script chains (`postinstall: npm run other-script`).

Verdict rules:

- **CLEAN**: every finding is SAFE, or no hooks were found. Exit code 0. When nothing was found, the report carries a note saying nothing was found to audit, in the JSON as well as the human output, so an empty estate never reads as an all-clear.
- **REVIEW**: at least one UNKNOWN finding, or a RISKY finding whose evidence is weak on its own (a remote URL alone, a download by itself, credential access with no network behavior). Exit code 1.
- **COMPROMISED-PATTERN**: at least one RISKY finding with strong evidence: fetched or decoded content executed directly as code (curl piped to an interpreter, base64 decode piped to an interpreter, eval of fetched content), a verified exfil flow (a credential value flowing into an outbound send, or credential store contents piped into a network tool), or credential store access combined with network behavior in the same finding. This is the Shai-Hulud persistence shape. Treat the repo as untrusted until proven otherwise. Exit code 1. Canonical legitimate installers that download their own binary (esbuild, puppeteer) verdict REVIEW under this calibration, not COMPROMISED-PATTERN; the download is reported as a RISKY finding with its evidence, and the top verdict no longer over-claims it. The same applies to a repo's own release automation: a step that reads its token and pushes to its own repo, posts its own workflow dispatch, or updates its own homebrew tap uses the token as authentication and verdicts REVIEW, because the credential value never flows into a payload to a third party.

Every finding reports file, hook id, command text, classification, rule ids, and evidence. Malformed JSON is reported as a warning, never silently ignored. Scanning a path that does not exist, or that is a file instead of a directory, is a clean error with exit code 2.

## Limits

Honest boundaries, pinned by tests in test/hardening.test.ts:

- One hop only. hookcheck follows a hook into the local file or package.json script it directly invokes, and classifies that target. It does not follow a second hop, and it does not trace data flow inside a script. A payload assembled at runtime from pieces that never appear as a recognizable pattern in any single file will not be named; the hook that runs it will usually still land in UNKNOWN or REVIEW, which is the signal to read it by hand.
- Pattern based, not execution based. hookcheck never runs the hooks it finds. A RISKY verdict means the command text matches a known bad shape, not that the payload was observed doing harm. A CLEAN verdict means no known shape matched, not that the repo is proven safe.
- Exfil detection is a static value flow check inside one finding: a credential value must visibly reach a send construct in the same command or referenced file (including through one variable assignment chain). A value laundered through several files, assembled at runtime, or sent by a tool whose arguments never name it will not be named as exfil; the finding still lands in RISKY or UNKNOWN on its other evidence. Conversely, a credential value placed in a request body or query string counts as exfil shape even to a first party host, because credentials belong in authentication positions, not payloads.
- Quote awareness has edges. In script files, string and regex literal contents are treated as data for the behavior rules; a payload hidden inside a string that is assembled and executed indirectly (not through a recognized exec call) can be missed. In shell text, quoted strings are command text and stay visible, except echo and printf arguments, which are output data.
- Remote pre-commit repos and remote MCP servers are inventoried, not verified. hookcheck cannot see inside a remote pre-commit repo, so those entries are UNKNOWN with a note to review the pinned rev. A remote MCP server URL is RISKY by construction, because the server autostarts and is remote.
- Duplicate JSON keys resolve last-wins, exactly as JSON.parse, Node, and npm resolve them, so the scanner sees the same value that would actually run.
- Non-string package.json script values are skipped: npm only executes string script values, so an array or number in scripts cannot auto-run.
- Classification reads up to 200,000 characters of a hook file or a referenced local file. Beyond that depth a payload can hide; the cap exists so a hostile file cannot make the scan unbounded.
- GitHub workflow run steps in block scalars (`run: |`, `run: >`, and chomping variants) are parsed and classified like one line commands. Plain multi-line scalars without a block header are not joined, and YAML anchors and reusable workflow internals are not resolved.
- Agent config coverage boundaries: `.gemini/settings.json` is not scanned yet. Template configs (for example `templates/settings.json.template`) are not scanned: they are inert until copied into place, at which point the copied file is scanned under its real name.
- UNKNOWN is the dominant classification on large real repos (measured at roughly 80 percent of findings on langfuse and cli/cli in Round 1 validation). The classifications are inventory, not suspicion: a REVIEW verdict on a large estate means the auto-exec surface is mapped and needs human triage, and the per finding evidence says exactly what each hook runs. More workflow step patterns will be classified over time; until then hookcheck does not guess.

## Usage

### CLI

```bash
npx @reneturcios/hookcheck scan
npx @reneturcios/hookcheck scan ./some-repo
npx @reneturcios/hookcheck scan ./some-repo --json
npx @reneturcios/hookcheck explain ./some-repo package.json:postinstall
```

Example output:

```
hookcheck ./some-repo: COMPROMISED-PATTERN
  2 hook(s): 0 SAFE, 2 RISKY, 0 UNKNOWN
  [RISKY] package.json:postinstall (package.json)
      command: node setup.mjs
      rules: NET-FETCH, REMOTE-URL, ENV-BULK, ENV-EXFIL
      evidence: referenced local file setup.mjs is RISKY: NET-FETCH: performs a network fetch
COMPROMISED-PATTERN: at least one risky hook shows strong evidence: fetched or decoded content executed as code, credential values flowing into an outbound send, or credential store access combined with network behavior.
```

### MCP server

Add to your MCP client config:

```json
{
  "mcpServers": {
    "hookcheck": {
      "command": "npx",
      "args": ["-y", "@reneturcios/hookcheck", "mcp"]
    }
  }
}
```

Tools:

- `scan_hooks(path)`: full scan with verdict, findings, counts, and warnings.
- `explain_hook(path, hookId or file)`: one hook explained in plain language with its evidence.

### Docker

```bash
docker run -i ghcr.io/cloudcorprecords/hookcheck mcp
docker run --rm -v "$PWD:/repo" ghcr.io/cloudcorprecords/hookcheck scan /repo
```

## The toolkit

hookcheck is part of a family of small, single-purpose developer tools by the same author, all built the same way: one bin that serves a CLI and an MCP server, deterministic checks with evidence, no invented answers.

- [greenlight](https://github.com/CloudCorpRecords/greenlight): pre-flight checks for open-source contributions: is this issue actually landable?
- [shipcheck](https://github.com/CloudCorpRecords/shipcheck): verify a release actually shipped on every surface, or NO-GO.

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT
